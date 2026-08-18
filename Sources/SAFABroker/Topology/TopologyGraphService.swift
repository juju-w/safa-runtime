import Foundation
import SAFACrypto
import SAFADomain
import SAFAProtocol

public protocol TopologyQueryHandling: Sendable {
    func query(
        _ request: TopologyQueryRequestV1,
        caller: CallerIdentity,
        now: Date
    ) async -> TopologyQueryReplyV1
}

public protocol TopologyMutationHandling: Sendable {
    func mutate(
        _ request: TopologyMutationRequestV1,
        caller: CallerIdentity,
        now: Date
    ) async -> TopologyMutationReplyV1
}

public protocol TopologyReachabilityRecording: Sendable {
    func recordSuccessfulReachability(
        to target: ResourceAlias,
        observedAt: Date
    ) async throws
}

public enum TopologyObservationError: Error, Equatable, Sendable {
    case aliasNotFound(String)
}

public actor TopologyGraphService: TopologyQueryHandling, TopologyMutationHandling,
    TopologyReachabilityRecording
{
    private let vault: any VaultDocumentStoring
    private let userPresenceAuthorizer: any UserPresenceAuthorizing
    private let cooldown: TimeInterval
    private let authorizationReuseInterval: TimeInterval
    private let mutationGate: ResourceMutationGate
    private var lastDeniedAt: Date?
    private var lastReusableApprovalAt: Date?

    public init(
        vault: any VaultDocumentStoring,
        userPresenceAuthorizer: any UserPresenceAuthorizing,
        cooldown: TimeInterval = 10,
        authorizationReuseInterval: TimeInterval = 0
    ) {
        self.vault = vault
        self.userPresenceAuthorizer = userPresenceAuthorizer
        self.cooldown = cooldown
        self.authorizationReuseInterval = min(max(0, authorizationReuseInterval), 300)
        mutationGate = ResourceMutationGate()
    }

    init(
        vault: any VaultDocumentStoring,
        userPresenceAuthorizer: any UserPresenceAuthorizing,
        cooldown: TimeInterval = 10,
        authorizationReuseInterval: TimeInterval = 0,
        mutationGate: ResourceMutationGate
    ) {
        self.vault = vault
        self.userPresenceAuthorizer = userPresenceAuthorizer
        self.cooldown = cooldown
        self.authorizationReuseInterval = min(max(0, authorizationReuseInterval), 300)
        self.mutationGate = mutationGate
    }

    public func query(
        _ request: TopologyQueryRequestV1,
        caller _: CallerIdentity,
        now: Date = Date()
    ) async -> TopologyQueryReplyV1 {
        do {
            let query = try makeQuery(request)
            let document = try await vault.readDocument()
            let graph = try (document.topologyGraph ?? TopologyGraph()).reconciling(
                resources: document.resources)
            let result = try TopologyQueryEngine.query(graph: graph, query: query, now: now)
            return TopologyQueryReplyV1(
                messageID: request.header.messageID,
                status: .completed,
                projection: TopologyProjectionV1(result)
            )
        } catch TopologyQueryError.aliasNotFound(let alias) {
            return queryFailure(
                request,
                code: "topology_alias_not_found",
                message: "The requested topology alias is not registered.",
                details: ["resource": .string(alias)]
            )
        } catch TopologyQueryError.invalidBounds, TopologyQueryError.invalidShape {
            return queryFailure(
                request,
                code: "topology_query_invalid",
                message: "The topology query shape or bounds are invalid."
            )
        } catch {
            return queryFailure(
                request,
                code: "topology_query_failed",
                message: "The broker could not compute the topology projection."
            )
        }
    }

    public func mutate(
        _ request: TopologyMutationRequestV1,
        caller _: CallerIdentity,
        now: Date = Date()
    ) async -> TopologyMutationReplyV1 {
        do {
            try await validateMutationPreflight(request)
        } catch let error as TopologyMutationError {
            return mutationErrorReply(error, request: request)
        } catch {
            return mutationFailure(
                request,
                code: "topology_change_failed",
                message: "The broker could not validate the topology change."
            )
        }

        if let lastDeniedAt, now.timeIntervalSince(lastDeniedAt) < cooldown {
            return mutationDenial(
                request,
                code: "topology_change_rate_limited",
                message: "Topology change authorization is temporarily rate limited."
            )
        }

        let elapsed = lastReusableApprovalAt.map { now.timeIntervalSince($0) }
        let hasReusableApproval =
            request.action == .link
            && authorizationReuseInterval > 0
            && elapsed.map { $0 >= 0 && $0 <= authorizationReuseInterval } == true
        if !hasReusableApproval {
            if request.action == .unlink { lastReusableApprovalAt = nil }
            let verb = request.action == .link ? "Link" : "Unlink"
            let reason =
                "\(verb) \(request.source.rawValue) \(request.relation.rawValue) "
                + "\(request.target.rawValue) in SAFA topology"
            guard await userPresenceAuthorizer.authorize(reason: reason) else {
                lastReusableApprovalAt = nil
                lastDeniedAt = now
                return mutationDenial(
                    request,
                    code: "topology_change_denied",
                    message: "The topology change was not authorized by the user."
                )
            }
            if request.action == .link { lastReusableApprovalAt = now }
        }

        do {
            let result = try await mutationGate.withLock { [vault] in
                var document = try await vault.readDocument()
                var graph = try (document.topologyGraph ?? TopologyGraph()).reconciling(
                    resources: document.resources)
                if let expected = request.expectedGraphRevision, expected != graph.revision {
                    throw TopologyMutationError.revisionConflict
                }
                var nodes = graph.nodes
                let source = try Self.resolveMutationNode(
                    alias: request.source,
                    nodes: &nodes,
                    mayCreateContext: request.action == .link
                )
                let target = try Self.resolveMutationNode(
                    alias: request.target,
                    nodes: &nodes,
                    mayCreateContext: request.action == .link
                )
                guard source.id != target.id else { throw TopologyMutationError.selfLink }

                let matches: (TopologyEdge) -> Bool = { edge in
                    edge.fromNodeID == source.id
                        && edge.relation == request.relation
                        && edge.toNodeID == target.id
                        && edge.layer == .desired
                }
                var changedEdge: TopologyEdge?
                if let relationshipKind = request.relation.resourceRelationshipKind,
                    let sourceID = source.resourceID,
                    let targetID = target.resourceID
                {
                    changedEdge = graph.edges.first(where: matches)
                    let changed = try Self.updateResourceRelationship(
                        in: &document,
                        sourceID: sourceID,
                        kind: relationshipKind,
                        targetID: targetID,
                        action: request.action,
                        now: now
                    )
                    if changed {
                        graph = try graph.reconciling(
                            resources: document.resources,
                            incrementRevisionWhenChanged: true
                        )
                        if request.action == .link {
                            changedEdge = graph.edges.first(where: matches)
                        }
                    } else if request.action == .unlink, let existing = changedEdge {
                        graph = try TopologyGraph(
                            revision: graph.revision + 1,
                            nodes: graph.nodes,
                            edges: graph.edges.filter { $0.id != existing.id }
                        )
                    }
                } else {
                    var edges = graph.edges
                    switch request.action {
                    case .link:
                        if let existing = edges.first(where: matches) {
                            changedEdge = existing
                        } else {
                            let edge = TopologyEdge(
                                id: UUID(),
                                fromNodeID: source.id,
                                relation: request.relation,
                                toNodeID: target.id,
                                layer: .desired,
                                verification: .asserted,
                                origin: .agent,
                                visibility: .agent
                            )
                            edges.append(edge)
                            changedEdge = edge
                            graph = try TopologyGraph(
                                revision: graph.revision + 1,
                                nodes: nodes,
                                edges: edges
                            )
                        }
                    case .unlink:
                        guard let existing = edges.first(where: matches) else {
                            throw TopologyMutationError.edgeNotFound
                        }
                        edges.removeAll(where: matches)
                        changedEdge = existing
                        graph = try TopologyGraph(
                            revision: graph.revision + 1,
                            nodes: graph.nodes,
                            edges: edges
                        )
                    }
                }
                if request.action == .link,
                    Self.requiresAcyclicPlacement(request.relation),
                    Self.hasPlacementCycle(graph)
                {
                    throw TopologyMutationError.cycleProhibited
                }
                document.topologyGraph = graph
                try await vault.writeDocument(document)
                return (graph, source, target, changedEdge)
            }
            return TopologyMutationReplyV1(
                messageID: request.header.messageID,
                status: .completed,
                graphRevision: result.0.revision,
                edge: result.3.map {
                    Self.project($0, from: result.1.alias, to: result.2.alias, now: now)
                }
            )
        } catch let error as TopologyMutationError {
            return mutationErrorReply(error, request: request)
        } catch {
            return mutationFailure(
                request,
                code: "topology_change_failed",
                message: "The broker could not apply the topology change."
            )
        }
    }

    /// Trusted adapters call this Broker API after an actual probe. It is deliberately absent
    /// from the Agent XPC contract, so an Agent cannot promote its own assertion to evidence.
    public func recordObservation(
        source: ResourceAlias,
        relation: TopologyRelation,
        target: ResourceAlias,
        verification: TopologyVerification,
        observedAt: Date,
        validUntil: Date,
        evidenceReference: UUID,
        visibility: TopologyVisibility = .agent
    ) async throws {
        try await mutationGate.withLock { [vault] in
            var document = try await vault.readDocument()
            let graph = try (document.topologyGraph ?? TopologyGraph()).reconciling(
                resources: document.resources)
            guard graph.nodes.contains(where: { $0.alias == target }) else {
                throw TopologyObservationError.aliasNotFound(target.rawValue)
            }
            document.topologyGraph = try graph.recordingObservation(
                source: source,
                relation: relation,
                target: target,
                verification: verification,
                observedAt: observedAt,
                validUntil: validUntil,
                origin: .adapter,
                visibility: visibility,
                evidenceReference: evidenceReference
            )
            try await vault.writeDocument(document)
        }
    }

    public func recordSuccessfulReachability(
        to target: ResourceAlias,
        observedAt: Date
    ) async throws {
        try await recordObservation(
            source: ResourceAlias("runtime.local"),
            relation: .canReach,
            target: target,
            verification: .verified,
            observedAt: observedAt,
            validUntil: observedAt.addingTimeInterval(300),
            evidenceReference: UUID()
        )
    }

    private func makeQuery(_ request: TopologyQueryRequestV1) throws -> TopologyQuery {
        let bounds = try TopologyQueryBounds(
            maximumHops: request.bounds.maximumHops,
            maximumNodes: request.bounds.maximumNodes,
            maximumEdges: request.bounds.maximumEdges
        )
        switch request.task {
        case .inventory:
            guard request.source == nil, request.target == nil, request.relation == nil else {
                throw TopologyQueryError.invalidShape
            }
            return .inventory(bounds: bounds)
        case .placement:
            guard let source = request.source,
                request.target == nil,
                request.relation == nil
            else { throw TopologyQueryError.invalidShape }
            return .placement(of: source, bounds: bounds)
        case .reachability:
            guard let source = request.source,
                let target = request.target,
                request.relation == nil
            else { throw TopologyQueryError.invalidShape }
            return .reachability(from: source, to: target, bounds: bounds)
        case .dependencyImpact:
            guard request.source == nil,
                let target = request.target,
                request.relation == nil
            else { throw TopologyQueryError.invalidShape }
            return .dependencyImpact(of: target, bounds: bounds)
        case .denseComparison:
            guard request.source == nil,
                request.target == nil,
                let relation = request.relation
            else { throw TopologyQueryError.invalidShape }
            return .denseComparison(relation: relation, bounds: bounds)
        }
    }

    private func validateMutationPreflight(
        _ request: TopologyMutationRequestV1
    ) async throws {
        let document = try await vault.readDocument()
        let graph = try (document.topologyGraph ?? TopologyGraph()).reconciling(
            resources: document.resources)
        if let expected = request.expectedGraphRevision, expected != graph.revision {
            throw TopologyMutationError.revisionConflict
        }
        var nodes = graph.nodes
        let source = try Self.resolveMutationNode(
            alias: request.source,
            nodes: &nodes,
            mayCreateContext: request.action == .link
        )
        let target = try Self.resolveMutationNode(
            alias: request.target,
            nodes: &nodes,
            mayCreateContext: request.action == .link
        )
        guard source.id != target.id else { throw TopologyMutationError.selfLink }

        let matches: (TopologyEdge) -> Bool = { edge in
            edge.fromNodeID == source.id
                && edge.relation == request.relation
                && edge.toNodeID == target.id
                && edge.layer == .desired
        }
        switch request.action {
        case .unlink:
            guard graph.edges.contains(where: matches) else {
                throw TopologyMutationError.edgeNotFound
            }
        case .link:
            guard !graph.edges.contains(where: matches),
                Self.requiresAcyclicPlacement(request.relation)
            else { return }
            let proposed = TopologyEdge(
                fromNodeID: source.id,
                relation: request.relation,
                toNodeID: target.id,
                layer: .desired,
                verification: .asserted,
                origin: .agent,
                visibility: .agent
            )
            let candidate = try TopologyGraph(
                revision: graph.revision + 1,
                nodes: nodes,
                edges: graph.edges + [proposed]
            )
            if Self.hasPlacementCycle(candidate) {
                throw TopologyMutationError.cycleProhibited
            }
        }
    }

    private static func project(
        _ edge: TopologyEdge,
        from: ResourceAlias,
        to: ResourceAlias,
        now: Date
    ) -> TopologyEdgeV1 {
        TopologyEdgeV1(
            id: edge.id.uuidString.lowercased(),
            from: from.rawValue,
            relation: edge.relation.rawValue,
            to: to.rawValue,
            layer: edge.layer.rawValue,
            verification: edge.verification.rawValue,
            freshness: edge.freshness(at: now).rawValue
        )
    }

    private static func resolveMutationNode(
        alias: ResourceAlias,
        nodes: inout [TopologyNode],
        mayCreateContext: Bool
    ) throws -> TopologyNode {
        if let node = nodes.first(where: { $0.alias == alias }) { return node }
        guard mayCreateContext else {
            throw TopologyMutationError.aliasNotFound(alias.rawValue)
        }
        do {
            let node = try TopologyNode.context(alias: alias, visibility: .agent)
            nodes.append(node)
            return node
        } catch {
            throw TopologyMutationError.aliasNotFound(alias.rawValue)
        }
    }

    private static func updateResourceRelationship(
        in document: inout VaultDocument,
        sourceID: UUID,
        kind: ResourceRelationshipKind,
        targetID: UUID,
        action: TopologyMutationActionV1,
        now: Date
    ) throws -> Bool {
        guard
            let index = document.resources.firstIndex(where: {
                $0.id == sourceID && $0.state != .deleted
            })
        else {
            throw TopologyMutationError.aliasNotFound(sourceID.uuidString.lowercased())
        }
        var resource = document.resources[index]
        var relationships = resource.resolvedRelationships
        let matches = { (relationship: ResourceRelationship) in
            relationship.kind == kind && relationship.targetResourceID == targetID
        }
        switch action {
        case .link:
            guard !relationships.contains(where: matches) else { return false }
            relationships.append(
                ResourceRelationship(
                    kind: kind,
                    targetResourceID: targetID,
                    origin: .agent
                )
            )
        case .unlink:
            guard relationships.contains(where: matches) else { return false }
            relationships.removeAll(where: matches)
        }
        resource.profile = ResourceProfile(
            classification: resource.resolvedClassification,
            alternateAliases: resource.resolvedAlternateAliases,
            accessMethods: resource.resolvedAccessMethods,
            metadata: resource.resolvedMetadata,
            relationships: relationships,
            credentialBindings: resource.resolvedCredentialBindings
        )
        resource.revision += 1
        resource.updatedAt = now
        document.resources[index] = resource
        _ = try ResourceRegistry(resources: document.resources)
        return true
    }

    private static let acyclicPlacementRelations: Set<TopologyRelation> = [
        .locatedIn, .memberOf, .runsOn, .routedVia,
    ]

    private static func requiresAcyclicPlacement(_ relation: TopologyRelation) -> Bool {
        acyclicPlacementRelations.contains(relation)
    }

    private static func hasPlacementCycle(_ graph: TopologyGraph) -> Bool {
        let edges = graph.edges.filter {
            acyclicPlacementRelations.contains($0.relation) && $0.verification != .failed
        }
        let adjacency = Dictionary(grouping: edges, by: \.fromNodeID)
        var active = Set<UUID>()
        var complete = Set<UUID>()

        func visit(_ nodeID: UUID) -> Bool {
            if active.contains(nodeID) { return true }
            if complete.contains(nodeID) { return false }
            active.insert(nodeID)
            for edge in adjacency[nodeID] ?? [] where visit(edge.toNodeID) { return true }
            active.remove(nodeID)
            complete.insert(nodeID)
            return false
        }

        return graph.nodes.map(\.id).contains(where: visit)
    }

    private func queryFailure(
        _ request: TopologyQueryRequestV1,
        code: String,
        message: String,
        details: [String: JSONValue] = [:]
    ) -> TopologyQueryReplyV1 {
        TopologyQueryReplyV1(
            messageID: request.header.messageID,
            status: .failed,
            error: SAFAErrorPayload(
                code: code, message: message, retryable: false, details: details)
        )
    }

    private func mutationDenial(
        _ request: TopologyMutationRequestV1,
        code: String,
        message: String
    ) -> TopologyMutationReplyV1 {
        TopologyMutationReplyV1(
            messageID: request.header.messageID,
            status: .denied,
            error: SAFAErrorPayload(code: code, message: message, retryable: false)
        )
    }

    private func mutationFailure(
        _ request: TopologyMutationRequestV1,
        code: String,
        message: String,
        details: [String: JSONValue] = [:]
    ) -> TopologyMutationReplyV1 {
        TopologyMutationReplyV1(
            messageID: request.header.messageID,
            status: .failed,
            error: SAFAErrorPayload(
                code: code, message: message, retryable: false, details: details)
        )
    }

    private func mutationErrorReply(
        _ error: TopologyMutationError,
        request: TopologyMutationRequestV1
    ) -> TopologyMutationReplyV1 {
        switch error {
        case .aliasNotFound(let alias):
            return mutationFailure(
                request,
                code: "topology_alias_not_found",
                message: "The requested topology alias is not registered.",
                details: ["resource": .string(alias)]
            )
        case .revisionConflict:
            return mutationFailure(
                request,
                code: "topology_revision_conflict",
                message: "The topology changed; read it again before retrying."
            )
        case .selfLink:
            return mutationFailure(
                request,
                code: "topology_link_invalid",
                message: "A topology node cannot link to itself."
            )
        case .edgeNotFound:
            return mutationFailure(
                request,
                code: "topology_link_not_found",
                message: "The requested desired topology link does not exist."
            )
        case .cycleProhibited:
            return mutationFailure(
                request,
                code: "topology_cycle_rejected",
                message: "The topology link would create a placement or route cycle."
            )
        }
    }
}

private enum TopologyMutationError: Error {
    case revisionConflict
    case aliasNotFound(String)
    case selfLink
    case edgeNotFound
    case cycleProhibited
}
