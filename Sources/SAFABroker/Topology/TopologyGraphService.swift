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

public enum TopologyObservationError: Error, Equatable, Sendable {
    case aliasNotFound(String)
}

public actor TopologyGraphService: TopologyQueryHandling, TopologyMutationHandling {
    private let vault: any VaultDocumentStoring
    private let userPresenceAuthorizer: any UserPresenceAuthorizing
    private let cooldown: TimeInterval
    private let mutationGate: ResourceMutationGate
    private var lastDeniedAt: Date?

    public init(
        vault: any VaultDocumentStoring,
        userPresenceAuthorizer: any UserPresenceAuthorizing,
        cooldown: TimeInterval = 10
    ) {
        self.vault = vault
        self.userPresenceAuthorizer = userPresenceAuthorizer
        self.cooldown = cooldown
        mutationGate = ResourceMutationGate()
    }

    init(
        vault: any VaultDocumentStoring,
        userPresenceAuthorizer: any UserPresenceAuthorizing,
        cooldown: TimeInterval = 10,
        mutationGate: ResourceMutationGate
    ) {
        self.vault = vault
        self.userPresenceAuthorizer = userPresenceAuthorizer
        self.cooldown = cooldown
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

        let verb = request.action == .link ? "Link" : "Unlink"
        let reason =
            "\(verb) \(request.source.rawValue) \(request.relation.rawValue) "
            + "\(request.target.rawValue) in SAFA topology"
        guard await userPresenceAuthorizer.authorize(reason: reason) else {
            lastDeniedAt = now
            return mutationDenial(
                request,
                code: "topology_change_denied",
                message: "The topology change was not authorized by the user."
            )
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
                        if Self.requiresAcyclicPlacement(request.relation),
                            Self.hasPlacementCycle(graph)
                        {
                            throw TopologyMutationError.cycleProhibited
                        }
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
            guard let sourceNode = graph.nodes.first(where: { $0.alias == source }) else {
                throw TopologyObservationError.aliasNotFound(source.rawValue)
            }
            guard let targetNode = graph.nodes.first(where: { $0.alias == target }) else {
                throw TopologyObservationError.aliasNotFound(target.rawValue)
            }
            let edge = try TopologyEdge.observed(
                fromNodeID: sourceNode.id,
                relation: relation,
                toNodeID: targetNode.id,
                verification: verification,
                origin: .adapter,
                observedAt: observedAt,
                validUntil: validUntil,
                visibility: visibility,
                evidenceReference: evidenceReference
            )
            document.topologyGraph = try TopologyGraph(
                revision: graph.revision + 1,
                nodes: graph.nodes,
                edges: graph.edges + [edge]
            )
            try await vault.writeDocument(document)
        }
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
