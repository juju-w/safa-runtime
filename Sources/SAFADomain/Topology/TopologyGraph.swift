import Foundation

public enum TopologyNodeKind: String, Codable, CaseIterable, Sendable {
    case resource
    case site
    case securityDomain = "security-domain"
    case networkSegment = "network-segment"
    case runtime
    case route
}

public enum TopologyVisibility: String, Codable, Sendable {
    case agent
    case protected
    case broker
}

public enum TopologyLayer: String, Codable, Sendable {
    case desired
    case observed
    case derived
}

public enum TopologyVerification: String, Codable, Sendable {
    case asserted
    case verified
    case stale
    case failed
}

public enum TopologyOrigin: String, Codable, Sendable {
    case user
    case agent
    case `import`
    case adapter
    case broker
}

public enum TopologyRelation: String, Codable, CaseIterable, Sendable {
    case locatedIn = "located-in"
    case memberOf = "member-of"
    case runsOn = "runs-on"
    case dependsOn = "depends-on"
    case backedBy = "backed-by"
    case replicatesTo = "replicates-to"
    case routedVia = "routed-via"
    case canReach = "can-reach"
}

public enum TopologyFreshness: String, Codable, Sendable {
    case asserted
    case fresh
    case stale
    case failed
}

public enum TopologyValidationError: Error, Equatable, Sendable {
    case duplicateNodeID(UUID)
    case duplicateNodeAlias(String)
    case duplicateEdgeID(UUID)
    case endpointNotFound(UUID)
    case selfEdge(UUID)
    case invalidResourceNode(UUID)
    case invalidContextNode(UUID)
    case invalidContextAlias(String)
    case invalidEdgeTrust(UUID)
}

public struct TopologyNode: Codable, Equatable, Sendable {
    public let id: UUID
    public let alias: ResourceAlias
    public let kind: TopologyNodeKind
    public let resourceKind: ResourceKindIdentifier?
    public let resourceID: UUID?
    public let visibility: TopologyVisibility

    public init(
        id: UUID = UUID(),
        alias: ResourceAlias,
        kind: TopologyNodeKind,
        resourceKind: ResourceKindIdentifier? = nil,
        resourceID: UUID? = nil,
        visibility: TopologyVisibility
    ) throws {
        if kind == .resource {
            guard resourceKind != nil, resourceID != nil else {
                throw TopologyValidationError.invalidResourceNode(id)
            }
        } else if resourceKind != nil || resourceID != nil {
            throw TopologyValidationError.invalidContextNode(id)
        }
        self.id = id
        self.alias = alias
        self.kind = kind
        self.resourceKind = resourceKind
        self.resourceID = resourceID
        self.visibility = visibility
    }

    public init(resource: Resource, visibility: TopologyVisibility) throws {
        try self.init(
            id: resource.id,
            alias: resource.alias,
            kind: .resource,
            resourceKind: resource.resolvedClassification.kind,
            resourceID: resource.id,
            visibility: visibility
        )
    }

    public static func context(
        alias: ResourceAlias,
        visibility: TopologyVisibility
    ) throws -> Self {
        guard let kind = contextKind(for: alias) else {
            throw TopologyValidationError.invalidContextAlias(alias.rawValue)
        }
        return try Self(alias: alias, kind: kind, visibility: visibility)
    }

    func validateShape() throws {
        if kind == .resource {
            guard resourceKind != nil, resourceID != nil else {
                throw TopologyValidationError.invalidResourceNode(id)
            }
        } else if resourceKind != nil || resourceID != nil {
            throw TopologyValidationError.invalidContextNode(id)
        } else if Self.contextKind(for: alias) != kind {
            throw TopologyValidationError.invalidContextAlias(alias.rawValue)
        }
    }

    private static func contextKind(for alias: ResourceAlias) -> TopologyNodeKind? {
        guard
            alias.rawValue.range(
                of: "^(site|domain|network|runtime|route)\\.[a-z][a-z0-9-]{0,31}$",
                options: .regularExpression
            ) != nil
        else { return nil }

        if alias.rawValue.hasPrefix("site.") { return .site }
        if alias.rawValue.hasPrefix("domain.") { return .securityDomain }
        if alias.rawValue.hasPrefix("network.") { return .networkSegment }
        if alias.rawValue.hasPrefix("runtime.") { return .runtime }
        if alias.rawValue.hasPrefix("route.") { return .route }
        return nil
    }
}

public struct TopologyEdge: Codable, Equatable, Sendable {
    public let id: UUID
    public let fromNodeID: UUID
    public let relation: TopologyRelation
    public let toNodeID: UUID
    public let layer: TopologyLayer
    public let verification: TopologyVerification
    public let origin: TopologyOrigin
    public let observedAt: Date?
    public let validUntil: Date?
    public let visibility: TopologyVisibility
    public let evidenceReference: UUID?

    public init(
        id: UUID = UUID(),
        fromNodeID: UUID,
        relation: TopologyRelation,
        toNodeID: UUID,
        layer: TopologyLayer,
        verification: TopologyVerification,
        origin: TopologyOrigin,
        observedAt: Date? = nil,
        validUntil: Date? = nil,
        visibility: TopologyVisibility,
        evidenceReference: UUID? = nil
    ) {
        self.id = id
        self.fromNodeID = fromNodeID
        self.relation = relation
        self.toNodeID = toNodeID
        self.layer = layer
        self.verification = verification
        self.origin = origin
        self.observedAt = observedAt
        self.validUntil = validUntil
        self.visibility = visibility
        self.evidenceReference = evidenceReference
    }

    public static func observed(
        id: UUID = UUID(),
        fromNodeID: UUID,
        relation: TopologyRelation,
        toNodeID: UUID,
        verification: TopologyVerification,
        origin: TopologyOrigin,
        observedAt: Date,
        validUntil: Date,
        visibility: TopologyVisibility,
        evidenceReference: UUID
    ) throws -> Self {
        let edge = Self(
            id: id,
            fromNodeID: fromNodeID,
            relation: relation,
            toNodeID: toNodeID,
            layer: .observed,
            verification: verification,
            origin: origin,
            observedAt: observedAt,
            validUntil: validUntil,
            visibility: visibility,
            evidenceReference: evidenceReference
        )
        try edge.validateTrust()
        return edge
    }

    public func freshness(at now: Date) -> TopologyFreshness {
        switch verification {
        case .asserted:
            return .asserted
        case .failed:
            return .failed
        case .stale:
            return .stale
        case .verified:
            if let validUntil, validUntil < now { return .stale }
            return .fresh
        }
    }

    func validateTrust() throws {
        switch layer {
        case .desired:
            guard verification == .asserted,
                [.user, .agent, .import].contains(origin),
                observedAt == nil,
                validUntil == nil,
                evidenceReference == nil
            else {
                throw TopologyValidationError.invalidEdgeTrust(id)
            }
        case .observed:
            guard verification != .asserted,
                [.adapter, .broker].contains(origin),
                observedAt != nil,
                evidenceReference != nil,
                let observedAt,
                let validUntil,
                validUntil >= observedAt
            else {
                throw TopologyValidationError.invalidEdgeTrust(id)
            }
        case .derived:
            guard verification != .asserted,
                origin == .broker,
                observedAt != nil
            else {
                throw TopologyValidationError.invalidEdgeTrust(id)
            }
        }
    }
}

public struct TopologyGraph: Codable, Equatable, Sendable {
    public let revision: UInt64
    public let nodes: [TopologyNode]
    public let edges: [TopologyEdge]

    public init(
        revision: UInt64 = 0,
        nodes: [TopologyNode] = [],
        edges: [TopologyEdge] = []
    ) throws {
        var nodeIDs = Set<UUID>()
        var aliases = Set<ResourceAlias>()
        for node in nodes {
            try node.validateShape()
            guard nodeIDs.insert(node.id).inserted else {
                throw TopologyValidationError.duplicateNodeID(node.id)
            }
            guard aliases.insert(node.alias).inserted else {
                throw TopologyValidationError.duplicateNodeAlias(node.alias.rawValue)
            }
        }
        var edgeIDs = Set<UUID>()
        for edge in edges {
            guard edgeIDs.insert(edge.id).inserted else {
                throw TopologyValidationError.duplicateEdgeID(edge.id)
            }
            guard nodeIDs.contains(edge.fromNodeID) else {
                throw TopologyValidationError.endpointNotFound(edge.fromNodeID)
            }
            guard nodeIDs.contains(edge.toNodeID) else {
                throw TopologyValidationError.endpointNotFound(edge.toNodeID)
            }
            guard edge.fromNodeID != edge.toNodeID else {
                throw TopologyValidationError.selfEdge(edge.id)
            }
            try edge.validateTrust()
        }
        self.revision = revision
        self.nodes = nodes
        self.edges = edges
    }

    private enum CodingKeys: String, CodingKey {
        case revision
        case nodes
        case edges
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            revision: container.decode(UInt64.self, forKey: .revision),
            nodes: container.decode([TopologyNode].self, forKey: .nodes),
            edges: container.decode([TopologyEdge].self, forKey: .edges)
        )
    }

    public func reconciling(
        resources: [Resource],
        incrementRevisionWhenChanged: Bool = false
    ) throws -> Self {
        let live = resources.filter { $0.state != .deleted }
        _ = try ResourceRegistry(resources: live)

        let resourceNodes = try live.map {
            try TopologyNode(resource: $0, visibility: .agent)
        }
        let reconciledNodes = (nodes.filter { $0.kind != .resource } + resourceNodes)
            .sorted(by: Self.nodeLess)
        let nodeIDs = Set(reconciledNodes.map(\.id))
        let resourceIDs = Set(resourceNodes.map(\.id))

        var desiredRelationships: [ResourceTopologyRelationshipKey: TopologyOrigin] = [:]
        for resource in live {
            for relationship in resource.resolvedRelationships {
                guard let relation = relationship.kind.topologyRelation else { continue }
                desiredRelationships[
                    ResourceTopologyRelationshipKey(
                        sourceID: resource.id,
                        relation: relation,
                        targetID: relationship.targetResourceID
                    )
                ] = relationship.origin
            }
        }

        var reconciledEdges = edges.filter {
            nodeIDs.contains($0.fromNodeID) && nodeIDs.contains($0.toNodeID)
        }.filter { edge in
            guard edge.layer == .desired,
                edge.relation.resourceRelationshipKind != nil,
                resourceIDs.contains(edge.fromNodeID),
                resourceIDs.contains(edge.toNodeID)
            else { return true }
            let key = ResourceTopologyRelationshipKey(
                sourceID: edge.fromNodeID,
                relation: edge.relation,
                targetID: edge.toNodeID
            )
            // Preserve only pre-bridge random-ID relationships for compatibility. New
            // resource-owned relationships always use the deterministic identity below.
            return desiredRelationships[key] == nil && edge.id != key.stableEdgeID
        }
        reconciledEdges.append(
            contentsOf: desiredRelationships.map { key, origin in
                TopologyEdge(
                    id: key.stableEdgeID,
                    fromNodeID: key.sourceID,
                    relation: key.relation,
                    toNodeID: key.targetID,
                    layer: .desired,
                    verification: .asserted,
                    origin: origin,
                    visibility: .agent
                )
            }
        )
        reconciledEdges.sort(by: Self.edgeLess)

        let changed = reconciledNodes != nodes || reconciledEdges != edges
        return try Self(
            revision: changed && incrementRevisionWhenChanged ? revision + 1 : revision,
            nodes: reconciledNodes,
            edges: reconciledEdges
        )
    }

    private static func nodeLess(_ lhs: TopologyNode, _ rhs: TopologyNode) -> Bool {
        if lhs.alias != rhs.alias { return lhs.alias.rawValue < rhs.alias.rawValue }
        return lhs.id.uuidString.lowercased() < rhs.id.uuidString.lowercased()
    }

    private static func edgeLess(_ lhs: TopologyEdge, _ rhs: TopologyEdge) -> Bool {
        lhs.id.uuidString.lowercased() < rhs.id.uuidString.lowercased()
    }
}
