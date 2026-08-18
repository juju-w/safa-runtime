import Foundation
import SAFADomain

public struct TopologyQueryBoundsV1: Codable, Equatable, Sendable {
    public let maximumHops: Int
    public let maximumNodes: Int
    public let maximumEdges: Int

    public init(maximumHops: Int = 6, maximumNodes: Int = 64, maximumEdges: Int = 128) {
        self.maximumHops = maximumHops
        self.maximumNodes = maximumNodes
        self.maximumEdges = maximumEdges
    }

    private enum CodingKeys: String, CodingKey {
        case maximumHops = "maximum_hops"
        case maximumNodes = "maximum_nodes"
        case maximumEdges = "maximum_edges"
    }
}

public struct TopologyQueryRequestV1: Codable, Equatable, Sendable {
    public let header: IPCHeader
    public let task: TopologyProjectionTask
    public let source: ResourceAlias?
    public let target: ResourceAlias?
    public let relation: TopologyRelation?
    public let bounds: TopologyQueryBoundsV1

    public init(
        header: IPCHeader,
        task: TopologyProjectionTask,
        source: ResourceAlias? = nil,
        target: ResourceAlias? = nil,
        relation: TopologyRelation? = nil,
        bounds: TopologyQueryBoundsV1 = TopologyQueryBoundsV1()
    ) {
        self.header = header
        self.task = task
        self.source = source
        self.target = target
        self.relation = relation
        self.bounds = bounds
    }

    private enum CodingKeys: String, CodingKey {
        case header
        case task
        case source
        case target
        case relation
        case bounds
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        header = try container.decode(IPCHeader.self, forKey: .header)
        task = try container.decode(TopologyProjectionTask.self, forKey: .task)
        source = try container.decodeIfPresent(String.self, forKey: .source).map(ResourceAlias.init)
        target = try container.decodeIfPresent(String.self, forKey: .target).map(ResourceAlias.init)
        relation = try container.decodeIfPresent(TopologyRelation.self, forKey: .relation)
        bounds = try container.decode(TopologyQueryBoundsV1.self, forKey: .bounds)
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(header, forKey: .header)
        try container.encode(task, forKey: .task)
        try container.encodeIfPresent(source?.rawValue, forKey: .source)
        try container.encodeIfPresent(target?.rawValue, forKey: .target)
        try container.encodeIfPresent(relation, forKey: .relation)
        try container.encode(bounds, forKey: .bounds)
    }
}

public struct TopologyNodeV1: Codable, Equatable, Sendable {
    public let alias: String
    public let kind: String
    public let resourceKind: String?

    public init(alias: String, kind: String, resourceKind: String? = nil) {
        self.alias = alias
        self.kind = kind
        self.resourceKind = resourceKind
    }

    private enum CodingKeys: String, CodingKey {
        case alias
        case kind
        case resourceKind = "resource_kind"
    }
}

public struct TopologyEdgeV1: Codable, Equatable, Sendable {
    public let id: String
    public let from: String
    public let relation: String
    public let to: String
    public let layer: String
    public let verification: String
    public let freshness: String

    public init(
        id: String,
        from: String,
        relation: String,
        to: String,
        layer: String,
        verification: String,
        freshness: String
    ) {
        self.id = id
        self.from = from
        self.relation = relation
        self.to = to
        self.layer = layer
        self.verification = verification
        self.freshness = freshness
    }
}

public struct TopologyAnswerV1: Codable, Equatable, Sendable {
    public let outcome: TopologyAnswerOutcome
    public let source: String?
    public let target: String?
    public let affectedAliases: [String]
    public let proofEdgeIDs: [String]

    public init(
        outcome: TopologyAnswerOutcome,
        source: String? = nil,
        target: String? = nil,
        affectedAliases: [String] = [],
        proofEdgeIDs: [String] = []
    ) {
        self.outcome = outcome
        self.source = source
        self.target = target
        self.affectedAliases = affectedAliases
        self.proofEdgeIDs = proofEdgeIDs
    }

    private enum CodingKeys: String, CodingKey {
        case outcome
        case source
        case target
        case affectedAliases = "affected_aliases"
        case proofEdgeIDs = "proof_edge_ids"
    }
}

public struct TopologyMatrixV1: Codable, Equatable, Sendable {
    public let aliases: [String]
    public let values: [[Bool]]

    public init(aliases: [String], values: [[Bool]]) {
        self.aliases = aliases
        self.values = values
    }
}

public struct TopologyProjectionV1: Codable, Equatable, Sendable {
    public static let currentSchema = "dev.safa.topology/v1"

    public let schema: String
    public let graphRevision: UInt64
    public let task: TopologyProjectionTask
    public let ordering: TopologyProjectionOrdering
    public let roots: [String]
    public let nodes: [TopologyNodeV1]
    public let edges: [TopologyEdgeV1]
    public let answer: TopologyAnswerV1
    public let matrix: TopologyMatrixV1?
    public let truncated: Bool

    public init(
        schema: String = Self.currentSchema,
        graphRevision: UInt64,
        task: TopologyProjectionTask,
        ordering: TopologyProjectionOrdering,
        roots: [String],
        nodes: [TopologyNodeV1],
        edges: [TopologyEdgeV1],
        answer: TopologyAnswerV1,
        matrix: TopologyMatrixV1?,
        truncated: Bool
    ) {
        self.schema = schema
        self.graphRevision = graphRevision
        self.task = task
        self.ordering = ordering
        self.roots = roots
        self.nodes = nodes
        self.edges = edges
        self.answer = answer
        self.matrix = matrix
        self.truncated = truncated
    }

    public init(_ result: TopologyQueryResult) {
        self.init(
            graphRevision: result.graphRevision,
            task: result.task,
            ordering: result.ordering,
            roots: result.roots.map(\.rawValue),
            nodes: result.nodes.map {
                TopologyNodeV1(
                    alias: $0.alias.rawValue,
                    kind: $0.kind.rawValue,
                    resourceKind: $0.resourceKind?.rawValue
                )
            },
            edges: result.edges.map {
                TopologyEdgeV1(
                    id: $0.id.uuidString.lowercased(),
                    from: $0.from.rawValue,
                    relation: $0.relation.rawValue,
                    to: $0.to.rawValue,
                    layer: $0.layer.rawValue,
                    verification: $0.verification.rawValue,
                    freshness: $0.freshness.rawValue
                )
            },
            answer: TopologyAnswerV1(
                outcome: result.answer.outcome,
                source: result.answer.source?.rawValue,
                target: result.answer.target?.rawValue,
                affectedAliases: result.answer.affectedAliases.map(\.rawValue),
                proofEdgeIDs: result.answer.proofEdgeIDs.map {
                    $0.uuidString.lowercased()
                }
            ),
            matrix: result.matrix.map {
                TopologyMatrixV1(aliases: $0.aliases.map(\.rawValue), values: $0.values)
            },
            truncated: result.truncated
        )
    }

    private enum CodingKeys: String, CodingKey {
        case schema
        case graphRevision = "graph_revision"
        case task
        case ordering
        case roots
        case nodes
        case edges
        case answer
        case matrix
        case truncated
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        schema = try container.decode(String.self, forKey: .schema)
        guard schema == Self.currentSchema else { throw ProtocolCodecError.invalidSchema }
        graphRevision = try container.decode(UInt64.self, forKey: .graphRevision)
        task = try container.decode(TopologyProjectionTask.self, forKey: .task)
        ordering = try container.decode(TopologyProjectionOrdering.self, forKey: .ordering)
        roots = try container.decode([String].self, forKey: .roots)
        nodes = try container.decode([TopologyNodeV1].self, forKey: .nodes)
        edges = try container.decode([TopologyEdgeV1].self, forKey: .edges)
        answer = try container.decode(TopologyAnswerV1.self, forKey: .answer)
        matrix = try container.decodeIfPresent(TopologyMatrixV1.self, forKey: .matrix)
        truncated = try container.decode(Bool.self, forKey: .truncated)
    }
}

public enum TopologyQueryReplyStatusV1: String, Codable, Sendable {
    case completed
    case failed
}

public struct TopologyQueryReplyV1: Codable, Equatable, Sendable {
    public let protocolVersion: UInt
    public let messageID: UUID
    public let status: TopologyQueryReplyStatusV1
    public let projection: TopologyProjectionV1?
    public let error: SAFAErrorPayload?

    public init(
        protocolVersion: UInt = IPCHeader.currentVersion,
        messageID: UUID,
        status: TopologyQueryReplyStatusV1,
        projection: TopologyProjectionV1? = nil,
        error: SAFAErrorPayload? = nil
    ) {
        self.protocolVersion = protocolVersion
        self.messageID = messageID
        self.status = status
        self.projection = projection
        self.error = error
    }

    private enum CodingKeys: String, CodingKey {
        case protocolVersion = "protocol_version"
        case messageID = "message_id"
        case status
        case projection
        case error
    }
}

public enum TopologyMutationActionV1: String, Codable, Sendable {
    case link
    case unlink
}

public struct TopologyMutationRequestV1: Codable, Equatable, Sendable {
    public let header: IPCHeader
    public let action: TopologyMutationActionV1
    public let source: ResourceAlias
    public let relation: TopologyRelation
    public let target: ResourceAlias
    public let expectedGraphRevision: UInt64?

    public init(
        header: IPCHeader,
        action: TopologyMutationActionV1,
        source: ResourceAlias,
        relation: TopologyRelation,
        target: ResourceAlias,
        expectedGraphRevision: UInt64? = nil
    ) {
        self.header = header
        self.action = action
        self.source = source
        self.relation = relation
        self.target = target
        self.expectedGraphRevision = expectedGraphRevision
    }

    private enum CodingKeys: String, CodingKey {
        case header
        case action
        case source
        case relation
        case target
        case expectedGraphRevision = "expected_graph_revision"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        header = try container.decode(IPCHeader.self, forKey: .header)
        action = try container.decode(TopologyMutationActionV1.self, forKey: .action)
        source = try ResourceAlias(container.decode(String.self, forKey: .source))
        relation = try container.decode(TopologyRelation.self, forKey: .relation)
        target = try ResourceAlias(container.decode(String.self, forKey: .target))
        expectedGraphRevision = try container.decodeIfPresent(
            UInt64.self, forKey: .expectedGraphRevision)
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(header, forKey: .header)
        try container.encode(action, forKey: .action)
        try container.encode(source.rawValue, forKey: .source)
        try container.encode(relation, forKey: .relation)
        try container.encode(target.rawValue, forKey: .target)
        try container.encodeIfPresent(expectedGraphRevision, forKey: .expectedGraphRevision)
    }
}

public enum TopologyMutationReplyStatusV1: String, Codable, Sendable {
    case completed
    case denied
    case failed
}

public struct TopologyMutationReplyV1: Codable, Equatable, Sendable {
    public let protocolVersion: UInt
    public let messageID: UUID
    public let status: TopologyMutationReplyStatusV1
    public let graphRevision: UInt64?
    public let edge: TopologyEdgeV1?
    public let error: SAFAErrorPayload?

    public init(
        protocolVersion: UInt = IPCHeader.currentVersion,
        messageID: UUID,
        status: TopologyMutationReplyStatusV1,
        graphRevision: UInt64? = nil,
        edge: TopologyEdgeV1? = nil,
        error: SAFAErrorPayload? = nil
    ) {
        self.protocolVersion = protocolVersion
        self.messageID = messageID
        self.status = status
        self.graphRevision = graphRevision
        self.edge = edge
        self.error = error
    }

    private enum CodingKeys: String, CodingKey {
        case protocolVersion = "protocol_version"
        case messageID = "message_id"
        case status
        case graphRevision = "graph_revision"
        case edge
        case error
    }
}
