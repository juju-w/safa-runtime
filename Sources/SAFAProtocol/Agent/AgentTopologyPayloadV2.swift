public struct AgentTopologyPayloadV2: Equatable, Sendable {
    public let graphRevision: UInt64
    public let task: String
    public let ordering: String
    public let roots: [String]
    public let nodes: [AgentTopologyNodeV2]
    public let edges: [AgentTopologyEdgeV2]
    public let answer: AgentTopologyAnswerV2
    public let matrix: AgentTopologyMatrixV2?
    public let truncated: Bool
    public let nodeFields: [AgentTopologyNodeFieldV2]

    public init(
        graphRevision: UInt64,
        task: String,
        ordering: String,
        roots: [String],
        nodes: [AgentTopologyNodeV2],
        edges: [AgentTopologyEdgeV2],
        answer: AgentTopologyAnswerV2,
        matrix: AgentTopologyMatrixV2?,
        truncated: Bool,
        nodeFields: [AgentTopologyNodeFieldV2] = AgentTopologyNodeFieldV2.defaultFields
    ) {
        self.graphRevision = graphRevision
        self.task = task
        self.ordering = ordering
        self.roots = roots
        self.nodes = nodes
        self.edges = edges
        self.answer = answer
        self.matrix = matrix
        self.truncated = truncated
        self.nodeFields = nodeFields
    }
}

public enum AgentTopologyNodeFieldV2: String, CaseIterable, Equatable, Sendable {
    case alias
    case kind
    case resourceKind = "resource_kind"

    public static let defaultFields: [Self] = [.alias, .kind, .resourceKind]
}

public struct AgentTopologyNodeV2: Equatable, Sendable {
    public let alias: String
    public let kind: String
    public let resourceKind: String?

    public init(alias: String, kind: String, resourceKind: String?) {
        self.alias = alias
        self.kind = kind
        self.resourceKind = resourceKind
    }
}

public struct AgentTopologyEdgeV2: Equatable, Sendable {
    public let id: String
    public let from: String
    public let relation: String
    public let to: String

    public init(id: String, from: String, relation: String, to: String) {
        self.id = id
        self.from = from
        self.relation = relation
        self.to = to
    }
}

public struct AgentTopologyAnswerV2: Equatable, Sendable {
    public let outcome: String
    public let source: String?
    public let target: String?
    public let affectedAliases: [String]
    public let proofEdgeIDs: [String]

    public init(
        outcome: String,
        source: String?,
        target: String?,
        affectedAliases: [String],
        proofEdgeIDs: [String]
    ) {
        self.outcome = outcome
        self.source = source
        self.target = target
        self.affectedAliases = affectedAliases
        self.proofEdgeIDs = proofEdgeIDs
    }
}

public struct AgentTopologyMatrixV2: Equatable, Sendable {
    public let aliases: [String]
    public let values: [[Bool]]

    public init(aliases: [String], values: [[Bool]]) {
        self.aliases = aliases
        self.values = values
    }
}

public struct AgentTopologyMutationPayloadV2: Equatable, Sendable {
    public let graphRevision: UInt64?
    public let edge: AgentTopologyEdgeV2?

    public init(graphRevision: UInt64?, edge: AgentTopologyEdgeV2?) {
        self.graphRevision = graphRevision
        self.edge = edge
    }
}
