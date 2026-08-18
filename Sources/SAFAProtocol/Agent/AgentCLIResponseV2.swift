import Foundation

public enum AgentCLIV2Contract {
    public static let schema = "dev.safa.cli/v2"
}

public enum AgentCLIStatusV2: String, Sendable {
    case completed
    case accepted
    case noOp = "no_op"
    case approvalRequired = "approval_required"
    case userActionRequired = "user_action_required"
    case denied
    case cancelled
    case expired
    case transportFailed = "transport_failed"
    case remoteExecutionFailed = "remote_execution_failed"
    case failed
}

public struct AgentNextCommandV2: Equatable, Sendable {
    public let command: String
    public let reason: String
    public let safeForAgent: Bool

    public init(command: String, reason: String, safeForAgent: Bool) {
        self.command = command
        self.reason = reason
        self.safeForAgent = safeForAgent
    }
}

public struct AgentCLIErrorV2: Equatable, Sendable {
    public let code: String
    public let message: String
    public let retryable: Bool

    public init(code: String, message: String, retryable: Bool) {
        self.code = code
        self.message = message
        self.retryable = retryable
    }
}

public struct AgentCLIResponseV2<Payload: Sendable>: Sendable {
    public let command: String
    public let status: AgentCLIStatusV2
    public let requestID: UUID?
    public let payload: Payload
    public let error: AgentCLIErrorV2?
    public let warnings: [String]
    public let next: [AgentNextCommandV2]

    public init(
        command: String,
        status: AgentCLIStatusV2,
        requestID: UUID? = nil,
        payload: Payload,
        error: AgentCLIErrorV2? = nil,
        warnings: [String] = [],
        next: [AgentNextCommandV2] = []
    ) {
        self.command = command
        self.status = status
        self.requestID = requestID
        self.payload = payload
        self.error = error
        self.warnings = warnings
        self.next = next
    }
}

public enum AgentCLIV2ValidationError: Error, Equatable, Sendable {
    case inconsistentCollectionCount
    case invalidFieldSelection
}

public struct AgentNoPayloadV2: Equatable, Sendable {
    public init() {}
}

public struct AgentResourceRowV2: Equatable, Sendable {
    public let alias: String
    public let kind: String
    public let state: String
    public let health: String
    public let resourceType: String?
    public let templateID: String?
    public let hostPlatform: String?

    public init(
        alias: String,
        kind: String,
        state: String,
        health: String,
        resourceType: String? = nil,
        templateID: String? = nil,
        hostPlatform: String? = nil
    ) {
        self.alias = alias
        self.kind = kind
        self.state = state
        self.health = health
        self.resourceType = resourceType
        self.templateID = templateID
        self.hostPlatform = hostPlatform
    }
}

public enum AgentResourceListFieldV2: String, CaseIterable, Equatable, Sendable {
    case alias
    case kind
    case state
    case health
    case resourceType = "resource_type"
    case templateID = "template_id"
    case hostPlatform = "host_platform"

    public static let defaultFields: [Self] = [.alias, .kind, .state, .health]
}

public struct AgentResourceListV2: Equatable, Sendable {
    public let total: Int
    public let truncated: Bool
    public let resources: [AgentResourceRowV2]
    public let fields: [AgentResourceListFieldV2]

    public var returned: Int { resources.count }

    public init(
        total: Int,
        truncated: Bool,
        resources: [AgentResourceRowV2],
        fields: [AgentResourceListFieldV2] = AgentResourceListFieldV2.defaultFields
    ) throws {
        guard total >= resources.count,
            truncated == (total > resources.count)
        else {
            throw AgentCLIV2ValidationError.inconsistentCollectionCount
        }
        guard !fields.isEmpty,
            Set(fields.map(\.rawValue)).count == fields.count,
            fields.contains(.alias)
        else {
            throw AgentCLIV2ValidationError.invalidFieldSelection
        }
        self.total = total
        self.truncated = truncated
        self.resources = resources
        self.fields = fields
    }
}
