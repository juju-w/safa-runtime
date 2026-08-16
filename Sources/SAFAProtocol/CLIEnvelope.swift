import Foundation

public enum JSONValue: Codable, Equatable, Sendable {
    case string(String)
    case integer(Int64)
    case number(Double)
    case boolean(Bool)
    case object([String: JSONValue])
    case array([JSONValue])
    case null

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(Bool.self) {
            self = .boolean(value)
        } else if let value = try? container.decode(Int64.self) {
            self = .integer(value)
        } else if let value = try? container.decode(Double.self) {
            self = .number(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode([String: JSONValue].self) {
            self = .object(value)
        } else {
            self = .array(try container.decode([JSONValue].self))
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case let .string(value): try container.encode(value)
        case let .integer(value): try container.encode(value)
        case let .number(value): try container.encode(value)
        case let .boolean(value): try container.encode(value)
        case let .object(value): try container.encode(value)
        case let .array(value): try container.encode(value)
        case .null: try container.encodeNil()
        }
    }
}

public enum CLIStatus: String, Codable, Sendable {
    case completed
    case accepted
    case approvalRequired = "approval_required"
    case userActionRequired = "user_action_required"
    case denied
    case cancelled
    case expired
    case failed
}

public struct NextAction: Codable, Equatable, Sendable {
    public let kind: String
    public let command: [String]
    public let safeForAgent: Bool

    public init(kind: String, command: [String], safeForAgent: Bool) {
        self.kind = kind
        self.command = command
        self.safeForAgent = safeForAgent
    }

    private enum CodingKeys: String, CodingKey {
        case kind
        case command
        case safeForAgent = "safe_for_agent"
    }
}

public struct SAFAErrorPayload: Codable, Equatable, Sendable {
    public let code: String
    public let message: String
    public let retryable: Bool
    public let details: [String: JSONValue]
    public let remediation: NextAction?

    public init(
        code: String,
        message: String,
        retryable: Bool,
        details: [String: JSONValue] = [:],
        remediation: NextAction? = nil
    ) {
        self.code = code
        self.message = message
        self.retryable = retryable
        self.details = details
        self.remediation = remediation
    }

    public var jsonObject: [String: JSONValue] {
        var value: [String: JSONValue] = [
            "code": .string(code),
            "message": .string(message),
            "retryable": .boolean(retryable),
            "details": .object(details),
        ]
        value["remediation"] =
            remediation.map {
                .object([
                    "kind": .string($0.kind),
                    "command": .array($0.command.map(JSONValue.string)),
                    "safe_for_agent": .boolean($0.safeForAgent),
                ])
            } ?? .null
        return value
    }
}

public struct CLIEnvelope: Codable, Equatable, Sendable {
    public static let currentSchema = "dev.safa.cli/v1"

    public let schema: String
    public let command: String
    public let status: CLIStatus
    public let requestID: UUID?
    public let timestamp: Date
    public let data: [String: JSONValue]
    public let warnings: [String]
    public let nextAction: NextAction?

    public init(
        schema: String = Self.currentSchema,
        command: String,
        status: CLIStatus,
        requestID: UUID? = nil,
        timestamp: Date = Date(),
        data: [String: JSONValue] = [:],
        warnings: [String] = [],
        nextAction: NextAction? = nil
    ) {
        self.schema = schema
        self.command = command
        self.status = status
        self.requestID = requestID
        self.timestamp = Date(timeIntervalSince1970: floor(timestamp.timeIntervalSince1970))
        self.data = data
        self.warnings = warnings
        self.nextAction = nextAction
    }

    private enum CodingKeys: String, CodingKey {
        case schema
        case command
        case status
        case requestID = "request_id"
        case timestamp
        case data
        case warnings
        case nextAction = "next_action"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        schema = try container.decode(String.self, forKey: .schema)
        command = try container.decode(String.self, forKey: .command)
        status = try container.decode(CLIStatus.self, forKey: .status)
        requestID = try container.decodeIfPresent(UUID.self, forKey: .requestID)
        timestamp = try container.decode(Date.self, forKey: .timestamp)
        data = try container.decode([String: JSONValue].self, forKey: .data)
        warnings = try container.decode([String].self, forKey: .warnings)
        nextAction = try container.decodeIfPresent(NextAction.self, forKey: .nextAction)
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(schema, forKey: .schema)
        try container.encode(command, forKey: .command)
        try container.encode(status, forKey: .status)
        if let requestID {
            try container.encode(requestID, forKey: .requestID)
        } else {
            try container.encodeNil(forKey: .requestID)
        }
        try container.encode(timestamp, forKey: .timestamp)
        try container.encode(data, forKey: .data)
        try container.encode(warnings, forKey: .warnings)
        if let nextAction {
            try container.encode(nextAction, forKey: .nextAction)
        } else {
            try container.encodeNil(forKey: .nextAction)
        }
    }
}
