import Foundation

/// Private JSON data model used only by the typed Broker IPC boundary.
///
/// This is not an Agent-facing presentation type. The CLI projects Broker replies into explicit
/// `Agent*V2` DTOs before the final TOON encoding step.
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
