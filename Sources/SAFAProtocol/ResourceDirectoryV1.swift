import Foundation
import SAFADomain

public enum ResourceDirectoryActionV1: String, Codable, Sendable {
    case list
    case show
    case inspect
}

public struct ResourceDirectoryRequestV1: Codable, Equatable, Sendable {
    public let header: IPCHeader
    public let action: ResourceDirectoryActionV1
    public let alias: ResourceAlias?
    public let state: ResourceState?

    public init(
        header: IPCHeader,
        action: ResourceDirectoryActionV1,
        alias: ResourceAlias? = nil,
        state: ResourceState? = nil
    ) {
        self.header = header
        self.action = action
        self.alias = alias
        self.state = state
    }

    private enum CodingKeys: String, CodingKey {
        case header
        case action
        case alias
        case state
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        header = try container.decode(IPCHeader.self, forKey: .header)
        action = try container.decode(ResourceDirectoryActionV1.self, forKey: .action)
        if let rawAlias = try container.decodeIfPresent(String.self, forKey: .alias) {
            alias = try ResourceAlias(rawAlias)
        } else {
            alias = nil
        }
        state = try container.decodeIfPresent(ResourceState.self, forKey: .state)
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(header, forKey: .header)
        try container.encode(action, forKey: .action)
        try container.encodeIfPresent(alias?.rawValue, forKey: .alias)
        try container.encodeIfPresent(state, forKey: .state)
    }
}

public enum ResourceDirectoryReplyStatusV1: String, Codable, Sendable {
    case completed
    case denied
    case failed
}

public struct ResourceDirectoryReplyV1: Codable, Equatable, Sendable {
    public let protocolVersion: UInt
    public let messageID: UUID
    public let status: ResourceDirectoryReplyStatusV1
    public let summaries: [ResourceSummaryV1]
    public let details: ResourceDetailsV1?
    public let error: SAFAErrorPayload?

    public init(
        protocolVersion: UInt = IPCHeader.currentVersion,
        messageID: UUID,
        status: ResourceDirectoryReplyStatusV1,
        summaries: [ResourceSummaryV1] = [],
        details: ResourceDetailsV1? = nil,
        error: SAFAErrorPayload? = nil
    ) {
        self.protocolVersion = protocolVersion
        self.messageID = messageID
        self.status = status
        self.summaries = summaries
        self.details = details
        self.error = error
    }

    private enum CodingKeys: String, CodingKey {
        case protocolVersion = "protocol_version"
        case messageID = "message_id"
        case status
        case summaries
        case details
        case error
    }
}

public struct ResourceSummaryV1: Codable, Equatable, Sendable {
    public let alias: String
    public let displayName: String?
    public let resourceType: String
    public let state: String
    public let health: String
    public let capabilities: [String]
    public let metadata: [ResourceMetadataEntryV1]

    public init(
        alias: String,
        displayName: String?,
        resourceType: String,
        state: String,
        health: String,
        capabilities: [String],
        metadata: [ResourceMetadataEntryV1]
    ) {
        self.alias = alias
        self.displayName = displayName
        self.resourceType = resourceType
        self.state = state
        self.health = health
        self.capabilities = capabilities
        self.metadata = metadata
    }

    private enum CodingKeys: String, CodingKey {
        case alias
        case displayName = "display_name"
        case resourceType = "resource_type"
        case state
        case health
        case capabilities
        case metadata
    }
}

public struct ResourceDetailsV1: Codable, Equatable, Sendable {
    public let alias: String
    public let displayName: String?
    public let resourceType: String
    public let alternateAliases: [String]
    public let accessMethods: [String]
    public let state: String
    public let health: String
    public let capabilities: [String]
    public let endpoint: ResourceEndpointV1?
    public let username: String?
    public let securityDomain: String
    public let metadata: [ResourceMetadataEntryV1]
    public let relationships: [ResourceRelationshipV1]
    public let hostIdentityStatus: String?
    public let updatedAt: Date

    public init(
        alias: String,
        displayName: String?,
        resourceType: String,
        alternateAliases: [String],
        accessMethods: [String],
        state: String,
        health: String,
        capabilities: [String],
        endpoint: ResourceEndpointV1?,
        username: String?,
        securityDomain: String,
        metadata: [ResourceMetadataEntryV1],
        relationships: [ResourceRelationshipV1],
        hostIdentityStatus: String?,
        updatedAt: Date
    ) {
        self.alias = alias
        self.displayName = displayName
        self.resourceType = resourceType
        self.alternateAliases = alternateAliases
        self.accessMethods = accessMethods
        self.state = state
        self.health = health
        self.capabilities = capabilities
        self.endpoint = endpoint
        self.username = username
        self.securityDomain = securityDomain
        self.metadata = metadata
        self.relationships = relationships
        self.hostIdentityStatus = hostIdentityStatus
        self.updatedAt = updatedAt
    }

    private enum CodingKeys: String, CodingKey {
        case alias
        case displayName = "display_name"
        case resourceType = "resource_type"
        case alternateAliases = "alternate_aliases"
        case accessMethods = "access_methods"
        case state
        case health
        case capabilities
        case endpoint
        case username
        case securityDomain = "security_domain"
        case metadata
        case relationships
        case hostIdentityStatus = "host_identity_status"
        case updatedAt = "updated_at"
    }
}

public struct ResourceEndpointV1: Codable, Equatable, Sendable {
    public let scheme: String?
    public let host: String
    public let port: UInt16
    public let path: String?

    public init(scheme: String?, host: String, port: UInt16, path: String?) {
        self.scheme = scheme
        self.host = host
        self.port = port
        self.path = path
    }
}

public struct ResourceRelationshipV1: Codable, Equatable, Sendable {
    public let kind: String
    public let targetAlias: String

    public init(kind: String, targetAlias: String) {
        self.kind = kind
        self.targetAlias = targetAlias
    }

    private enum CodingKeys: String, CodingKey {
        case kind
        case targetAlias = "target_alias"
    }
}

public struct ResourceMetadataEntryV1: Codable, Equatable, Sendable {
    public let key: String
    public let value: ResourceMetadataValueV1
    public let observedAt: Date?

    public init(key: String, value: ResourceMetadataValueV1, observedAt: Date? = nil) {
        self.key = key
        self.value = value
        self.observedAt = observedAt
    }

    private enum CodingKeys: String, CodingKey {
        case key
        case value
        case observedAt = "observed_at"
    }
}

public enum ResourceMetadataValueV1: Equatable, Sendable {
    case text(String)
    case integer(Int64)
    case boolean(Bool)
    case byteCount(UInt64)
    case textList([String])
}

extension ResourceMetadataValueV1: Codable {
    private enum ValueType: String, Codable {
        case text
        case integer
        case boolean
        case byteCount = "byte_count"
        case textList = "text_list"
    }

    private enum CodingKeys: String, CodingKey {
        case type
        case value
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(ValueType.self, forKey: .type) {
        case .text: self = .text(try container.decode(String.self, forKey: .value))
        case .integer: self = .integer(try container.decode(Int64.self, forKey: .value))
        case .boolean: self = .boolean(try container.decode(Bool.self, forKey: .value))
        case .byteCount: self = .byteCount(try container.decode(UInt64.self, forKey: .value))
        case .textList: self = .textList(try container.decode([String].self, forKey: .value))
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case let .text(value):
            try container.encode(ValueType.text, forKey: .type)
            try container.encode(value, forKey: .value)
        case let .integer(value):
            try container.encode(ValueType.integer, forKey: .type)
            try container.encode(value, forKey: .value)
        case let .boolean(value):
            try container.encode(ValueType.boolean, forKey: .type)
            try container.encode(value, forKey: .value)
        case let .byteCount(value):
            try container.encode(ValueType.byteCount, forKey: .type)
            try container.encode(value, forKey: .value)
        case let .textList(value):
            try container.encode(ValueType.textList, forKey: .type)
            try container.encode(value, forKey: .value)
        }
    }
}
