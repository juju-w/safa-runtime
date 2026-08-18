import Foundation

public struct AgentResourceSummaryV2: Equatable, Sendable {
    public let alias: String
    public let displayName: String?
    public let resourceType: String
    public let kind: String
    public let templateID: String
    public let templateVersion: UInt
    public let hostPlatform: String?
    public let roles: [String]
    public let state: String
    public let health: String
    public let capabilities: [String]
    public let metadata: [AgentResourceMetadataV2]

    public init(
        alias: String,
        displayName: String?,
        resourceType: String,
        kind: String,
        templateID: String,
        templateVersion: UInt,
        hostPlatform: String?,
        roles: [String],
        state: String,
        health: String,
        capabilities: [String],
        metadata: [AgentResourceMetadataV2]
    ) {
        self.alias = alias
        self.displayName = displayName
        self.resourceType = resourceType
        self.kind = kind
        self.templateID = templateID
        self.templateVersion = templateVersion
        self.hostPlatform = hostPlatform
        self.roles = roles
        self.state = state
        self.health = health
        self.capabilities = capabilities
        self.metadata = metadata
    }
}

public struct AgentResourceSummaryPayloadV2: Equatable, Sendable {
    public let resource: AgentResourceSummaryV2

    public init(resource: AgentResourceSummaryV2) {
        self.resource = resource
    }
}

public struct AgentResourceDetailsPayloadV2: Equatable, Sendable {
    public let resource: AgentResourceDetailsV2

    public init(resource: AgentResourceDetailsV2) {
        self.resource = resource
    }
}

public struct AgentResourceDetailsV2: Equatable, Sendable {
    public let summary: AgentResourceSummaryV2
    public let alternateAliases: [String]
    public let accessMethods: [String]
    public let endpoint: AgentResourceEndpointV2?
    public let username: String?
    public let securityDomain: String
    public let relationships: [AgentResourceRelationshipV2]
    public let hostIdentityStatus: String?
    public let updatedAt: Date

    public init(
        summary: AgentResourceSummaryV2,
        alternateAliases: [String],
        accessMethods: [String],
        endpoint: AgentResourceEndpointV2?,
        username: String?,
        securityDomain: String,
        relationships: [AgentResourceRelationshipV2],
        hostIdentityStatus: String?,
        updatedAt: Date
    ) {
        self.summary = summary
        self.alternateAliases = alternateAliases
        self.accessMethods = accessMethods
        self.endpoint = endpoint
        self.username = username
        self.securityDomain = securityDomain
        self.relationships = relationships
        self.hostIdentityStatus = hostIdentityStatus
        self.updatedAt = Date(timeIntervalSince1970: floor(updatedAt.timeIntervalSince1970))
    }
}

public struct AgentResourceEndpointV2: Equatable, Sendable {
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

public struct AgentResourceRelationshipV2: Equatable, Sendable {
    public let kind: String
    public let targetAlias: String

    public init(kind: String, targetAlias: String) {
        self.kind = kind
        self.targetAlias = targetAlias
    }
}

public struct AgentResourceMetadataV2: Equatable, Sendable {
    public let key: String
    public let value: AgentResourceMetadataValueV2

    public init(key: String, value: AgentResourceMetadataValueV2) {
        self.key = key
        self.value = value
    }
}

public enum AgentResourceMetadataValueV2: Equatable, Sendable {
    case text(String)
    case integer(Int64)
    case boolean(Bool)
    case byteCount(UInt64)
    case textList([String])
}
