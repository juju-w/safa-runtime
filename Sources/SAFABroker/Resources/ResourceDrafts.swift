import Foundation
import SAFADomain

public struct PrivateResourceDraft: Equatable, Sendable {
    public let alias: ResourceAlias
    public let resourceType: ResourceTypeIdentifier
    public let alternateAliases: [ResourceAlias]
    public let accessMethods: [AccessMethodIdentifier]
    public let metadata: [ResourceMetadataEntry]
    public let relationships: [ResourceRelationship]
    public let displayName: String?
    public let endpoint: ResourceEndpoint
    public let username: String
    public let securityDomain: String
    public let hostIdentity: HostIdentity

    public init(
        alias: ResourceAlias,
        resourceType: ResourceTypeIdentifier = .hostLinux,
        alternateAliases: [ResourceAlias] = [],
        accessMethods: [AccessMethodIdentifier] = [.ssh],
        metadata: [ResourceMetadataEntry] = [],
        relationships: [ResourceRelationship] = [],
        displayName: String? = nil,
        endpoint: ResourceEndpoint,
        username: String,
        securityDomain: String,
        hostIdentity: HostIdentity
    ) {
        self.alias = alias
        self.resourceType = resourceType
        self.alternateAliases = alternateAliases
        self.accessMethods = accessMethods
        self.metadata = metadata
        self.relationships = relationships
        self.displayName = displayName
        self.endpoint = endpoint
        self.username = username
        self.securityDomain = securityDomain
        self.hostIdentity = hostIdentity
    }
}

/// A connection discovered from a broker-owned local adapter. It deliberately
/// carries no credential or host identity: discovery is not proof of trust.
public struct DiscoveredResourceDraft: Equatable, Sendable {
    public let alias: ResourceAlias
    public let resourceType: ResourceTypeIdentifier?
    public let displayName: String?
    public let endpoint: ResourceEndpoint
    public let username: String
    public let securityDomain: String

    public init(
        alias: ResourceAlias,
        resourceType: ResourceTypeIdentifier? = nil,
        displayName: String? = nil,
        endpoint: ResourceEndpoint,
        username: String,
        securityDomain: String
    ) {
        self.alias = alias
        self.resourceType = resourceType
        self.displayName = displayName
        self.endpoint = endpoint
        self.username = username
        self.securityDomain = securityDomain
    }
}

public enum ResourceServiceError: Error, Equatable, Sendable {
    case duplicate(alias: String)
    case duplicateMetadataKey(String)
    case invalidMetadata(String)
    case notFound(alias: String)
    case invalidHostIdentity
    case invalidRelationship
    case referencedByResource(alias: String)
    case unsafeConnectionChange
    case unsupportedDiscoveredResourceType(String)
    case staleResource
}
