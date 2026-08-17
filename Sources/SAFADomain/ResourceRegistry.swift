import Foundation

public enum ResourceRegistryError: Error, Equatable, Sendable {
    case duplicateAlias(alias: String)
    case duplicateResourceID(UUID)
    case duplicateMetadataKey(resourceAlias: String, key: String)
    case invalidRelationship(resourceAlias: String, targetResourceID: UUID)
    case notFound(alias: String)
}

public enum ResourceHealth: String, Codable, Sendable {
    case ready
    case needsSetup = "needs_setup"
    case needsVerification = "needs_verification"
    case disabled
}

public struct SafeResourceProjection: Codable, Equatable, Sendable {
    public let alias: ResourceAlias
    public let displayName: String?
    public let resourceType: ResourceTypeIdentifier
    public let transport: TransportKind?
    public let state: ResourceState
    public let capabilities: [String]
    public let health: ResourceHealth
    public let summaryMetadata: [ResourceMetadataEntry]

    public init(resource: Resource) {
        alias = resource.alias
        // Display names remain encrypted detail unless a separate disclosure policy is introduced.
        displayName = nil
        resourceType = resource.resolvedResourceType
        transport = resource.transport
        state = resource.state
        let template = ResourceTemplateRegistry.builtIn.template(
            resourceType: resource.resolvedResourceType
        )
        var values = template?.capabilities ?? []
        if resource.resolvedAccessMethods.contains(.ssh), resource.sudoRef != nil {
            values.append("sudo")
        }
        capabilities = values
        if resource.state == .disabled || resource.state == .deleted {
            health = .disabled
        } else {
            let hasCredential =
                resource.authRef != nil
                || !resource.resolvedCredentialBindings.isEmpty
            let credentialReady = !(template?.credentialRequired ?? true) || hasCredential
            let connectionReady: Bool
            let verificationReady: Bool
            if resource.resolvedAccessMethods.contains(.ssh) {
                connectionReady =
                    resource.endpoint != nil
                    && resource.hostIdentity?.status == .trusted
                // SSH setup verifies the pinned host identity and the expected account
                // before the broker activates the resource.
                verificationReady = true
            } else {
                connectionReady = resource.endpoint != nil
                verificationReady = resource.verification?.status == .verified
            }
            if resource.state != .active || !connectionReady || !credentialReady {
                health = .needsSetup
            } else if !verificationReady {
                health = .needsVerification
            } else {
                health = .ready
            }
        }
        summaryMetadata = ResourceSummaryDisclosure.publicEntries(from: resource.resolvedMetadata)
    }
}

public struct ResourceRegistry: Sendable {
    private let resourcesByAlias: [ResourceAlias: Resource]

    public init(resources: [Resource]) throws {
        let liveResources = resources.filter { $0.state != .deleted }
        var resourcesByID: [UUID: Resource] = [:]
        for resource in liveResources {
            guard resourcesByID.updateValue(resource, forKey: resource.id) == nil else {
                throw ResourceRegistryError.duplicateResourceID(resource.id)
            }
        }
        var index: [ResourceAlias: Resource] = [:]
        for resource in liveResources {
            var metadataKeys: Set<ResourceMetadataKey> = []
            for entry in resource.resolvedMetadata {
                guard metadataKeys.insert(entry.key).inserted else {
                    throw ResourceRegistryError.duplicateMetadataKey(
                        resourceAlias: resource.alias.rawValue,
                        key: entry.key.rawValue
                    )
                }
            }
            for alias in [resource.alias] + resource.resolvedAlternateAliases {
                guard index.updateValue(resource, forKey: alias) == nil else {
                    throw ResourceRegistryError.duplicateAlias(alias: alias.rawValue)
                }
            }
            var relationships: Set<String> = []
            for relationship in resource.resolvedRelationships {
                let relationshipKey =
                    "\(relationship.kind.rawValue):\(relationship.targetResourceID.uuidString)"
                guard relationship.targetResourceID != resource.id,
                    resourcesByID[relationship.targetResourceID] != nil,
                    relationships.insert(relationshipKey).inserted
                else {
                    throw ResourceRegistryError.invalidRelationship(
                        resourceAlias: resource.alias.rawValue,
                        targetResourceID: relationship.targetResourceID
                    )
                }
            }
        }
        resourcesByAlias = index
    }

    public func list(state: ResourceState? = nil) -> [SafeResourceProjection] {
        resourcesByAlias.values.reduce(into: [UUID: Resource]()) { unique, resource in
            unique[resource.id] = resource
        }.values
            .filter { state == nil || $0.state == state }
            .sorted { $0.alias.rawValue < $1.alias.rawValue }
            .map(SafeResourceProjection.init)
    }

    public func resource(alias: ResourceAlias) throws -> Resource {
        guard let resource = resourcesByAlias[alias] else {
            throw ResourceRegistryError.notFound(alias: alias.rawValue)
        }
        return resource
    }
}
