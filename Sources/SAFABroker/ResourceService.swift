import Foundation
import SAFACrypto
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

public enum ResourceServiceError: Error, Equatable, Sendable {
    case duplicate(alias: String)
    case duplicateMetadataKey(String)
    case invalidMetadata(String)
    case notFound(alias: String)
    case invalidHostIdentity
    case invalidRelationship
    case referencedByResource(alias: String)
}

public actor ResourceService {
    private let vault: any VaultDocumentStoring
    private let passwordStore: any PasswordSecretStoring

    public init(
        vault: any VaultDocumentStoring,
        passwordStore: any PasswordSecretStoring
    ) {
        self.vault = vault
        self.passwordStore = passwordStore
    }

    public func addPasswordResource(
        _ draft: PrivateResourceDraft,
        password: Data,
        now: Date = Date()
    ) async throws -> Resource {
        guard draft.hostIdentity.status == .trusted else {
            throw ResourceServiceError.invalidHostIdentity
        }
        var document = try await vault.readDocument()
        try Self.ensureValidMetadata(draft.metadata)
        try Self.ensureAliasesAvailable(
            canonical: draft.alias,
            alternates: draft.alternateAliases,
            excluding: nil,
            resources: document.resources
        )
        let resourceID = UUID()
        try Self.ensureRelationships(
            draft.relationships,
            ownerID: resourceID,
            resources: document.resources
        )

        let credentialID = UUID()
        let passwordCredential = PasswordCredential(store: passwordStore)
        let locator = try await passwordCredential.create(secret: password, id: credentialID)
        let reference = CredentialReference(
            id: credentialID,
            kind: .sshPassword,
            storageLocator: Data(locator.account.utf8),
            securityDomains: [draft.securityDomain],
            accessClass: .automaticWithinPolicy,
            health: .ready,
            createdAt: now
        )
        let resource = Resource(
            id: resourceID,
            alias: draft.alias,
            resourceType: draft.resourceType,
            alternateAliases: draft.alternateAliases,
            accessMethods: draft.accessMethods,
            metadata: draft.metadata,
            relationships: draft.relationships,
            displayName: draft.displayName,
            endpoint: draft.endpoint,
            username: draft.username,
            securityDomain: draft.securityDomain,
            hostIdentity: draft.hostIdentity,
            authRef: credentialID,
            revision: 1,
            state: .active,
            createdAt: now,
            updatedAt: now
        )
        document.credentialReferences.append(reference)
        document.resources.append(resource)
        do {
            try await vault.writeDocument(document)
        } catch {
            try? await passwordCredential.delete(id: credentialID)
            throw error
        }
        return resource
    }

    @discardableResult
    public func disable(alias: ResourceAlias, now: Date = Date()) async throws -> Resource {
        var document = try await vault.readDocument()
        guard
            let index = document.resources.firstIndex(where: {
                $0.alias == alias && $0.state != .deleted
            })
        else {
            throw ResourceServiceError.notFound(alias: alias.rawValue)
        }
        var resource = document.resources[index]
        guard resource.state.canTransition(to: .disabled) else {
            throw DomainValidationError.invalidTransition
        }
        resource.state = .disabled
        resource.revision += 1
        resource.updatedAt = now
        document.resources[index] = resource
        try await vault.writeDocument(document)
        return resource
    }

    private static func ensureAliasesAvailable(
        canonical: ResourceAlias,
        alternates: [ResourceAlias],
        excluding resourceID: UUID?,
        resources: [Resource]
    ) throws {
        let proposed = Set([canonical] + alternates)
        guard proposed.count == alternates.count + 1 else {
            let values = [canonical] + alternates
            let duplicate =
                Dictionary(grouping: values, by: \.self)
                .first(where: { $0.value.count > 1 })?.key ?? canonical
            throw ResourceServiceError.duplicate(alias: duplicate.rawValue)
        }
        for resource in resources where resource.state != .deleted && resource.id != resourceID {
            for alias in [resource.alias] + resource.resolvedAlternateAliases
            where proposed.contains(alias) {
                throw ResourceServiceError.duplicate(alias: alias.rawValue)
            }
        }
    }

    private static func ensureValidMetadata(_ metadata: [ResourceMetadataEntry]) throws {
        var keys: Set<ResourceMetadataKey> = []
        for entry in metadata where !keys.insert(entry.key).inserted {
            throw ResourceServiceError.duplicateMetadataKey(entry.key.rawValue)
        }
        do {
            try ResourceMetadataPolicy.validateForPersistence(metadata)
        } catch let error as ResourceMetadataPolicyError {
            switch error {
            case .sensitiveOrInvalidValue(let key):
                throw ResourceServiceError.invalidMetadata(key)
            }
        }
    }

    private static func ensureRelationships(
        _ relationships: [ResourceRelationship],
        ownerID: UUID,
        resources: [Resource]
    ) throws {
        let liveIDs = Set(resources.filter { $0.state != .deleted }.map(\.id))
        var seen: Set<String> = []
        for relationship in relationships {
            let key = "\(relationship.kind.rawValue):\(relationship.targetResourceID.uuidString)"
            guard relationship.targetResourceID != ownerID,
                liveIDs.contains(relationship.targetResourceID),
                seen.insert(key).inserted
            else {
                throw ResourceServiceError.invalidRelationship
            }
        }
    }

    @discardableResult
    public func edit(
        alias: ResourceAlias,
        draft: PrivateResourceDraft,
        replacementPassword: Data? = nil,
        now: Date = Date()
    ) async throws -> Resource {
        guard draft.alias == alias else {
            throw ResourceServiceError.notFound(alias: alias.rawValue)
        }
        guard draft.hostIdentity.status == .trusted else {
            throw ResourceServiceError.invalidHostIdentity
        }
        var document = try await vault.readDocument()
        guard
            let index = document.resources.firstIndex(where: {
                $0.alias == alias && $0.state != .deleted
            })
        else {
            throw ResourceServiceError.notFound(alias: alias.rawValue)
        }

        var resource = document.resources[index]
        try Self.ensureValidMetadata(draft.metadata)
        try Self.ensureAliasesAvailable(
            canonical: draft.alias,
            alternates: draft.alternateAliases,
            excluding: resource.id,
            resources: document.resources
        )
        try Self.ensureRelationships(
            draft.relationships,
            ownerID: resource.id,
            resources: document.resources
        )
        let previousCredentialID = resource.authRef
        var replacementCredentialID: UUID?
        if let replacementPassword {
            let id = UUID()
            let credential = PasswordCredential(store: passwordStore)
            let locator = try await credential.create(secret: replacementPassword, id: id)
            replacementCredentialID = id
            resource.authRef = id
            document.credentialReferences.append(
                CredentialReference(
                    id: id,
                    kind: .sshPassword,
                    storageLocator: Data(locator.account.utf8),
                    securityDomains: [draft.securityDomain],
                    accessClass: .automaticWithinPolicy,
                    health: .ready,
                    createdAt: now
                )
            )
        }
        resource.displayName = draft.displayName
        resource.profile = ResourceProfile(
            resourceType: draft.resourceType,
            alternateAliases: draft.alternateAliases,
            accessMethods: draft.accessMethods,
            metadata: draft.metadata,
            relationships: draft.relationships,
            credentialBindings: resource.resolvedCredentialBindings
        )
        resource.endpoint = draft.endpoint
        resource.username = draft.username
        resource.securityDomain = draft.securityDomain
        resource.hostIdentity = draft.hostIdentity
        resource.revision += 1
        resource.updatedAt = now
        document.resources[index] = resource

        if let replacementCredentialID,
            let previousCredentialID,
            previousCredentialID != replacementCredentialID,
            !document.resources.contains(where: {
                $0.state != .deleted && $0.id != resource.id && $0.authRef == previousCredentialID
            })
        {
            document.credentialReferences.removeAll { $0.id == previousCredentialID }
        }
        do {
            try await vault.writeDocument(document)
        } catch {
            if let replacementCredentialID {
                try? await passwordStore.deleteSecret(id: replacementCredentialID)
            }
            throw error
        }
        if let replacementCredentialID,
            let previousCredentialID,
            previousCredentialID != replacementCredentialID,
            !document.credentialReferences.contains(where: { $0.id == previousCredentialID })
        {
            try? await passwordStore.deleteSecret(id: previousCredentialID)
        }
        return resource
    }

    @discardableResult
    public func remove(alias: ResourceAlias, now: Date = Date()) async throws -> Resource {
        var document = try await vault.readDocument()
        guard
            let index = document.resources.firstIndex(where: {
                $0.alias == alias && $0.state != .deleted
            })
        else {
            throw ResourceServiceError.notFound(alias: alias.rawValue)
        }
        var resource = document.resources[index]
        guard resource.state.canTransition(to: .deleted) else {
            throw DomainValidationError.invalidTransition
        }
        do {
            try ResourceDeletionPolicy.validateRemoval(
                resourceID: resource.id,
                from: document.resources
            )
        } catch ResourceDeletionPolicyError.referencedBy(let alias) {
            throw ResourceServiceError.referencedByResource(alias: alias)
        }
        resource.state = .deleted
        resource.revision += 1
        resource.updatedAt = now
        document.resources[index] = resource

        let credentialID = resource.authRef
        if let credentialID,
            !document.resources.contains(where: {
                $0.state != .deleted && $0.id != resource.id && $0.authRef == credentialID
            })
        {
            document.credentialReferences.removeAll { $0.id == credentialID }
        }
        try await vault.writeDocument(document)
        if let credentialID,
            !document.credentialReferences.contains(where: { $0.id == credentialID })
        {
            try? await passwordStore.deleteSecret(id: credentialID)
        }
        return resource
    }
}
