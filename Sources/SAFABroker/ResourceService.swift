import Foundation
import SAFACrypto
import SAFADomain

public struct PrivateResourceDraft: Equatable, Sendable {
    public let alias: ResourceAlias
    public let displayName: String?
    public let endpoint: ResourceEndpoint
    public let username: String
    public let securityDomain: String
    public let hostIdentity: HostIdentity

    public init(
        alias: ResourceAlias,
        displayName: String? = nil,
        endpoint: ResourceEndpoint,
        username: String,
        securityDomain: String,
        hostIdentity: HostIdentity
    ) {
        self.alias = alias
        self.displayName = displayName
        self.endpoint = endpoint
        self.username = username
        self.securityDomain = securityDomain
        self.hostIdentity = hostIdentity
    }
}

public enum ResourceServiceError: Error, Equatable, Sendable {
    case duplicate(alias: String)
    case notFound(alias: String)
    case invalidHostIdentity
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
        guard
            !document.resources.contains(where: {
                $0.alias == draft.alias && $0.state != .deleted
            })
        else {
            throw ResourceServiceError.duplicate(alias: draft.alias.rawValue)
        }

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
            id: UUID(),
            alias: draft.alias,
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
