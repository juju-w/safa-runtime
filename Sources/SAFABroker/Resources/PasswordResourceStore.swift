import Foundation
import SAFACrypto
import SAFADomain

extension ResourceService {
    public func addPasswordResource(
        _ draft: PrivateResourceDraft,
        password: Data,
        now: Date = Date()
    ) async throws -> Resource {
        guard draft.credentialKind != nil else {
            throw ResourceServiceError.unexpectedCredential
        }
        return try await addProtectedResource(draft, credential: password, now: now)
    }

    public func addProtectedResource(
        _ draft: PrivateResourceDraft,
        credential: Data?,
        now: Date = Date()
    ) async throws -> Resource {
        try await mutationGate.withLock { [self] in
            try await addProtectedResourceUnlocked(draft, credential: credential, now: now)
        }
    }

    func addProtectedResourceUnlocked(
        _ draft: PrivateResourceDraft,
        credential: Data?,
        now: Date
    ) async throws -> Resource {
        let template = try Self.ensureTemplateCompatibility(
            resourceType: draft.resourceType,
            accessMethods: draft.accessMethods,
            credentialKind: draft.credentialKind
        )
        guard (credential == nil) == (draft.credentialKind == nil) else {
            throw ResourceServiceError.unexpectedCredential
        }
        guard !template.credentialRequired || credential != nil else {
            throw ResourceServiceError.credentialRequired(template.id.rawValue)
        }
        if draft.accessMethods.contains(.ssh), draft.hostIdentity?.status != .trusted {
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

        let credentialID = credential.map { _ in UUID() }
        var reference: CredentialReference?
        if let credential, let credentialID, let credentialKind = draft.credentialKind {
            let passwordCredential = PasswordCredential(store: passwordStore)
            let locator = try await passwordCredential.create(secret: credential, id: credentialID)
            reference = CredentialReference(
                id: credentialID,
                kind: credentialKind,
                storageLocator: Data(locator.account.utf8),
                securityDomains: [draft.securityDomain],
                accessClass: .automaticWithinPolicy,
                health: .ready,
                createdAt: now
            )
        }
        let resource = Resource(
            id: resourceID,
            alias: draft.alias,
            resourceType: draft.resourceType,
            alternateAliases: draft.alternateAliases,
            accessMethods: draft.accessMethods,
            metadata: draft.metadata,
            relationships: draft.relationships,
            credentialBindings: credentialID.map {
                [
                    ResourceCredentialBinding(
                        role: draft.credentialRole,
                        credentialID: $0
                    )
                ]
            } ?? [],
            displayName: draft.displayName,
            transport: draft.accessMethods.contains(.ssh) ? .ssh : nil,
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
        if let reference {
            document.credentialReferences.append(reference)
        }
        document.resources.append(resource)
        do {
            try await vault.writeDocument(document)
        } catch {
            if let credentialID {
                try? await passwordStore.deleteSecret(id: credentialID)
            }
            throw error
        }
        return resource
    }

    @discardableResult
    public func edit(
        alias: ResourceAlias,
        draft: PrivateResourceDraft,
        replacementPassword: Data? = nil,
        now: Date = Date()
    ) async throws -> Resource {
        try await mutationGate.withLock { [self] in
            try await editUnlocked(
                alias: alias,
                draft: draft,
                replacementPassword: replacementPassword,
                now: now
            )
        }
    }

    func editUnlocked(
        alias: ResourceAlias,
        draft: PrivateResourceDraft,
        replacementPassword: Data?,
        now: Date
    ) async throws -> Resource {
        guard draft.alias == alias else {
            throw ResourceServiceError.notFound(alias: alias.rawValue)
        }
        _ = try Self.ensureTemplateCompatibility(
            resourceType: draft.resourceType,
            accessMethods: draft.accessMethods,
            credentialKind: draft.credentialKind
        )
        if draft.accessMethods.contains(.ssh), draft.hostIdentity?.status != .trusted {
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
        guard resource.resolvedResourceType == draft.resourceType else {
            throw ResourceServiceError.templateChangeNotAllowed(
                from: resource.resolvedResourceType.rawValue,
                to: draft.resourceType.rawValue
            )
        }
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
            guard let credentialKind = draft.credentialKind else {
                throw ResourceServiceError.unexpectedCredential
            }
            let id = UUID()
            let credential = PasswordCredential(store: passwordStore)
            let locator = try await credential.create(secret: replacementPassword, id: id)
            replacementCredentialID = id
            resource.authRef = id
            document.credentialReferences.append(
                CredentialReference(
                    id: id,
                    kind: credentialKind,
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
            credentialBindings: replacementCredentialID.map {
                [
                    ResourceCredentialBinding(
                        role: draft.credentialRole,
                        credentialID: $0
                    )
                ]
            } ?? resource.resolvedCredentialBindings
        )
        resource.endpoint = draft.endpoint
        resource.username = draft.username
        resource.securityDomain = draft.securityDomain
        resource.hostIdentity = draft.hostIdentity
        resource.revision += 1
        resource.updatedAt = now
        document.resources[index] = resource

        let previousCredentialKind = previousCredentialID.flatMap { previousID in
            document.credentialReferences.first(where: { $0.id == previousID })?.kind
        }
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
            !document.credentialReferences.contains(where: { $0.id == previousCredentialID }),
            previousCredentialKind.map(Self.isBrokerStoredSecret) == true
        {
            try? await passwordStore.deleteSecret(id: previousCredentialID)
        }
        return resource
    }
}
