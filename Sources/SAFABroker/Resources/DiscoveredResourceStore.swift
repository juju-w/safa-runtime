import Foundation
import SAFADomain

extension ResourceService {
    public func addDiscoveredResource(
        _ draft: DiscoveredResourceDraft,
        now: Date = Date()
    ) async throws -> Resource {
        try await mutationGate.withLock { [self] in
            try await addDiscoveredResourceUnlocked(draft, now: now)
        }
    }

    func addDiscoveredResourceUnlocked(
        _ draft: DiscoveredResourceDraft,
        now: Date
    ) async throws -> Resource {
        var document = try await vault.readDocument()
        let resourceType = draft.resourceType ?? .hostLinux
        guard Self.isSSHHostType(resourceType) else {
            throw ResourceServiceError.unsupportedDiscoveredResourceType(resourceType.rawValue)
        }
        try Self.ensureAliasesAvailable(
            canonical: draft.alias,
            alternates: [],
            excluding: nil,
            resources: document.resources
        )
        let resource = Resource(
            id: UUID(),
            alias: draft.alias,
            resourceType: resourceType,
            accessMethods: [.ssh],
            displayName: draft.displayName,
            transport: .ssh,
            endpoint: draft.endpoint,
            username: draft.username,
            securityDomain: draft.securityDomain,
            revision: 1,
            state: .draft,
            createdAt: now,
            updatedAt: now
        )
        document.resources.append(resource)
        try await vault.writeDocument(document)
        return resource
    }

    public func editDiscoveredResource(
        alias: ResourceAlias,
        draft: DiscoveredResourceDraft,
        now: Date = Date()
    ) async throws -> Resource {
        try await mutationGate.withLock { [self] in
            try await editDiscoveredResourceUnlocked(alias: alias, draft: draft, now: now)
        }
    }

    func editDiscoveredResourceUnlocked(
        alias: ResourceAlias,
        draft: DiscoveredResourceDraft,
        now: Date
    ) async throws -> Resource {
        guard alias == draft.alias else {
            throw ResourceServiceError.notFound(alias: alias.rawValue)
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
        let resourceType = draft.resourceType ?? resource.resolvedResourceType
        guard Self.isSSHHostType(resource.resolvedResourceType),
            Self.isSSHHostType(resourceType)
        else {
            throw ResourceServiceError.unsupportedDiscoveredResourceType(resourceType.rawValue)
        }
        let connectionChanged =
            resource.endpoint != draft.endpoint
            || resource.username != draft.username
            || resource.securityDomain != draft.securityDomain
        if connectionChanged && (resource.hostIdentity != nil || resource.authRef != nil) {
            throw ResourceServiceError.unsafeConnectionChange
        }

        resource.profile = ResourceProfile(
            resourceType: resourceType,
            alternateAliases: resource.resolvedAlternateAliases,
            accessMethods: [.ssh],
            metadata: resource.resolvedMetadata,
            relationships: resource.resolvedRelationships,
            credentialBindings: resource.resolvedCredentialBindings
        )
        resource.displayName = draft.displayName ?? resource.displayName
        resource.endpoint = draft.endpoint
        resource.username = draft.username
        resource.securityDomain = draft.securityDomain
        resource.revision += 1
        resource.updatedAt = now
        document.resources[index] = resource
        try await vault.writeDocument(document)
        return resource
    }

    public func activateDiscoveredResource(
        alias: ResourceAlias,
        expectedRevision: UInt64,
        hostIdentity: HostIdentity,
        credentialLocator: Data,
        now: Date = Date()
    ) async throws -> Resource {
        try await mutationGate.withLock { [self] in
            try await activateDiscoveredResourceUnlocked(
                alias: alias,
                expectedRevision: expectedRevision,
                hostIdentity: hostIdentity,
                credentialLocator: credentialLocator,
                now: now
            )
        }
    }

    func activateDiscoveredResourceUnlocked(
        alias: ResourceAlias,
        expectedRevision: UInt64,
        hostIdentity: HostIdentity,
        credentialLocator: Data,
        now: Date
    ) async throws -> Resource {
        guard hostIdentity.status == .trusted else {
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
        guard resource.revision == expectedRevision, resource.state == .draft,
            resource.authRef == nil, resource.hostIdentity == nil
        else {
            throw ResourceServiceError.staleResource
        }

        let credentialID = UUID()
        document.credentialReferences.append(
            CredentialReference(
                id: credentialID,
                kind: .sshOpenSSH,
                storageLocator: credentialLocator,
                securityDomains: [resource.securityDomain],
                accessClass: .automaticWithinPolicy,
                health: .ready,
                createdAt: now
            )
        )
        resource.hostIdentity = hostIdentity
        resource.authRef = credentialID
        resource.state = .active
        resource.revision += 1
        resource.updatedAt = now
        document.resources[index] = resource
        try await vault.writeDocument(document)
        return resource
    }
}
