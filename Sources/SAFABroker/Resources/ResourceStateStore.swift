import Foundation
import SAFADomain

extension ResourceService {
    @discardableResult
    public func enable(alias: ResourceAlias, now: Date = Date()) async throws -> Resource {
        try await mutationGate.withLock { [self] in
            try await enableUnlocked(alias: alias, now: now)
        }
    }

    func enableUnlocked(alias: ResourceAlias, now: Date) async throws -> Resource {
        var document = try await vault.readDocument()
        guard
            let index = document.resources.firstIndex(where: {
                $0.alias == alias && $0.state != .deleted
            })
        else {
            throw ResourceServiceError.notFound(alias: alias.rawValue)
        }
        var resource = document.resources[index]
        guard resource.state.canTransition(to: .active) else {
            throw DomainValidationError.invalidTransition
        }
        resource.state = .active
        resource.revision += 1
        resource.updatedAt = now
        document.resources[index] = resource
        try await writeResourceDocument(document)
        return resource
    }

    @discardableResult
    public func disable(alias: ResourceAlias, now: Date = Date()) async throws -> Resource {
        try await mutationGate.withLock { [self] in
            try await disableUnlocked(alias: alias, now: now)
        }
    }

    func disableUnlocked(alias: ResourceAlias, now: Date) async throws -> Resource {
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
        try await writeResourceDocument(document)
        return resource
    }

    @discardableResult
    public func remove(alias: ResourceAlias, now: Date = Date()) async throws -> Resource {
        try await mutationGate.withLock { [self] in
            try await removeUnlocked(alias: alias, now: now)
        }
    }

    func removeUnlocked(alias: ResourceAlias, now: Date) async throws -> Resource {
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
        let credentialKind = credentialID.flatMap { credentialID in
            document.credentialReferences.first(where: { $0.id == credentialID })?.kind
        }
        if let credentialID,
            !document.resources.contains(where: {
                $0.state != .deleted && $0.id != resource.id && $0.authRef == credentialID
            })
        {
            document.credentialReferences.removeAll { $0.id == credentialID }
        }
        try await writeResourceDocument(document)
        if let credentialID,
            credentialKind.map(Self.isBrokerStoredSecret) == true,
            !document.credentialReferences.contains(where: { $0.id == credentialID })
        {
            try? await passwordStore.deleteSecret(id: credentialID)
        }
        return resource
    }
}
