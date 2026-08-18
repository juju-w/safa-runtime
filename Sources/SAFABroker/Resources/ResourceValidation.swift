import Foundation
import SAFADomain

extension ResourceService {
    static func ensureAliasesAvailable(
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

    static func isSSHHostType(_ resourceType: ResourceTypeIdentifier) -> Bool {
        resourceType == .hostLinux
            || resourceType == .hostMacOS
            || resourceType == .hostWindows
    }

    static func ensureValidMetadata(_ metadata: [ResourceMetadataEntry]) throws {
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

    static func ensureTemplateCompatibility(
        classification: ResourceClassification,
        accessMethods: [AccessMethodIdentifier],
        credentialKind: CredentialKind?
    ) throws -> ResourceTemplateDefinition {
        guard
            let template = ResourceTemplateRegistry.builtIn.template(classification: classification)
        else {
            throw ResourceServiceError.unsupportedTemplate(
                classification.template.id.rawValue
            )
        }
        let allowedMethods = Set(template.accessMethods)
        guard !accessMethods.isEmpty,
            accessMethods.allSatisfy(allowedMethods.contains)
        else {
            let method =
                accessMethods.first { !allowedMethods.contains($0) }
                ?? accessMethods.first
            throw ResourceServiceError.incompatibleAccessMethod(
                method?.rawValue ?? "missing"
            )
        }
        if let credentialKind,
            !template.credentialKinds.contains(credentialKind)
        {
            throw ResourceServiceError.incompatibleCredentialKind(credentialKind.rawValue)
        }
        guard !template.credentialRequired || credentialKind != nil else {
            throw ResourceServiceError.credentialRequired(template.id.rawValue)
        }
        return template
    }

    static func isBrokerStoredSecret(_ kind: CredentialKind) -> Bool {
        kind != .sshOpenSSH && kind != .sshSecureEnclaveKey
    }

    static func ensureRelationships(
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
                [.user, .agent, .import].contains(relationship.origin),
                seen.insert(key).inserted
            else {
                throw ResourceServiceError.invalidRelationship
            }
        }
    }
}
