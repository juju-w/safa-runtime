import Foundation
import SAFADomain
import SAFAProtocol

public enum TrustedResourceSetupError: Error, Equatable, Sendable {
    case invalidSession
    case invalidPayload
    case unsupportedTemplate
}

/// Owns protected resource configuration received only from the separately
/// signed trusted-local XPC role. Agent-facing DTOs never contain these values.
public actor TrustedResourceSetupService {
    private let resources: ResourceService
    private var sessions: [UUID: ResourceAlias] = [:]

    public init(resources: ResourceService) {
        self.resources = resources
    }

    public func begin(alias: ResourceAlias) -> UUID {
        let sessionID = UUID()
        sessions[sessionID] = alias
        return sessionID
    }

    public func commit(
        sessionID: UUID,
        protectedPayload: Data,
        now: Date = Date()
    ) async throws -> Resource {
        guard let alias = sessions.removeValue(forKey: sessionID) else {
            throw TrustedResourceSetupError.invalidSession
        }
        let payload = try CanonicalCodec.decode(
            ProtectedResourceSetupPayload.self,
            from: protectedPayload,
            maxBytes: 64 * 1_024
        )
        guard !payload.host.isEmpty,
            payload.host.utf8.count <= 255,
            (payload.username?.utf8.count ?? 0) <= 255,
            payload.securityDomain.utf8.count <= 128,
            (payload.hostFingerprint?.utf8.count ?? 0) <= 512
        else {
            throw TrustedResourceSetupError.invalidPayload
        }

        let resourceType =
            try payload.resourceType.map { try ResourceTypeIdentifier($0) }
            ?? .hostLinux
        guard
            let template = ResourceTemplateRegistry.builtIn.template(resourceType: resourceType)
        else {
            throw TrustedResourceSetupError.unsupportedTemplate
        }
        let accessMethods = try (payload.accessMethods ?? template.accessMethods.map(\.rawValue))
            .map { try AccessMethodIdentifier($0) }
        let hostIdentity = try hostIdentity(
            payload: payload, accessMethods: accessMethods, now: now)
        let protectedCredential = payload.credential ?? payload.password
        let credentialKind =
            try payload.credentialKind.map { try CredentialKind($0) }
            ?? (protectedCredential == nil ? nil : template.credentialKinds.first)
        let draft = PrivateResourceDraft(
            alias: alias,
            resourceType: resourceType,
            alternateAliases: try (payload.alternateAliases ?? []).map { try ResourceAlias($0) },
            accessMethods: accessMethods,
            metadata: try (payload.metadata ?? []).map(Self.domainMetadata),
            displayName: payload.displayName,
            endpoint: ResourceEndpoint(
                scheme: payload.scheme,
                host: payload.host,
                port: payload.port,
                path: payload.path
            ),
            username: payload.username,
            securityDomain: payload.securityDomain,
            hostIdentity: hostIdentity,
            credentialKind: credentialKind,
            credentialRole: try payload.credentialRole.map { try ResourceCredentialRole($0) }
                ?? .primary
        )

        do {
            _ = try await resources.resource(alias: alias)
            return try await resources.edit(
                alias: alias,
                draft: draft,
                replacementPassword: protectedCredential,
                now: now
            )
        } catch ResourceServiceError.notFound {
            return try await resources.addProtectedResource(
                draft,
                credential: protectedCredential,
                now: now
            )
        }
    }

    private func hostIdentity(
        payload: ProtectedResourceSetupPayload,
        accessMethods: [AccessMethodIdentifier],
        now: Date
    ) throws -> HostIdentity? {
        guard accessMethods.contains(.ssh) else { return nil }
        guard let username = payload.username, !username.isEmpty,
            let algorithm = payload.hostKeyAlgorithm, !algorithm.isEmpty,
            let publicKey = payload.hostPublicKey, !publicKey.isEmpty,
            let fingerprint = payload.hostFingerprint, !fingerprint.isEmpty
        else {
            throw TrustedResourceSetupError.invalidPayload
        }
        return HostIdentity(
            algorithm: algorithm,
            publicKey: publicKey,
            fingerprint: fingerprint,
            verifiedAt: now,
            verificationMethod: .manual,
            status: .trusted
        )
    }

    private static func domainMetadata(
        _ entry: ResourceMetadataEntryV1
    ) throws -> ResourceMetadataEntry {
        ResourceMetadataEntry(
            key: try ResourceMetadataKey(entry.key),
            value: domainMetadataValue(entry.value),
            observedAt: entry.observedAt
        )
    }

    private static func domainMetadataValue(
        _ value: ResourceMetadataValueV1
    ) -> ResourceMetadataValue {
        switch value {
        case let .text(value): .text(value)
        case let .integer(value): .integer(value)
        case let .boolean(value): .boolean(value)
        case let .byteCount(value): .byteCount(value)
        case let .textList(value): .textList(value)
        }
    }
}
