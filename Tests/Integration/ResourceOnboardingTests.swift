import Foundation
import SAFABroker
import SAFACrypto
import SAFADomain
import SAFATestFixtures
import Testing

@Suite("Private resource onboarding")
struct ResourceOnboardingTests {
    @Test("the trusted service commits metadata and a separate opaque password reference")
    func privatePasswordOnboarding() async throws {
        let vault = InMemoryVaultDocumentStore()
        let credentials = InMemoryPasswordSecretStore()
        let service = ResourceService(vault: vault, passwordStore: credentials)
        let secret = Data("synthetic-password".utf8)

        let resource = try await service.addPasswordResource(
            PrivateResourceDraft.synthetic(alias: "nas.home"),
            password: secret,
            now: Date(timeIntervalSince1970: 1_700_000_000)
        )

        let document = await vault.readDocument()
        #expect(document.resources == [resource])
        #expect(document.credentialReferences.count == 1)
        #expect(document.credentialReferences[0].storageLocator != secret)
        #expect(await credentials.readSecret(id: resource.authRef!) == secret)
    }

    @Test("host profile metadata and aliases are committed into the encrypted document")
    func resourceProfileOnboarding() async throws {
        let vault = InMemoryVaultDocumentStore()
        let service = ResourceService(
            vault: vault,
            passwordStore: InMemoryPasswordSecretStore()
        )
        let draft = try PrivateResourceDraft.synthetic(
            alias: "hm-105",
            alternateAliases: ["gpu-worker"],
            metadata: [
                ResourceMetadataEntry(key: "host.os.family", value: .text("linux")),
                ResourceMetadataEntry(key: "host.kernel.release", value: .text("6.8.0")),
                ResourceMetadataEntry(key: "host.cpu.logical-count", value: .integer(64)),
                ResourceMetadataEntry(
                    key: "host.memory.total-bytes",
                    value: .byteCount(274_877_906_944)
                ),
                ResourceMetadataEntry(key: "host.docker.available", value: .boolean(true)),
            ]
        )

        let resource = try await service.addPasswordResource(
            draft,
            password: Data("synthetic-password".utf8)
        )

        #expect(resource.resolvedResourceType == .hostLinux)
        #expect(resource.resolvedAlternateAliases.map(\.rawValue) == ["gpu-worker"])
        #expect(resource.resolvedMetadata == draft.metadata)
        #expect(
            try ResourceRegistry(resources: [resource])
                .resource(alias: ResourceAlias("gpu-worker")).id == resource.id
        )
    }

    @Test("onboarding rejects canonical or alternate alias collisions before storing a secret")
    func onboardingAliasCollision() async throws {
        let vault = InMemoryVaultDocumentStore()
        let credentials = InMemoryPasswordSecretStore()
        let service = ResourceService(vault: vault, passwordStore: credentials)
        _ = try await service.addPasswordResource(
            PrivateResourceDraft.synthetic(
                alias: "hm-105",
                alternateAliases: ["gpu-worker"]
            ),
            password: Data("first".utf8)
        )

        await #expect(throws: ResourceServiceError.duplicate(alias: "gpu-worker")) {
            try await service.addPasswordResource(
                PrivateResourceDraft.synthetic(alias: "gpu-worker"),
                password: Data("must-not-be-stored".utf8)
            )
        }
        #expect(await vault.readDocument().credentialReferences.count == 1)
    }

    @Test("editing an unknown alias does not expose an endpoint or credential")
    func unknownEdit() async {
        let service = ResourceService(
            vault: InMemoryVaultDocumentStore(),
            passwordStore: InMemoryPasswordSecretStore()
        )
        await #expect(throws: ResourceServiceError.notFound(alias: "missing.host")) {
            try await service.disable(alias: ResourceAlias("missing.host"))
        }
    }

    @Test("edit rotates the opaque credential and remove deletes the final secret")
    func editAndRemoveTransactions() async throws {
        let vault = InMemoryVaultDocumentStore()
        let credentials = InMemoryPasswordSecretStore()
        let service = ResourceService(vault: vault, passwordStore: credentials)
        let original = try await service.addPasswordResource(
            PrivateResourceDraft.synthetic(alias: "nas.home"),
            password: Data("old-password".utf8)
        )
        let edited = try await service.edit(
            alias: original.alias,
            draft: PrivateResourceDraft.synthetic(alias: "nas.home"),
            replacementPassword: Data("new-password".utf8)
        )

        #expect(edited.revision == original.revision + 1)
        #expect(edited.authRef != original.authRef)
        #expect(await credentials.readSecret(id: original.authRef!) == nil)
        #expect(await credentials.readSecret(id: edited.authRef!) == Data("new-password".utf8))

        let removed = try await service.remove(alias: edited.alias)
        #expect(removed.state == .deleted)
        #expect(await credentials.readSecret(id: edited.authRef!) == nil)
    }
}

extension PrivateResourceDraft {
    static func synthetic(
        alias: String,
        alternateAliases: [String] = [],
        metadata: [ResourceMetadataEntry] = []
    ) throws -> Self {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        return Self(
            alias: try ResourceAlias(alias),
            resourceType: .hostLinux,
            alternateAliases: try alternateAliases.map(ResourceAlias.init),
            accessMethods: [.ssh],
            metadata: metadata,
            displayName: "Synthetic NAS",
            endpoint: ResourceEndpoint(host: "203.0.113.10", port: 2222),
            username: "diagnostic-user",
            securityDomain: "synthetic",
            hostIdentity: HostIdentity(
                algorithm: "ssh-ed25519",
                publicKey: Data(repeating: 7, count: 32),
                fingerprint: "SHA256:synthetic",
                verifiedAt: now,
                verificationMethod: .manual,
                status: .trusted
            )
        )
    }
}
