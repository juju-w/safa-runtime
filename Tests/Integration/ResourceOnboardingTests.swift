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
    static func synthetic(alias: String) throws -> Self {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        return Self(
            alias: try ResourceAlias(alias),
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
