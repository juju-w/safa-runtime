import Foundation
import SAFACrypto
import SAFADomain
import SAFAProtocol
import SAFATestFixtures
import Testing
@testable import SAFABroker

@Suite("CLI resource lifecycle")
struct ResourceLifecycleTests {
    @Test("denied user presence leaves the vault unchanged")
    func deniedMutationFailsClosed() async throws {
        let vault = InMemoryVaultDocumentStore()
        let authorizer = LifecyclePresenceAuthorizer(result: false)
        let lifecycle = ResourceLifecycleService(
            resources: ResourceService(
                vault: vault,
                passwordStore: InMemoryPasswordSecretStore()
            ),
            sshConfigResolver: FailingSSHConfigResolver(),
            userPresenceAuthorizer: authorizer,
            cooldown: 0
        )

        await #expect(throws: ResourceLifecycleError.denied) {
            try await lifecycle.mutate(
                action: .add,
                alias: ResourceAlias("nas.home"),
                mutation: ResourceMutationV1(
                    sourceSSHConfigAlias: ResourceAlias("home-nas"),
                    resourceType: .hostNAS
                ),
                now: Date(timeIntervalSince1970: 1_700_000_000)
            )
        }
        #expect(await vault.readDocument().resources.isEmpty)
        #expect(await authorizer.reasons == ["Add SAFA resource nas.home"])
    }

    @Test("SSH config import rejects non-host profiles before prompting")
    func nonHostImportIsRejectedBeforePrompt() async throws {
        let vault = InMemoryVaultDocumentStore()
        let authorizer = LifecyclePresenceAuthorizer(result: true)
        let lifecycle = ResourceLifecycleService(
            resources: ResourceService(
                vault: vault,
                passwordStore: InMemoryPasswordSecretStore()
            ),
            sshConfigResolver: FailingSSHConfigResolver(),
            userPresenceAuthorizer: authorizer,
            cooldown: 0
        )

        await #expect(
            throws: ResourceLifecycleError.unsupportedResourceType("database.mysql")
        ) {
            try await lifecycle.mutate(
                action: .add,
                alias: ResourceAlias("mysql.test"),
                mutation: ResourceMutationV1(
                    sourceSSHConfigAlias: ResourceAlias("mysql-host"),
                    resourceType: .databaseMySQL
                ),
                now: Date(timeIntervalSince1970: 1_700_000_000)
            )
        }
        #expect(await authorizer.reasons.isEmpty)
        #expect(await vault.readDocument().resources.isEmpty)
    }

    @Test("approved add imports broker-resolved SSH settings as a draft")
    func approvedSSHConfigImport() async throws {
        let vault = InMemoryVaultDocumentStore()
        let authorizer = LifecyclePresenceAuthorizer(result: true)
        let lifecycle = ResourceLifecycleService(
            resources: ResourceService(
                vault: vault,
                passwordStore: InMemoryPasswordSecretStore()
            ),
            sshConfigResolver: StaticSSHConfigResolver(
                value: ResolvedSSHConfig(
                    endpoint: ResourceEndpoint(
                        scheme: "ssh",
                        host: "nas.internal",
                        port: 2222
                    ),
                    username: "operator"
                )
            ),
            userPresenceAuthorizer: authorizer,
            cooldown: 0
        )

        let resource = try await lifecycle.mutate(
            action: .add,
            alias: ResourceAlias("nas.home"),
            mutation: ResourceMutationV1(
                sourceSSHConfigAlias: ResourceAlias("home-nas"),
                resourceType: .hostNAS,
                displayName: "Home NAS"
            ),
            now: Date(timeIntervalSince1970: 1_700_000_000)
        )

        #expect(resource.alias.rawValue == "nas.home")
        #expect(resource.resolvedResourceType == .hostNAS)
        #expect(resource.endpoint?.host == "nas.internal")
        #expect(resource.username == "operator")
        #expect(resource.state == .draft)
        #expect(resource.authRef == nil)
        #expect(resource.hostIdentity == nil)
    }

    @Test("edit preserves the existing type unless type is explicitly supplied")
    func editPreservesType() async throws {
        let vault = InMemoryVaultDocumentStore()
        let resources = ResourceService(
            vault: vault,
            passwordStore: InMemoryPasswordSecretStore()
        )
        _ = try await resources.addDiscoveredResource(
            DiscoveredResourceDraft(
                alias: ResourceAlias("nas.home"),
                resourceType: .hostNAS,
                endpoint: ResourceEndpoint(host: "nas.internal", port: 22),
                username: "operator",
                securityDomain: "local-ssh-config"
            )
        )
        let lifecycle = ResourceLifecycleService(
            resources: resources,
            sshConfigResolver: StaticSSHConfigResolver(
                value: ResolvedSSHConfig(
                    endpoint: ResourceEndpoint(host: "nas.internal", port: 22),
                    username: "operator"
                )
            ),
            userPresenceAuthorizer: LifecyclePresenceAuthorizer(result: true),
            cooldown: 0
        )

        let edited = try await lifecycle.mutate(
            action: .edit,
            alias: ResourceAlias("nas.home"),
            mutation: ResourceMutationV1(
                sourceSSHConfigAlias: ResourceAlias("home-nas"),
                displayName: "Storage"
            ),
            now: Date(timeIntervalSince1970: 1_700_000_001)
        )

        #expect(edited.resolvedResourceType == .hostNAS)
        #expect(edited.displayName == "Storage")
    }

    @Test("disable and remove are real authorized broker transactions")
    func disableAndRemove() async throws {
        let vault = InMemoryVaultDocumentStore()
        let resources = ResourceService(
            vault: vault,
            passwordStore: InMemoryPasswordSecretStore()
        )
        _ = try await resources.addPasswordResource(
            PrivateResourceDraft.synthetic(alias: "nas.home"),
            password: Data("synthetic-password".utf8)
        )
        let authorizer = LifecyclePresenceAuthorizer(result: true)
        let lifecycle = ResourceLifecycleService(
            resources: resources,
            sshConfigResolver: FailingSSHConfigResolver(),
            userPresenceAuthorizer: authorizer,
            cooldown: 0
        )

        let disabled = try await lifecycle.mutate(
            action: .disable,
            alias: ResourceAlias("nas.home"),
            mutation: nil,
            now: Date(timeIntervalSince1970: 1_700_000_001)
        )
        let removed = try await lifecycle.mutate(
            action: .remove,
            alias: ResourceAlias("nas.home"),
            mutation: nil,
            now: Date(timeIntervalSince1970: 1_700_000_002)
        )

        #expect(disabled.state == .disabled)
        #expect(removed.state == .deleted)
        #expect(
            await authorizer.reasons == [
                "Disable SAFA resource nas.home",
                "Remove SAFA resource nas.home",
            ]
        )
    }

    @Test("OpenSSH effective config parser selects typed connection fields")
    func parseEffectiveSSHConfig() {
        let values = OpenSSHConfigResolver.parse(
            """
            host home-nas
            user operator
            hostname nas.internal
            port 2222
            identityfile ~/.ssh/id_ed25519
            """
        )

        #expect(values["hostname"] == "nas.internal")
        #expect(values["user"] == "operator")
        #expect(values["port"] == "2222")
    }
}

private struct StaticSSHConfigResolver: SSHConfigResolving {
    let value: ResolvedSSHConfig

    func resolve(alias _: ResourceAlias) async throws -> ResolvedSSHConfig { value }
}

private struct FailingSSHConfigResolver: SSHConfigResolving {
    func resolve(alias _: ResourceAlias) async throws -> ResolvedSSHConfig {
        throw SSHConfigResolverError.unavailable
    }
}

private actor LifecyclePresenceAuthorizer: UserPresenceAuthorizing {
    private(set) var reasons: [String] = []
    private let result: Bool

    init(result: Bool) { self.result = result }

    func authorize(reason: String) async -> Bool {
        reasons.append(reason)
        return result
    }
}
