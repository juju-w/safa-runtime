import Foundation
import SAFADomain
import SAFAProtocol
import SAFASSH
import SAFATestFixtures
import SAFATransport
import Testing

@testable import SAFABroker

@Suite("Read-only synthetic SSH journey")
struct ReadOnlySSHJourneyTests {
    @Test("nas.home service status completes without Agent-visible infrastructure or secrets")
    func syntheticJourney() async throws {
        let resource = JourneyResourceFactory.active(alias: "nas.home")
        let runner = FakeProcessRunner(
            result: ProcessExecutionResult(
                termination: .exit,
                exitCode: 0,
                stdout: Data("active\nsynthetic-password\n".utf8),
                stderr: Data(),
                startedAt: Date(timeIntervalSince1970: 1_700_000_000),
                finishedAt: Date(timeIntervalSince1970: 1_700_000_001),
                stdoutTruncated: false,
                stderrTruncated: false
            )
        )
        let vault = InMemoryVaultDocumentStore(
            document: VaultDocument(
                schemaVersion: 1,
                resources: [resource],
                credentialReferences: [
                    CredentialReference(
                        id: resource.authRef!,
                        kind: .sshPassword,
                        storageLocator: Data("synthetic-locator".utf8),
                        securityDomains: ["synthetic"],
                        accessClass: .automaticWithinPolicy,
                        health: .ready,
                        createdAt: Date(timeIntervalSince1970: 1_700_000_000)
                    )
                ]
            )
        )
        let credentials = InMemoryPasswordSecretStore()
        await credentials.storeSecret(
            Data("synthetic-password".utf8),
            id: resource.authRef!
        )
        let audit = AuditService()
        let handler = MVPBrokerHandler(
            vault: vault,
            passwordStore: credentials,
            bindingStore: ChildCredentialBindingStore(),
            transport: SSHTransport(runner: runner),
            audit: audit,
            askPassExecutable: URL(fileURLWithPath: "/usr/local/libexec/safa-askpass"),
            workingDirectory: FileManager.default.temporaryDirectory
                .appendingPathComponent("safa-journey-\(UUID().uuidString)")
        )
        let reply = await handler.handle(
            .submitExecution(
                resourceAlias: resource.alias,
                command: try CommandSpec.exec(
                    arguments: ["systemctl", "is-active", "example"]
                ),
                privilege: .user,
                intent: "Check the synthetic service",
                expectedEffect: nil,
                rollback: nil
            ),
            caller: CallerIdentity(
                signingIdentifier: "dev.safa.cli",
                teamIdentifier: "TESTTEAM1",
                effectiveUserID: 501,
                auditSessionID: 77
            ),
            messageID: UUID()
        )

        let invocation = try #require(await runner.lastInvocation())
        let agentSurface = [
            resource.alias.rawValue,
            String(decoding: try CanonicalCodec.encode(reply), as: UTF8.self),
            await audit.exportSanitized(),
            invocation.arguments.joined(separator: " "),
            invocation.environment.description,
        ].joined(separator: "\n")
        #expect(agentSurface.contains("nas.home"))
        #expect(agentSurface.contains("active"))
        #expect(agentSurface.contains("[REDACTED]"))
        #expect(!agentSurface.contains("203.0.113.10"))
        #expect(!agentSurface.contains("diagnostic-user"))
        #expect(!agentSurface.contains("synthetic-password"))
    }

    @Test("an imported OpenSSH identity executes without a password binding")
    func openSSHJourney() async throws {
        let resource = JourneyResourceFactory.active(alias: "nas.home")
        let locator = try OpenSSHCredentialLocatorV1(
            identityFiles: ["/synthetic/id_ed25519"],
            identityAgent: nil
        )
        let runner = FakeProcessRunner(
            result: ProcessExecutionResult(
                termination: .exit,
                exitCode: 0,
                stdout: Data("synthetic-host\n".utf8),
                stderr: Data(),
                startedAt: Date(timeIntervalSince1970: 1_700_000_000),
                finishedAt: Date(timeIntervalSince1970: 1_700_000_001),
                stdoutTruncated: false,
                stderrTruncated: false
            )
        )
        let vault = InMemoryVaultDocumentStore(
            document: VaultDocument(
                schemaVersion: 1,
                resources: [resource],
                credentialReferences: [
                    CredentialReference(
                        id: resource.authRef!,
                        kind: .sshOpenSSH,
                        storageLocator: try CanonicalCodec.encode(locator),
                        securityDomains: ["synthetic"],
                        accessClass: .automaticWithinPolicy,
                        health: .ready,
                        createdAt: Date(timeIntervalSince1970: 1_700_000_000)
                    )
                ]
            )
        )
        let handler = MVPBrokerHandler(
            vault: vault,
            passwordStore: InMemoryPasswordSecretStore(),
            bindingStore: ChildCredentialBindingStore(),
            transport: SSHTransport(runner: runner),
            askPassExecutable: URL(fileURLWithPath: "/usr/local/libexec/safa-askpass"),
            workingDirectory: FileManager.default.temporaryDirectory
                .appendingPathComponent("safa-openssh-journey-\(UUID().uuidString)")
        )

        let reply = await handler.handle(
            .submitExecution(
                resourceAlias: resource.alias,
                command: try CommandSpec.exec(arguments: ["hostname"]),
                privilege: .user,
                intent: "Check the synthetic hostname",
                expectedEffect: nil,
                rollback: nil
            ),
            caller: CallerIdentity(
                signingIdentifier: "dev.safa.cli",
                teamIdentifier: "TESTTEAM1",
                effectiveUserID: 501,
                auditSessionID: 77
            ),
            messageID: UUID()
        )

        #expect(reply.status == .completed)
        #expect(await runner.lastInvocation() != nil)
    }
}

enum JourneyResourceFactory {
    static func active(alias: String) -> Resource {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        return Resource(
            id: UUID(),
            alias: try! ResourceAlias(alias),
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
            ),
            authRef: UUID(),
            revision: 1,
            state: .active,
            createdAt: now,
            updatedAt: now
        )
    }
}
