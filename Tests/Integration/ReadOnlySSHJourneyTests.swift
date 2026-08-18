import Foundation
import SAFACrypto
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
        let topology = TopologyGraphService(
            vault: vault,
            userPresenceAuthorizer: JourneyPresenceAuthorizer(),
            cooldown: 0
        )
        let handler = MVPBrokerHandler(
            vault: vault,
            passwordStore: credentials,
            bindingStore: ChildCredentialBindingStore(),
            transport: SSHTransport(runner: runner),
            audit: audit,
            topologyReachabilityRecorder: topology,
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
        let graph = try #require(await vault.readDocument().topologyGraph)
        let runtime = try ResourceAlias("runtime.local")
        let observation = try #require(
            graph.edges.first(where: {
                $0.fromNodeID == graph.nodes.first(where: { $0.alias == runtime })?.id
                    && $0.relation == .canReach
                    && $0.toNodeID == resource.id
            }))
        #expect(observation.verification == .verified)
        #expect(observation.observedAt == Date(timeIntervalSince1970: 1_700_000_001))
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

    @Test("alternate aliases record reachability against the canonical resource")
    func alternateAliasRecordsCanonicalReachability() async throws {
        let alternate = try ResourceAlias("nas.short")
        let resource = JourneyResourceFactory.active(
            alias: "nas.home",
            alternateAliases: [alternate]
        )
        let locator = try OpenSSHCredentialLocatorV1(
            identityFiles: ["/synthetic/id_ed25519"],
            identityAgent: nil
        )
        let finishedAt = Date(timeIntervalSince1970: 1_700_000_001)
        let runner = FakeProcessRunner(
            result: ProcessExecutionResult(
                termination: .exit,
                exitCode: 0,
                stdout: Data("synthetic-host\n".utf8),
                stderr: Data(),
                startedAt: Date(timeIntervalSince1970: 1_700_000_000),
                finishedAt: finishedAt,
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
        let recorder = JourneyReachabilityRecorder()
        let handler = MVPBrokerHandler(
            vault: vault,
            passwordStore: InMemoryPasswordSecretStore(),
            bindingStore: ChildCredentialBindingStore(),
            transport: SSHTransport(runner: runner),
            topologyReachabilityRecorder: recorder,
            askPassExecutable: URL(fileURLWithPath: "/usr/local/libexec/safa-askpass"),
            workingDirectory: FileManager.default.temporaryDirectory
                .appendingPathComponent("safa-alias-journey-\(UUID().uuidString)")
        )

        _ = await handler.handle(
            .submitExecution(
                resourceAlias: alternate,
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

        #expect(await recorder.targets == [resource.alias])
    }

    @Test("OpenSSH transport failure never becomes verified reachability")
    func transportFailureDoesNotRecordReachability() async throws {
        let resource = JourneyResourceFactory.active(alias: "nas.unreachable")
        let locator = try OpenSSHCredentialLocatorV1(
            identityFiles: ["/synthetic/id_ed25519"],
            identityAgent: nil
        )
        let runner = FakeProcessRunner(
            result: ProcessExecutionResult(
                termination: .exit,
                exitCode: 255,
                stdout: Data(),
                stderr: Data("connection refused\n".utf8),
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
        let recorder = JourneyReachabilityRecorder()
        let handler = MVPBrokerHandler(
            vault: vault,
            passwordStore: InMemoryPasswordSecretStore(),
            bindingStore: ChildCredentialBindingStore(),
            transport: SSHTransport(runner: runner),
            topologyReachabilityRecorder: recorder,
            askPassExecutable: URL(fileURLWithPath: "/usr/local/libexec/safa-askpass"),
            workingDirectory: FileManager.default.temporaryDirectory
                .appendingPathComponent("safa-failed-journey-\(UUID().uuidString)")
        )

        _ = await handler.handle(
            .submitExecution(
                resourceAlias: resource.alias,
                command: try CommandSpec.exec(arguments: ["uptime"]),
                privilege: .user,
                intent: "Check an unreachable synthetic host",
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

        #expect(await recorder.targets.isEmpty)
    }
}

private actor JourneyPresenceAuthorizer: UserPresenceAuthorizing {
    func authorize(reason _: String) -> Bool { false }
}

private actor JourneyReachabilityRecorder: TopologyReachabilityRecording {
    private(set) var targets: [ResourceAlias] = []

    func recordSuccessfulReachability(to target: ResourceAlias, observedAt _: Date) {
        targets.append(target)
    }
}

enum JourneyResourceFactory {
    static func active(
        alias: String,
        alternateAliases: [ResourceAlias] = []
    ) -> Resource {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        return Resource(
            id: UUID(),
            alias: try! ResourceAlias(alias),
            alternateAliases: alternateAliases,
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
