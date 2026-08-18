import Foundation
import SAFACrypto
import SAFADomain
import SAFAProtocol
import SAFATransport
import Testing

@testable import SAFATrustedSetup

@Suite("Trusted no-GUI resource enrollment")
struct TrustedResourceEnrollmentFlowTests {
    @Test("host scan keeps endpoint and port out of child process arguments")
    func hostScanArgumentBoundary() async throws {
        let runner = RecordingHostScanProcessRunner(
            expectedHost: "host.invalid",
            expectedPort: 2222
        )
        let identity = try await SystemSSHHostKeyScanner(runner: runner).scan(
            host: "host.invalid",
            port: 2222,
            now: Date(timeIntervalSince1970: 1_700_000_000)
        )

        let arguments = await runner.arguments
        #expect(arguments.first == "-F")
        #expect(arguments.suffix(2) == ["safa-setup-host", "true"])
        #expect(!arguments.contains("host.invalid"))
        #expect(!arguments.contains("2222"))
        #expect(await runner.configuration.contains("HostName host.invalid"))
        #expect(await runner.configuration.contains("Port 2222"))
        #expect(identity.algorithm == "ssh-ed25519")
    }

    @Test("password enrollment reaches the broker only through protected typed data")
    func passwordEnrollment() async throws {
        let secret = Data("synthetic-remote-password".utf8)
        let console = RecordingTrustedSetupConsole(
            secrets: [
                Data("host.invalid".utf8),
                Data("2222".utf8),
                Data("operator".utf8),
                Data("SHA256:trusted".utf8),
                secret,
            ]
        )
        let client = RecordingTrustedLocalSetupClient()
        let flow = TrustedSSHEnrollmentFlow(
            console: console,
            authorizer: StaticUserPresenceAuthorizer(approved: true),
            scanner: StaticSSHHostKeyScanner(
                identity: HostIdentity(
                    algorithm: "ssh-ed25519",
                    publicKey: Data([1, 2, 3]),
                    fingerprint: "SHA256:trusted",
                    verifiedAt: Date(timeIntervalSince1970: 1_700_000_000),
                    verificationMethod: .manual,
                    status: .trusted
                )
            ),
            client: client
        )

        try await flow.enroll(
            alias: ResourceAlias("nas.home"),
            resourceType: .hostLinux,
            now: Date(timeIntervalSince1970: 1_700_000_000)
        )

        let captured = try #require(await client.payload)
        #expect(captured.host == "host.invalid")
        #expect(captured.port == 2222)
        #expect(captured.username == "operator")
        #expect(captured.credential == secret)
        #expect(captured.credentialKind == CredentialKind.sshPassword.rawValue)
        #expect(captured.hostFingerprint == "SHA256:trusted")
        let expectedAlias = try ResourceAlias("nas.home")
        #expect(await client.beginAliases == [expectedAlias])
        #expect(!console.renderedText.contains("synthetic-remote-password"))
        #expect(!console.renderedText.contains("host.invalid"))
        #expect(!console.renderedText.contains("SHA256:trusted"))
    }

    @Test("denied user presence collects no protected value")
    func deniedPresence() async throws {
        let console = RecordingTrustedSetupConsole(secrets: [Data("unused".utf8)])
        let scanner = CountingSSHHostKeyScanner()
        let client = RecordingTrustedLocalSetupClient()
        let flow = TrustedSSHEnrollmentFlow(
            console: console,
            authorizer: StaticUserPresenceAuthorizer(approved: false),
            scanner: scanner,
            client: client
        )

        await #expect(throws: TrustedSSHEnrollmentError.authorizationDenied) {
            try await flow.enroll(alias: ResourceAlias("nas.home"), resourceType: .hostLinux)
        }
        #expect(console.secretReadCount == 0)
        #expect(await scanner.scanCount == 0)
        #expect(await client.beginAliases.isEmpty)
    }

    @Test("fingerprint mismatch sends neither password nor setup session")
    func fingerprintMismatch() async throws {
        let console = RecordingTrustedSetupConsole(
            secrets: [
                Data("host.invalid".utf8),
                Data("22".utf8),
                Data("operator".utf8),
                Data("SHA256:other".utf8),
                Data("must-not-be-read".utf8),
            ]
        )
        let client = RecordingTrustedLocalSetupClient()
        let flow = TrustedSSHEnrollmentFlow(
            console: console,
            authorizer: StaticUserPresenceAuthorizer(approved: true),
            scanner: StaticSSHHostKeyScanner(
                identity: HostIdentity(
                    algorithm: "ssh-ed25519",
                    publicKey: Data([1]),
                    fingerprint: "SHA256:trusted",
                    verifiedAt: .now,
                    verificationMethod: .manual,
                    status: .trusted
                )
            ),
            client: client
        )

        await #expect(throws: TrustedSSHEnrollmentError.hostFingerprintMismatch) {
            try await flow.enroll(alias: ResourceAlias("nas.home"), resourceType: .hostLinux)
        }
        #expect(console.secretReadCount == 4)
        #expect(await client.beginAliases.isEmpty)
    }

    @Test("the trusted helper accepts no endpoint username or password options")
    func noProtectedCLIOptions() throws {
        for arguments in [
            ["resource", "add", "nas.home", "--host", "host.invalid"],
            ["resource", "add", "nas.home", "--username", "operator"],
            ["resource", "add", "nas.home", "--password", "secret"],
        ] {
            #expect(throws: (any Error).self) {
                _ = try TrustedSetupCommand.parseAsRoot(arguments)
            }
        }
    }
}

private final class RecordingTrustedSetupConsole: TrustedSetupConsole, @unchecked Sendable {
    private let lock = NSLock()
    private var secrets: [Data]
    private(set) var renderedText = ""
    private(set) var secretReadCount = 0

    init(secrets: [Data]) {
        self.secrets = secrets
    }

    func write(_ text: String) throws {
        lock.withLock { renderedText += text }
    }

    func readSecret(prompt: String) throws -> Data {
        lock.withLock {
            renderedText += prompt
            secretReadCount += 1
            guard !secrets.isEmpty else { return Data() }
            return secrets.removeFirst()
        }
    }
}

private struct StaticUserPresenceAuthorizer: UserPresenceAuthorizing {
    let approved: Bool
    func authorize(reason _: String) async -> Bool { approved }
}

private struct StaticSSHHostKeyScanner: SSHHostKeyScanning {
    let identity: HostIdentity
    func scan(host _: String, port _: UInt16, now _: Date) async throws -> HostIdentity { identity }
}

private actor CountingSSHHostKeyScanner: SSHHostKeyScanning {
    private(set) var scanCount = 0
    func scan(host _: String, port _: UInt16, now _: Date) async throws -> HostIdentity {
        scanCount += 1
        throw TrustedSSHEnrollmentError.hostIdentityUnavailable
    }
}

private actor RecordingTrustedLocalSetupClient: TrustedLocalSetupClient {
    private(set) var beginAliases: [ResourceAlias] = []
    private(set) var payload: ProtectedResourceSetupPayload?

    func begin(alias: ResourceAlias) async throws -> UUID {
        beginAliases.append(alias)
        return UUID(uuidString: "00000000-0000-0000-0000-000000000001")!
    }

    func commit(sessionID _: UUID, payload: ProtectedResourceSetupPayload) async throws {
        self.payload = payload
    }
}

private actor RecordingHostScanProcessRunner: ProcessRunning {
    private let expectedHost: String
    private let expectedPort: UInt16
    private(set) var arguments: [String] = []
    private(set) var configuration = ""

    init(expectedHost: String, expectedPort: UInt16) {
        self.expectedHost = expectedHost
        self.expectedPort = expectedPort
    }

    func run(_ invocation: ProcessInvocation) async throws -> ProcessExecutionResult {
        arguments = invocation.arguments
        let configPath = try #require(invocation.arguments.dropFirst().first)
        configuration = try String(contentsOfFile: configPath, encoding: .utf8)
        #expect(configuration.contains("HostName \(expectedHost)"))
        #expect(configuration.contains("Port \(expectedPort)"))
        let knownHosts = URL(fileURLWithPath: configPath).deletingLastPathComponent()
            .appendingPathComponent("known_hosts")
        let publicKey = Data([1, 2, 3]).base64EncodedString()
        try "safa-setup-host ssh-ed25519 \(publicKey)\n".write(
            to: knownHosts,
            atomically: true,
            encoding: .utf8
        )
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        return ProcessExecutionResult(
            termination: .exit,
            exitCode: 255,
            stdout: Data(),
            stderr: Data("authentication intentionally unavailable".utf8),
            startedAt: now,
            finishedAt: now,
            stdoutTruncated: false,
            stderrTruncated: false
        )
    }
}
