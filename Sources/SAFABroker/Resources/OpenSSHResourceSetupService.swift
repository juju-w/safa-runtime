import CryptoKit
import Foundation
import SAFADomain
import SAFAProtocol
import SAFASSH
import SAFATransport

enum ResourceSetupError: Error, Equatable, Sendable {
    case resourceNotDraft
    case connectionChanged
    case unsupportedRoute
    case hostIdentityUnavailable
    case authenticationUnavailable
    case accountVerificationFailed
    case authenticationRejected
    case hostIdentityRejected
    case routeUnavailable
    case inventoryProbeFailed
    case platformMismatch
    case invalidCredentialLocator
}

struct OpenSSHCredentialLocatorV1: Codable, Equatable, Sendable {
    static let currentVersion: UInt = 1

    let version: UInt
    let identityFiles: [String]
    let identityAgent: String?

    init(identityFiles: [String], identityAgent: String?) throws {
        guard identityFiles.count <= 16,
            identityFiles.allSatisfy(Self.validPath),
            identityAgent.map(Self.validPath) ?? true,
            !identityFiles.isEmpty || identityAgent != nil
        else {
            throw ResourceSetupError.invalidCredentialLocator
        }
        version = Self.currentVersion
        self.identityFiles = identityFiles
        self.identityAgent = identityAgent
    }

    func credentialContext() throws -> SSHCredentialContext {
        guard version == Self.currentVersion else {
            throw ResourceSetupError.invalidCredentialLocator
        }
        return .openSSH(
            identityFiles: identityFiles.map { URL(fileURLWithPath: $0) },
            identityAgent: identityAgent.map { URL(fileURLWithPath: $0) }
        )
    }

    private static func validPath(_ path: String) -> Bool {
        path.hasPrefix("/")
            && path.utf8.count <= 1_024
            && !path.contains(where: \Character.isNewline)
    }
}

protocol ResourceSetupHandling: Sendable {
    func setup(
        alias: ResourceAlias,
        sourceSSHConfigAlias: ResourceAlias,
        now: Date
    ) async throws -> Resource
}

protocol OpenSSHKnownHostResolving: Sendable {
    func resolve(config: ResolvedSSHConfig, now: Date) async throws -> HostIdentity
}

protocol OpenSSHCredentialSourceResolving: Sendable {
    func resolve(config: ResolvedSSHConfig) async throws -> OpenSSHCredentialLocatorV1
}

protocol OpenSSHSetupVerifying: Sendable {
    func verify(
        resource: Resource,
        locator: OpenSSHCredentialLocatorV1,
        observedAt: Date
    ) async throws -> HostInventorySnapshot
}

struct OpenSSHResourceSetupService: ResourceSetupHandling {
    private let resources: ResourceService
    private let sshConfigResolver: any SSHConfigResolving
    private let knownHostResolver: any OpenSSHKnownHostResolving
    private let credentialSourceResolver: any OpenSSHCredentialSourceResolving
    private let verifier: any OpenSSHSetupVerifying

    init(
        resources: ResourceService,
        sshConfigResolver: any SSHConfigResolving = OpenSSHConfigResolver(),
        knownHostResolver: any OpenSSHKnownHostResolving = OpenSSHKnownHostResolver(),
        credentialSourceResolver: any OpenSSHCredentialSourceResolving =
            LocalOpenSSHCredentialSourceResolver(),
        verifier: any OpenSSHSetupVerifying
    ) {
        self.resources = resources
        self.sshConfigResolver = sshConfigResolver
        self.knownHostResolver = knownHostResolver
        self.credentialSourceResolver = credentialSourceResolver
        self.verifier = verifier
    }

    func setup(
        alias: ResourceAlias,
        sourceSSHConfigAlias: ResourceAlias,
        now: Date
    ) async throws -> Resource {
        let existing = try await resources.resource(alias: alias)
        guard existing.state == .draft, existing.hostIdentity == nil, existing.authRef == nil else {
            throw ResourceSetupError.resourceNotDraft
        }
        let config = try await sshConfigResolver.resolve(alias: sourceSSHConfigAlias)
        guard existing.endpoint == config.endpoint, existing.username == config.username else {
            throw ResourceSetupError.connectionChanged
        }
        guard config.proxyJump == nil, config.proxyCommand == nil else {
            throw ResourceSetupError.unsupportedRoute
        }

        let identity = try await knownHostResolver.resolve(config: config, now: now)
        let locator = try await credentialSourceResolver.resolve(config: config)
        var candidate = existing
        candidate.hostIdentity = identity
        candidate.state = .active
        let inventory = try await verifier.verify(
            resource: candidate,
            locator: locator,
            observedAt: now
        )

        return try await resources.activateDiscoveredResource(
            alias: alias,
            expectedRevision: existing.revision,
            hostIdentity: identity,
            credentialLocator: try CanonicalCodec.encode(locator),
            inventory: inventory,
            now: now
        )
    }
}

struct OpenSSHKnownHostResolver: OpenSSHKnownHostResolving {
    private let executableURL: URL
    private let runner: any ProcessRunning

    init(
        executableURL: URL = URL(fileURLWithPath: "/usr/bin/ssh-keygen"),
        runner: any ProcessRunning = ProcessRunner()
    ) {
        self.executableURL = executableURL
        self.runner = runner
    }

    func resolve(config: ResolvedSSHConfig, now: Date) async throws -> HostIdentity {
        let lookup = config.hostKeyAlias ?? Self.lookupHost(config.endpoint)
        let paths =
            config.userKnownHostsFiles.isEmpty
            ? [
                FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(
                    ".ssh/known_hosts"
                ).path
            ]
            : config.userKnownHostsFiles

        for path in paths.prefix(8) where Self.validPath(path) {
            let result: ProcessExecutionResult
            do {
                result = try await runner.run(
                    ProcessInvocation(
                        executableURL: executableURL,
                        arguments: ["-F", lookup, "-f", path],
                        environment: ["LC_ALL": "C", "LANG": "C"],
                        timeoutSeconds: 3,
                        outputLimitBytes: 256 * 1_024
                    )
                )
            } catch {
                continue
            }
            guard result.termination == .exit, result.exitCode == 0,
                !result.stdoutTruncated,
                let text = String(data: result.stdout, encoding: .utf8),
                let key = Self.preferredKey(in: text)
            else {
                continue
            }
            return HostIdentity(
                algorithm: key.algorithm,
                publicKey: key.publicKey,
                fingerprint: Self.fingerprint(key.publicKey),
                verifiedAt: now,
                verificationMethod: .trustedImport,
                status: .trusted
            )
        }
        throw ResourceSetupError.hostIdentityUnavailable
    }

    static func preferredKey(in text: String) -> (algorithm: String, publicKey: Data)? {
        let priority = ["ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"]
        let keys = text.split(whereSeparator: \Character.isNewline).compactMap {
            line -> (
                String, Data
            )? in
            guard !line.hasPrefix("#"), !line.hasPrefix("@") else { return nil }
            let fields = line.split(whereSeparator: \Character.isWhitespace)
            guard fields.count >= 3,
                let key = Data(base64Encoded: String(fields[2])),
                !key.isEmpty
            else {
                return nil
            }
            return (String(fields[1]), key)
        }
        for algorithm in priority {
            if let key = keys.first(where: { $0.0 == algorithm }) {
                return (key.0, key.1)
            }
        }
        return nil
    }

    private static func lookupHost(_ endpoint: ResourceEndpoint) -> String {
        endpoint.port == 22 ? endpoint.host : "[\(endpoint.host)]:\(endpoint.port)"
    }

    private static func fingerprint(_ publicKey: Data) -> String {
        let value = Data(SHA256.hash(data: publicKey)).base64EncodedString()
            .trimmingCharacters(in: CharacterSet(charactersIn: "="))
        return "SHA256:\(value)"
    }

    private static func validPath(_ path: String) -> Bool {
        path.hasPrefix("/")
            && path.utf8.count <= 1_024
            && !path.contains(where: \Character.isNewline)
    }
}

struct LocalOpenSSHCredentialSourceResolver: OpenSSHCredentialSourceResolving {
    func resolve(config: ResolvedSSHConfig) async throws -> OpenSSHCredentialLocatorV1 {
        let files = config.identityFiles
        let agent = config.identityAgent
        let available = await Task.detached(priority: .utility) {
            let fileManager = FileManager.default
            let identityFiles = files.filter { path in
                guard path.hasPrefix("/"), path.utf8.count <= 1_024 else { return false }
                var isDirectory: ObjCBool = false
                return fileManager.fileExists(atPath: path, isDirectory: &isDirectory)
                    && !isDirectory.boolValue
            }
            let identityAgent = agent.flatMap { path -> String? in
                guard path.hasPrefix("/"), path.utf8.count <= 1_024,
                    fileManager.fileExists(atPath: path)
                else {
                    return nil
                }
                return path
            }
            return (identityFiles, identityAgent)
        }.value
        guard !available.0.isEmpty || available.1 != nil else {
            throw ResourceSetupError.authenticationUnavailable
        }
        return try OpenSSHCredentialLocatorV1(
            identityFiles: Array(available.0.prefix(16)),
            identityAgent: available.1
        )
    }
}

struct OpenSSHSetupVerifier: OpenSSHSetupVerifying {
    private let transport: SSHTransport
    private let workingDirectory: URL
    private let inventoryProbe: any OpenSSHHostInventoryProbing

    init(
        transport: SSHTransport = SSHTransport(),
        workingDirectory: URL,
        inventoryProbe: (any OpenSSHHostInventoryProbing)? = nil
    ) {
        self.transport = transport
        self.workingDirectory = workingDirectory
        self.inventoryProbe =
            inventoryProbe
            ?? OpenSSHHostInventoryProbe(
                transport: transport,
                workingDirectory: workingDirectory
            )
    }

    func verify(
        resource: Resource,
        locator: OpenSSHCredentialLocatorV1,
        observedAt: Date
    ) async throws -> HostInventorySnapshot {
        let credential = try locator.credentialContext()
        let checks: [([String], @Sendable (String) -> Bool)]
        if resource.resolvedResourceType == .hostWindows {
            checks = [
                (["whoami"], { Self.windowsAccount($0, matches: resource.username) })
            ]
        } else {
            checks = [
                (["uname", "-n"], { !$0.isEmpty }),
                (["id", "-un"], { $0 == resource.username }),
            ]
        }
        for (arguments, accepts) in checks {
            let result: ProcessExecutionResult
            do {
                result = try await transport.execute(
                    resource: resource,
                    command: CommandSpec.exec(
                        arguments: arguments,
                        timeoutSeconds: 10,
                        outputLimitBytes: 4_096
                    ),
                    credential: credential,
                    workingRoot: workingDirectory.appendingPathComponent(
                        "setup-\(UUID().uuidString)",
                        isDirectory: true
                    )
                )
            } catch {
                throw ResourceSetupError.accountVerificationFailed
            }
            let output = String(decoding: result.stdout, as: UTF8.self)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            if result.termination == .exit, result.exitCode == 255 {
                throw Self.classifySSHFailure(result.stderr)
            }
            guard result.termination == .exit, result.exitCode == 0,
                !result.stdoutTruncated, accepts(output)
            else {
                throw ResourceSetupError.accountVerificationFailed
            }
        }
        return try await inventoryProbe.probe(
            resource: resource,
            credential: locator.credentialContext(),
            observedAt: observedAt,
            didLaunch: nil
        )
    }

    static func classifySSHFailure(_ stderr: Data) -> ResourceSetupError {
        let message = String(decoding: stderr.prefix(16 * 1_024), as: UTF8.self).lowercased()
        if message.contains("host key verification failed")
            || message.contains("remote host identification has changed")
        {
            return .hostIdentityRejected
        }
        if message.contains("permission denied")
            || message.contains("no mutual signature")
            || message.contains("not accessible: no such file")
        {
            return .authenticationRejected
        }
        if message.contains("connection refused")
            || message.contains("operation timed out")
            || message.contains("connection timed out")
            || message.contains("no route to host")
            || message.contains("connection reset")
            || message.contains("connection closed")
            || message.contains("could not resolve hostname")
        {
            return .routeUnavailable
        }
        return .accountVerificationFailed
    }

    private static func windowsAccount(_ output: String, matches expected: String?) -> Bool {
        guard let expected, !expected.isEmpty else { return false }
        let account = output.lowercased()
            .split(whereSeparator: { $0 == "\\" || $0 == "/" })
            .last
            .map(String.init)
        return account == expected.lowercased()
    }
}
