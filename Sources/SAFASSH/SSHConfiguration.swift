import CryptoKit
import Foundation
import SAFADomain
import SAFATransport
import Security

public enum SSHCredentialContext: Equatable, Sendable {
    case none
    case password(childBinding: String, askPassExecutable: URL)
    case secureEnclave(agentSocket: URL)
}

public enum SSHConfigurationError: Error, Equatable, Sendable {
    case resourceInactive
    case missingHostIdentity
    case hostIdentityChanged
    case invalidHostIdentity
    case invalidRandomness
    case unsupportedCommand
    case persistenceFailed
}

public struct PreparedSSHExecution: Sendable {
    public let invocation: ProcessInvocation
    public let rootDirectory: URL
    public let configURL: URL
    public let knownHostsURL: URL
    public let opaqueHostAlias: String

    public init(
        invocation: ProcessInvocation,
        rootDirectory: URL,
        configURL: URL,
        knownHostsURL: URL,
        opaqueHostAlias: String
    ) {
        self.invocation = invocation
        self.rootDirectory = rootDirectory
        self.configURL = configURL
        self.knownHostsURL = knownHostsURL
        self.opaqueHostAlias = opaqueHostAlias
    }
}

public struct SSHConfigurationBuilder: Sendable {
    public init() {}

    public func prepare(
        resource: Resource,
        command: CommandSpec,
        credential: SSHCredentialContext,
        rootDirectory: URL,
        randomBytes: Data? = nil
    ) throws -> PreparedSSHExecution {
        guard resource.state == .active else { throw SSHConfigurationError.resourceInactive }
        guard let identity = resource.hostIdentity else {
            throw SSHConfigurationError.missingHostIdentity
        }
        guard identity.status == .trusted else {
            if identity.status == .changed { throw SSHConfigurationError.hostIdentityChanged }
            throw SSHConfigurationError.invalidHostIdentity
        }
        guard command.mode == .exec, let commandArguments = command.arguments else {
            throw SSHConfigurationError.unsupportedCommand
        }

        let salt = try randomBytes ?? secureRandom(count: 20)
        guard salt.count >= 20 else { throw SSHConfigurationError.invalidRandomness }
        let opaqueAlias = "safa-" + UUID().uuidString.lowercased()
        let configURL = rootDirectory.appendingPathComponent("ssh_config")
        let knownHostsURL = rootDirectory.appendingPathComponent("known_hosts")

        do {
            try FileManager.default.createDirectory(
                at: rootDirectory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
            let knownHostName =
                resource.endpoint.port == 22
                ? resource.endpoint.host
                : "[\(resource.endpoint.host)]:\(resource.endpoint.port)"
            let hashedHost = hashKnownHost(knownHostName, salt: salt.prefix(20))
            let keyPayload = identity.publicKey.base64EncodedString()
            let knownHosts = "\(hashedHost) \(identity.algorithm) \(keyPayload)\n"
            try writePrivate(Data(knownHosts.utf8), to: knownHostsURL)

            var config = """
                Host \(opaqueAlias)
                    HostName \(resource.endpoint.host)
                    Port \(resource.endpoint.port)
                    User \(resource.username)
                    CanonicalizeHostname no
                    CheckHostIP no
                    ClearAllForwardings yes
                    GlobalKnownHostsFile /dev/null
                    HashKnownHosts yes
                    IdentitiesOnly yes
                    LogLevel ERROR
                    StrictHostKeyChecking yes
                    UserKnownHostsFile \(knownHostsURL.path)

                """
            var environment = ["LC_ALL": "C", "LANG": "C"]
            switch credential {
            case .none:
                config +=
                    "    BatchMode yes\n    PasswordAuthentication no\n    PubkeyAuthentication no\n"
            case let .password(childBinding, askPassExecutable):
                config +=
                    "    BatchMode no\n    KbdInteractiveAuthentication no\n    NumberOfPasswordPrompts 1\n    PasswordAuthentication yes\n    PreferredAuthentications password\n    PubkeyAuthentication no\n    StdinNull yes\n"
                environment["SSH_ASKPASS"] = askPassExecutable.path
                environment["SSH_ASKPASS_REQUIRE"] = "force"
                environment["DISPLAY"] = "SAFA"
                environment["SAFA_CHILD_BINDING"] = childBinding
            case let .secureEnclave(agentSocket):
                config +=
                    "    BatchMode yes\n    PasswordAuthentication no\n    PubkeyAuthentication yes\n    IdentityAgent \(agentSocket.path)\n"
            }
            try writePrivate(Data(config.utf8), to: configURL)

            let remoteCommand = commandArguments.map(Self.posixQuote).joined(separator: " ")
            let invocation = ProcessInvocation(
                executableURL: URL(fileURLWithPath: "/usr/bin/ssh"),
                arguments: ["-F", configURL.path, "-T", "--", opaqueAlias, remoteCommand],
                environment: environment,
                timeoutSeconds: command.timeoutSeconds,
                outputLimitBytes: command.outputLimitBytes
            )
            return PreparedSSHExecution(
                invocation: invocation,
                rootDirectory: rootDirectory,
                configURL: configURL,
                knownHostsURL: knownHostsURL,
                opaqueHostAlias: opaqueAlias
            )
        } catch let error as SSHConfigurationError {
            throw error
        } catch {
            throw SSHConfigurationError.persistenceFailed
        }
    }

    public static func posixQuote(_ argument: String) -> String {
        if argument.isEmpty { return "''" }
        return "'" + argument.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    private func hashKnownHost(_ host: String, salt: Data.SubSequence) -> String {
        let saltData = Data(salt)
        let digest = HMAC<Insecure.SHA1>.authenticationCode(
            for: Data(host.utf8),
            using: SymmetricKey(data: saltData)
        )
        return "|1|\(saltData.base64EncodedString())|\(Data(digest).base64EncodedString())"
    }

    private func secureRandom(count: Int) throws -> Data {
        var bytes = Data(repeating: 0, count: count)
        let status = bytes.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!)
        }
        guard status == errSecSuccess else { throw SSHConfigurationError.invalidRandomness }
        return bytes
    }

    private func writePrivate(_ data: Data, to url: URL) throws {
        try data.write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}
