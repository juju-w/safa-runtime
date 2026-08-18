import CryptoKit
import Foundation
import SAFADomain
import SAFATransport

protocol SSHHostKeyScanning: Sendable {
    func scan(host: String, port: UInt16, now: Date) async throws -> HostIdentity
}

struct SystemSSHHostKeyScanner: SSHHostKeyScanning {
    private let runner: any ProcessRunning

    init(runner: any ProcessRunning = ProcessRunner()) {
        self.runner = runner
    }

    func scan(host: String, port: UInt16, now: Date) async throws -> HostIdentity {
        guard TrustedSSHEnrollmentInput.validHost(host) else {
            throw TrustedSSHEnrollmentError.invalidHost
        }
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(
            "safa-trusted-host-scan-\(UUID().uuidString)",
            isDirectory: true
        )
        let config = directory.appendingPathComponent("ssh_config")
        let knownHosts = directory.appendingPathComponent("known_hosts")
        defer { try? FileManager.default.removeItem(at: directory) }
        do {
            try FileManager.default.createDirectory(
                at: directory,
                withIntermediateDirectories: false,
                attributes: [.posixPermissions: 0o700]
            )
            guard
                FileManager.default.createFile(
                    atPath: config.path,
                    contents: Data(
                        Self.configuration(host: host, port: port, knownHosts: knownHosts).utf8),
                    attributes: [.posixPermissions: 0o600]
                ),
                FileManager.default.createFile(
                    atPath: knownHosts.path,
                    contents: Data(),
                    attributes: [.posixPermissions: 0o600]
                )
            else {
                throw TrustedSSHEnrollmentError.hostIdentityUnavailable
            }
            let result = try await runner.run(
                ProcessInvocation(
                    executableURL: URL(fileURLWithPath: "/usr/bin/ssh"),
                    arguments: ["-F", config.path, "safa-setup-host", "true"],
                    environment: ["LC_ALL": "C", "LANG": "C"],
                    timeoutSeconds: 12,
                    outputLimitBytes: 32 * 1_024
                )
            )
            guard result.termination == .exit, result.exitCode == 0 || result.exitCode == 255 else {
                throw TrustedSSHEnrollmentError.hostIdentityUnavailable
            }
        } catch {
            throw TrustedSSHEnrollmentError.hostIdentityUnavailable
        }
        guard let data = try? Data(contentsOf: knownHosts), let key = Self.preferredKey(in: data)
        else {
            throw TrustedSSHEnrollmentError.hostIdentityUnavailable
        }
        return HostIdentity(
            algorithm: key.algorithm,
            publicKey: key.publicKey,
            fingerprint: Self.fingerprint(key.publicKey),
            verifiedAt: now,
            verificationMethod: .manual,
            status: .trusted
        )
    }

    private static func configuration(host: String, port: UInt16, knownHosts: URL) -> String {
        """
        Host safa-setup-host
          HostName \(host)
          Port \(port)
          User safa-setup-probe
          BatchMode yes
          PasswordAuthentication no
          KbdInteractiveAuthentication no
          PubkeyAuthentication no
          HostbasedAuthentication no
          GSSAPIAuthentication no
          IdentitiesOnly yes
          IdentityFile none
          IdentityAgent none
          ProxyCommand none
          ProxyJump none
          PermitLocalCommand no
          LocalCommand none
          RemoteCommand none
          ClearAllForwardings yes
          ForwardAgent no
          StrictHostKeyChecking accept-new
          UserKnownHostsFile \(quoted(knownHosts.path))
          GlobalKnownHostsFile /dev/null
          HashKnownHosts no
          CheckHostIP no
          UpdateHostKeys no
          VerifyHostKeyDNS no
          CanonicalizeHostname no
          ConnectionAttempts 1
          ConnectTimeout 8
          LogLevel ERROR
        """
    }

    private static func quoted(_ value: String) -> String {
        "\""
            + value.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }

    static func preferredKey(in data: Data) -> (algorithm: String, publicKey: Data)? {
        guard let text = String(data: data, encoding: .utf8) else { return nil }
        let supported = ["ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"]
        let keys = text.split(whereSeparator: \Character.isNewline).compactMap {
            line -> (String, Data)? in
            guard !line.hasPrefix("#") else { return nil }
            let fields = line.split(whereSeparator: \Character.isWhitespace)
            guard fields.count >= 3,
                supported.contains(String(fields[1])),
                let publicKey = Data(base64Encoded: String(fields[2])),
                !publicKey.isEmpty
            else {
                return nil
            }
            return (String(fields[1]), publicKey)
        }
        for algorithm in supported {
            if let match = keys.first(where: { $0.0 == algorithm }) { return match }
        }
        return nil
    }

    private static func fingerprint(_ publicKey: Data) -> String {
        let value = Data(SHA256.hash(data: publicKey)).base64EncodedString()
            .trimmingCharacters(in: CharacterSet(charactersIn: "="))
        return "SHA256:\(value)"
    }
}
