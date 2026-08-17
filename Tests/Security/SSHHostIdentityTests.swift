import Foundation
import SAFADomain
import SAFASSH
import Testing

@Suite("Strict SSH host identity")
struct SSHHostIdentityTests {
    @Test("isolated SSH configuration pins a host and keeps the endpoint out of argv")
    func strictConfiguration() throws {
        let resource = SyntheticSSHResource.make(status: .trusted)
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("safa-ssh-test-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let prepared = try SSHConfigurationBuilder().prepare(
            resource: resource,
            command: try CommandSpec.exec(arguments: ["systemctl", "is-active", "example"]),
            credential: .password(
                childBinding: "one-shot-binding",
                askPassExecutable: URL(fileURLWithPath: "/usr/local/libexec/safa-askpass")
            ),
            rootDirectory: root,
            randomBytes: Data(repeating: 9, count: 20)
        )
        let config = try String(contentsOf: prepared.configURL, encoding: .utf8)
        let knownHosts = try String(contentsOf: prepared.knownHostsURL, encoding: .utf8)
        let argv = prepared.invocation.arguments.joined(separator: " ")

        #expect(config.contains("StrictHostKeyChecking yes"))
        #expect(config.contains("UserKnownHostsFile"))
        #expect(config.contains("GlobalKnownHostsFile /dev/null"))
        #expect(!config.contains("StrictHostKeyChecking no"))
        #expect(knownHosts.contains("ssh-ed25519"))
        #expect(!argv.contains("203.0.113.10"))
        #expect(!argv.contains("diagnostic-user"))
        #expect(!argv.contains("synthetic-password"))
    }

    @Test("a changed host key fails closed before process launch")
    func changedIdentity() throws {
        let resource = SyntheticSSHResource.make(status: .changed)
        #expect(throws: SSHConfigurationError.hostIdentityChanged) {
            try SSHConfigurationBuilder().prepare(
                resource: resource,
                command: CommandSpec.exec(arguments: ["true"]),
                credential: .none,
                rootDirectory: FileManager.default.temporaryDirectory
                    .appendingPathComponent(UUID().uuidString),
                randomBytes: Data(repeating: 1, count: 20)
            )
        }
    }

    @Test("OpenSSH setup uses only private config files and a pinned agent route")
    func openSSHCredentialConfiguration() throws {
        let resource = SyntheticSSHResource.make(status: .trusted)
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("safa-openssh-test-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let prepared = try SSHConfigurationBuilder().prepare(
            resource: resource,
            command: CommandSpec.exec(arguments: ["hostname"]),
            credential: .openSSH(
                identityFiles: [URL(fileURLWithPath: "/synthetic/id with space")],
                identityAgent: URL(fileURLWithPath: "/synthetic/agent.sock")
            ),
            rootDirectory: root,
            randomBytes: Data(repeating: 5, count: 20)
        )
        let config = try String(contentsOf: prepared.configURL, encoding: .utf8)
        let argv = prepared.invocation.arguments.joined(separator: " ")

        #expect(config.contains("IdentityFile \"/synthetic/id with space\""))
        #expect(config.contains("IdentityAgent \"/synthetic/agent.sock\""))
        #expect(config.contains("UseKeychain yes"))
        #expect(!argv.contains("id with space"))
        #expect(!argv.contains("agent.sock"))
    }

    @Test("Windows arguments are transported as data instead of shell syntax")
    func windowsArgumentsAreEncoded() throws {
        let resource = SyntheticSSHResource.make(status: .trusted, platform: .windows)
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("safa-windows-ssh-test-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let prepared = try SSHConfigurationBuilder().prepare(
            resource: resource,
            command: try CommandSpec.exec(arguments: ["diagnose.exe", "a&whoami", "$env:PATH"]),
            credential: .openSSH(
                identityFiles: [URL(fileURLWithPath: "/synthetic/id")],
                identityAgent: nil
            ),
            rootDirectory: root,
            randomBytes: Data(repeating: 6, count: 20)
        )
        let remoteCommand = try #require(prepared.invocation.arguments.last)

        #expect(remoteCommand.hasPrefix("powershell.exe -NoLogo -NoProfile -NonInteractive"))
        #expect(!remoteCommand.contains("a&whoami"))
        #expect(!remoteCommand.contains("$env:PATH"))
    }
}

enum SyntheticSSHResource {
    static func make(
        status: HostIdentityStatus,
        platform: HostPlatform = .linux
    ) -> Resource {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        return Resource(
            id: UUID(),
            alias: try! ResourceAlias("nas.home"),
            classification: .host(platform: platform),
            endpoint: ResourceEndpoint(host: "203.0.113.10", port: 2222),
            username: "diagnostic-user",
            securityDomain: "synthetic",
            hostIdentity: HostIdentity(
                algorithm: "ssh-ed25519",
                publicKey: Data(repeating: 7, count: 32),
                fingerprint: "SHA256:synthetic",
                verifiedAt: now,
                verificationMethod: .manual,
                status: status
            ),
            authRef: UUID(),
            revision: 1,
            state: .active,
            createdAt: now,
            updatedAt: now
        )
    }
}
