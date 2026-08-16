import Foundation
import SAFADomain
import SAFATransport

public struct ResolvedSSHConfig: Equatable, Sendable {
    public let endpoint: ResourceEndpoint
    public let username: String
    public let identityFiles: [String]
    public let identityAgent: String?
    public let proxyJump: String?
    public let proxyCommand: String?
    public let userKnownHostsFiles: [String]
    public let hostKeyAlias: String?

    public init(
        endpoint: ResourceEndpoint,
        username: String,
        identityFiles: [String] = [],
        identityAgent: String? = nil,
        proxyJump: String? = nil,
        proxyCommand: String? = nil,
        userKnownHostsFiles: [String] = [],
        hostKeyAlias: String? = nil
    ) {
        self.endpoint = endpoint
        self.username = username
        self.identityFiles = identityFiles
        self.identityAgent = identityAgent
        self.proxyJump = proxyJump
        self.proxyCommand = proxyCommand
        self.userKnownHostsFiles = userKnownHostsFiles
        self.hostKeyAlias = hostKeyAlias
    }
}

public enum SSHConfigResolverError: Error, Equatable, Sendable {
    case aliasNotConfigured
    case unavailable
    case invalidConfiguration
    case timedOut
}

public protocol SSHConfigResolving: Sendable {
    func resolve(alias: ResourceAlias) async throws -> ResolvedSSHConfig
}

/// Resolves OpenSSH's effective configuration without connecting to a remote
/// host. The logical alias is validated before it becomes a process argument.
public struct OpenSSHConfigResolver: SSHConfigResolving {
    private let executableURL: URL
    private let runner: any ProcessRunning
    private let aliasChecker: any SSHConfigAliasChecking

    public init(
        executableURL: URL = URL(fileURLWithPath: "/usr/bin/ssh"),
        runner: any ProcessRunning = ProcessRunner()
    ) {
        self.executableURL = executableURL
        self.runner = runner
        aliasChecker = OpenSSHConfigAliasChecker()
    }

    init(
        executableURL: URL = URL(fileURLWithPath: "/usr/bin/ssh"),
        runner: any ProcessRunning,
        aliasChecker: any SSHConfigAliasChecking
    ) {
        self.executableURL = executableURL
        self.runner = runner
        self.aliasChecker = aliasChecker
    }

    public func resolve(alias: ResourceAlias) async throws -> ResolvedSSHConfig {
        guard await aliasChecker.contains(alias: alias) else {
            throw SSHConfigResolverError.aliasNotConfigured
        }
        var environment = ProcessInfo.processInfo.environment
        environment["LC_ALL"] = "C"
        let result: ProcessExecutionResult
        do {
            result = try await runner.run(
                ProcessInvocation(
                    executableURL: executableURL,
                    arguments: ["-G", alias.rawValue],
                    environment: environment,
                    timeoutSeconds: 3,
                    outputLimitBytes: 256 * 1_024
                )
            )
        } catch {
            throw SSHConfigResolverError.unavailable
        }
        guard result.termination != .timeout else {
            throw SSHConfigResolverError.timedOut
        }
        guard result.termination == .exit,
            result.exitCode == 0,
            !result.stdoutTruncated
        else {
            throw SSHConfigResolverError.invalidConfiguration
        }
        guard let text = String(data: result.stdout, encoding: .utf8)
        else {
            throw SSHConfigResolverError.invalidConfiguration
        }
        let allValues = Self.parseAll(text)
        let values = allValues.mapValues { $0.last ?? "" }
        guard
            let host = values["hostname"],
            !host.isEmpty,
            host.utf8.count <= 255,
            let username = values["user"],
            !username.isEmpty,
            username.utf8.count <= 255,
            let rawPort = values["port"],
            let port = UInt16(rawPort),
            !host.contains(where: \Character.isNewline),
            !username.contains(where: \Character.isNewline)
        else {
            throw SSHConfigResolverError.invalidConfiguration
        }
        return ResolvedSSHConfig(
            endpoint: ResourceEndpoint(scheme: "ssh", host: host, port: port),
            username: username,
            identityFiles: (allValues["identityfile"] ?? []).map(Self.expandPath),
            identityAgent: Self.identityAgent(values["identityagent"]),
            proxyJump: Self.optionalSetting(values["proxyjump"]),
            proxyCommand: Self.optionalSetting(values["proxycommand"]),
            userKnownHostsFiles: (allValues["userknownhostsfile"] ?? [])
                .flatMap { $0.split(whereSeparator: \Character.isWhitespace).map(String.init) }
                .map(Self.expandPath),
            hostKeyAlias: Self.optionalSetting(values["hostkeyalias"])
        )
    }

    static func parse(_ text: String) -> [String: String] {
        parseAll(text).mapValues { $0.last ?? "" }
    }

    static func parseAll(_ text: String) -> [String: [String]] {
        text.split(whereSeparator: \Character.isNewline).reduce(into: [:]) { values, line in
            let pieces = line.split(maxSplits: 1, whereSeparator: \Character.isWhitespace)
            guard pieces.count == 2 else { return }
            values[String(pieces[0]).lowercased(), default: []].append(String(pieces[1]))
        }
    }

    private static func optionalSetting(_ value: String?) -> String? {
        guard let value, !value.isEmpty, value.lowercased() != "none" else { return nil }
        return value
    }

    static func identityAgent(
        _ value: String?,
        environment: [String: String] = ProcessInfo.processInfo.environment
    ) -> String? {
        let socket = environment["SSH_AUTH_SOCK"]
        guard let setting = optionalSetting(value) else { return socket }
        if setting == "SSH_AUTH_SOCK" { return socket }
        return expandPath(setting)
    }

    private static func expandPath(_ value: String) -> String {
        NSString(string: value).expandingTildeInPath
    }
}
