import Foundation
import SAFADomain
import SAFATransport

public struct ResolvedSSHConfig: Equatable, Sendable {
    public let endpoint: ResourceEndpoint
    public let username: String

    public init(endpoint: ResourceEndpoint, username: String) {
        self.endpoint = endpoint
        self.username = username
    }
}

public enum SSHConfigResolverError: Error, Equatable, Sendable {
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

    public init(
        executableURL: URL = URL(fileURLWithPath: "/usr/bin/ssh"),
        runner: any ProcessRunning = ProcessRunner()
    ) {
        self.executableURL = executableURL
        self.runner = runner
    }

    public func resolve(alias: ResourceAlias) async throws -> ResolvedSSHConfig {
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
        let values = Self.parse(text)
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
            username: username
        )
    }

    static func parse(_ text: String) -> [String: String] {
        text.split(whereSeparator: \Character.isNewline).reduce(into: [:]) { values, line in
            let pieces = line.split(maxSplits: 1, whereSeparator: \Character.isWhitespace)
            guard pieces.count == 2 else { return }
            values[String(pieces[0]).lowercased()] = String(pieces[1])
        }
    }
}
