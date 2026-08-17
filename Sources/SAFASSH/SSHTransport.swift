import Foundation
import SAFADomain
import SAFATransport

public struct SSHTransport: Sendable {
    private let runner: any ProcessRunning
    private let builder: SSHConfigurationBuilder

    public init(
        runner: any ProcessRunning = ProcessRunner(),
        builder: SSHConfigurationBuilder = SSHConfigurationBuilder()
    ) {
        self.runner = runner
        self.builder = builder
    }

    public func execute(
        resource: Resource,
        command: CommandSpec,
        credential: SSHCredentialContext,
        workingRoot: URL,
        didLaunch: (@Sendable (Int32) -> Void)? = nil
    ) async throws -> ProcessExecutionResult {
        let prepared = try builder.prepare(
            resource: resource,
            command: command,
            credential: credential,
            rootDirectory: workingRoot
        )
        defer { try? FileManager.default.removeItem(at: prepared.rootDirectory) }
        let invocation = didLaunch.map(prepared.invocation.withLaunchHandler) ?? prepared.invocation
        return try await runner.run(invocation)
    }

    public func executeWindowsPowerShell(
        resource: Resource,
        encodedScript: String,
        credential: SSHCredentialContext,
        workingRoot: URL,
        timeoutSeconds: UInt,
        outputLimitBytes: UInt
    ) async throws -> ProcessExecutionResult {
        let prepared = try builder.prepareWindowsPowerShell(
            resource: resource,
            encodedScript: encodedScript,
            credential: credential,
            rootDirectory: workingRoot,
            timeoutSeconds: timeoutSeconds,
            outputLimitBytes: outputLimitBytes
        )
        defer { try? FileManager.default.removeItem(at: prepared.rootDirectory) }
        return try await runner.run(prepared.invocation)
    }
}
