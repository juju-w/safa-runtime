import ArgumentParser
import Foundation
import SAFADomain
import SAFAProtocol

@available(macOS 10.15, macCatalyst 13, iOS 13, tvOS 13, watchOS 6, *)
public struct SAFACommand: AsyncParsableCommand {
    public static let configuration = CommandConfiguration(
        commandName: "safa",
        abstract: "Secure agent access for macOS",
        version: "0.1.0",
        subcommands: [
            VersionCommand.self, DoctorCommand.self, SetupCommand.self,
            ResourceCommand.self, ExecCommand.self,
        ]
    )

    public init() {}

    public static func runMain() async {
        do {
            var command = try await asyncParseAsRoot()
            if var asyncCommand = command as? any AsyncParsableCommand {
                try await asyncCommand.run()
            } else {
                try command.run()
            }
        } catch {
            exit(withError: error)
        }
    }
}

protocol JSONCommand {
    var json: Bool { get }
}

extension JSONCommand {
    func emit(_ envelope: CLIEnvelope, humanMessage: String) throws {
        if json {
            FileHandle.standardOutput.write(try CanonicalCodec.encode(envelope))
            FileHandle.standardOutput.write(Data([0x0A]))
        } else {
            print(humanMessage)
        }
    }

    func emit(command: String, reply: BrokerReply) throws {
        let status: CLIStatus
        switch reply.status {
        case .completed: status = .completed
        case .userActionRequired: status = .userActionRequired
        case .failed: status = .failed
        }
        var data = reply.data
        if let error = reply.error { data["error"] = .object(error.jsonObject) }
        let requestID: UUID?
        if case let .string(value)? = reply.data["request_id"] {
            requestID = UUID(uuidString: value)
        } else {
            requestID = nil
        }
        let envelope = CLIEnvelope(
            command: command,
            status: status,
            requestID: requestID,
            data: data,
            nextAction: status == .userActionRequired
                ? NextAction(
                    kind: "complete_local_setup",
                    command: [],
                    safeForAgent: false
                )
                : nil
        )
        try emit(envelope, humanMessage: reply.error?.message ?? "\(command) completed.")
        let exit = exitCode(reply)
        if exit != .success { throw ExitCode(exit.rawValue) }
    }

    func brokerFailure(command: String) throws -> Never {
        let error = SAFAErrorPayload(
            code: "broker_unavailable",
            message: "The signed local broker is unavailable.",
            retryable: true
        )
        try emit(
            CLIEnvelope(
                command: command,
                status: .failed,
                data: ["error": .object(error.jsonObject)]
            ),
            humanMessage: error.message
        )
        throw ExitCode(SAFAProcessExit.runtimeFailure.rawValue)
    }

    func invalidInvocation(command: String, message: String) throws -> Never {
        let error = SAFAErrorPayload(
            code: "invalid_invocation",
            message: message,
            retryable: false
        )
        try emit(
            CLIEnvelope(
                command: command,
                status: .failed,
                data: ["error": .object(error.jsonObject)]
            ),
            humanMessage: message
        )
        throw ExitCode(SAFAProcessExit.invalidInvocation.rawValue)
    }

    private func exitCode(_ reply: BrokerReply) -> SAFAProcessExit {
        if reply.status == .userActionRequired { return .userActionRequired }
        guard reply.status != .failed else {
            return SAFAProcessExit.map(errorCode: reply.error?.code)
        }
        if case let .object(execution)? = reply.data["execution"],
            case let .integer(remoteExit)? = execution["remote_exit_code"],
            remoteExit != 0
        {
            return .remoteFailure
        }
        return .success
    }
}

struct VersionCommand: ParsableCommand, JSONCommand {
    static let configuration = CommandConfiguration(commandName: "version")
    @Flag var json = false

    func run() throws {
        try emit(
            CLIEnvelope(
                command: "version",
                status: .completed,
                data: [
                    "runtime_version": .string("0.1.0"),
                    "cli_schema": .string(CLIEnvelope.currentSchema),
                    "platform": .string("macOS"),
                ]
            ),
            humanMessage: "SAFA 0.1.0 (\(CLIEnvelope.currentSchema))"
        )
    }
}

struct DoctorCommand: AsyncParsableCommand, JSONCommand {
    static let configuration = CommandConfiguration(commandName: "doctor")
    @Flag var json = false

    func run() async throws {
        do {
            try emit(
                command: "doctor", reply: try await XPCBrokerAgentClient().send(.runtimeStatus))
        } catch let exit as ExitCode {
            throw exit
        } catch {
            try brokerFailure(command: "doctor")
        }
    }
}

struct SetupCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "setup",
        subcommands: [SetupStatusCommand.self]
    )
}

struct SetupStatusCommand: AsyncParsableCommand, JSONCommand {
    static let configuration = CommandConfiguration(commandName: "status")
    @Flag var json = false

    func run() async throws {
        do {
            try emit(
                command: "setup.status",
                reply: try await XPCBrokerAgentClient().send(.runtimeStatus))
        } catch let exit as ExitCode {
            throw exit
        } catch {
            try brokerFailure(command: "setup.status")
        }
    }
}

struct ExecCommand: AsyncParsableCommand, JSONCommand {
    static let configuration = CommandConfiguration(commandName: "exec")
    @Argument var alias: String
    @Option var intent: String
    @Option(name: .customLong("expected-effect")) var expectedEffect: String?
    @Option var rollback: String?
    @Option var timeout: UInt = 60
    @Option(name: .customLong("output-limit")) var outputLimit: UInt = 1_048_576
    @Flag var json = false
    @Argument(parsing: .postTerminator) var arguments: [String] = []

    func run() async throws {
        let target = try ResourceAlias(alias)
        let command = try CommandSpec.exec(
            arguments: arguments,
            timeoutSeconds: timeout,
            outputLimitBytes: outputLimit
        )
        do {
            try emit(
                command: "exec",
                reply: try await XPCBrokerAgentClient().send(
                    .submitExecution(
                        resourceAlias: target,
                        command: command,
                        privilege: .user,
                        intent: intent,
                        expectedEffect: expectedEffect,
                        rollback: rollback
                    )
                )
            )
        } catch let exit as ExitCode {
            throw exit
        } catch {
            try brokerFailure(command: "exec")
        }
    }
}
