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
                    kind: "trusted_setup",
                    command: ["open", "-a", "SAFA"],
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

    private func exitCode(_ reply: BrokerReply) -> SAFAProcessExit {
        if reply.status == .userActionRequired { return .userActionRequired }
        guard reply.status != .failed else {
            switch reply.error?.code {
            case "resource_not_found": return .notFound
            case "resource_not_ready", "host_identity_changed": return .securityFailure
            case "transport_failure": return .transportFailure
            default: return .runtimeFailure
            }
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
        subcommands: [SetupStatusCommand.self, SetupOpenCommand.self]
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

struct SetupOpenCommand: AsyncParsableCommand, JSONCommand {
    static let configuration = CommandConfiguration(commandName: "open")
    @Flag var json = false

    func run() async throws {
        do {
            try emit(
                command: "setup.open",
                reply: try await XPCBrokerAgentClient().send(.openTrustedSetup(resourceAlias: nil))
            )
        } catch let exit as ExitCode {
            throw exit
        } catch {
            try brokerFailure(command: "setup.open")
        }
    }
}

struct ResourceCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "resource",
        subcommands: [
            ResourceListCommand.self, ResourceShowCommand.self, ResourceAddCommand.self,
            ResourceEditCommand.self, ResourceDisableCommand.self, ResourceRemoveCommand.self,
        ]
    )
}

struct ResourceListCommand: AsyncParsableCommand, JSONCommand {
    static let configuration = CommandConfiguration(commandName: "list")
    @Flag var json = false
    @Option var state: String?

    func run() async throws {
        let parsedState: ResourceState?
        if let state {
            guard let value = ResourceState(rawValue: state) else {
                throw ValidationError("Invalid resource state")
            }
            parsedState = value
        } else {
            parsedState = nil
        }
        do {
            try emit(
                command: "resource.list",
                reply: try await XPCBrokerAgentClient().send(.listResources(state: parsedState))
            )
        } catch let exit as ExitCode {
            throw exit
        } catch {
            try brokerFailure(command: "resource.list")
        }
    }
}

struct ResourceShowCommand: AsyncParsableCommand, JSONCommand {
    static let configuration = CommandConfiguration(commandName: "show")
    @Argument var alias: String
    @Flag var json = false

    func run() async throws {
        let target = try ResourceAlias(alias)
        do {
            let reply = try await XPCBrokerAgentClient().send(.listResources(state: nil))
            guard case let .array(resources)? = reply.data["resources"],
                let resource = resources.first(where: {
                    if case let .object(value) = $0,
                        case let .string(name)? = value["alias"]
                    {
                        return name == target.rawValue
                    }
                    return false
                })
            else {
                let notFound = BrokerReply(
                    messageID: reply.messageID,
                    status: .failed,
                    error: SAFAErrorPayload(
                        code: "resource_not_found",
                        message: "The requested resource is not registered.",
                        retryable: false,
                        details: ["resource": .string(target.rawValue)]
                    )
                )
                try emit(command: "resource.show", reply: notFound)
                return
            }
            try emit(
                command: "resource.show",
                reply: BrokerReply(
                    messageID: reply.messageID,
                    status: .completed,
                    data: ["resource": resource]
                )
            )
        } catch let exit as ExitCode {
            throw exit
        } catch {
            try brokerFailure(command: "resource.show")
        }
    }
}

protocol TrustedResourceCommand: JSONCommand {
    var alias: String { get }
    var commandName: String { get }
}

extension TrustedResourceCommand {
    func runTrustedAction() async throws {
        let target = try ResourceAlias(alias)
        do {
            try emit(
                command: commandName,
                reply: try await XPCBrokerAgentClient().send(
                    .openTrustedSetup(resourceAlias: target)
                )
            )
        } catch let exit as ExitCode {
            throw exit
        } catch {
            try brokerFailure(command: commandName)
        }
    }
}

struct ResourceAddCommand: AsyncParsableCommand, TrustedResourceCommand {
    static let configuration = CommandConfiguration(commandName: "add")
    @Argument var alias: String
    @Flag var json = false
    var commandName: String { "resource.add" }
    func run() async throws { try await runTrustedAction() }
}

struct ResourceEditCommand: AsyncParsableCommand, TrustedResourceCommand {
    static let configuration = CommandConfiguration(commandName: "edit")
    @Argument var alias: String
    @Flag var json = false
    var commandName: String { "resource.edit" }
    func run() async throws { try await runTrustedAction() }
}

struct ResourceDisableCommand: AsyncParsableCommand, TrustedResourceCommand {
    static let configuration = CommandConfiguration(commandName: "disable")
    @Argument var alias: String
    @Flag var json = false
    var commandName: String { "resource.disable" }
    func run() async throws { try await runTrustedAction() }
}

struct ResourceRemoveCommand: AsyncParsableCommand, TrustedResourceCommand {
    static let configuration = CommandConfiguration(commandName: "remove")
    @Argument var alias: String
    @Flag var json = false
    var commandName: String { "resource.remove" }
    func run() async throws { try await runTrustedAction() }
}

struct ExecCommand: AsyncParsableCommand, JSONCommand {
    static let configuration = CommandConfiguration(commandName: "exec")
    @Argument var alias: String
    @Option var intent: String
    @Option(name: .customLong("expected-effect")) var expectedEffect: String?
    @Option var rollback: String?
    @Flag var sudo = false
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
                        privilege: sudo ? .sudo : .user,
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
