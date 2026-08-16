import ArgumentParser
import Foundation
import SAFAProtocol

@main
struct SAFACommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "safa",
        abstract: "Secure agent access for macOS",
        version: "0.1.0",
        subcommands: [VersionCommand.self, DoctorCommand.self]
    )
}

private protocol JSONCommand: ParsableCommand {
    var json: Bool { get }
}

extension JSONCommand {
    func emit(_ envelope: CLIEnvelope, humanMessage: String) throws {
        if json {
            let bytes = try CanonicalCodec.encode(envelope)
            FileHandle.standardOutput.write(bytes)
            FileHandle.standardOutput.write(Data([0x0A]))
        } else {
            print(humanMessage)
        }
    }
}

private struct VersionCommand: JSONCommand {
    static let configuration = CommandConfiguration(
        commandName: "version",
        abstract: "Print the runtime and contract versions"
    )

    @Flag(help: "Emit one versioned JSON envelope")
    var json = false

    func run() throws {
        let envelope = CLIEnvelope(
            command: "version",
            status: .completed,
            data: [
                "runtime_version": .string("0.1.0"),
                "cli_schema": .string(CLIEnvelope.currentSchema),
                "platform": .string("macOS"),
            ]
        )
        try emit(envelope, humanMessage: "SAFA 0.1.0 (\(CLIEnvelope.currentSchema))")
    }
}

private struct DoctorCommand: JSONCommand {
    static let configuration = CommandConfiguration(
        commandName: "doctor",
        abstract: "Check the local signed runtime without contacting a resource"
    )

    @Flag(help: "Emit one versioned JSON envelope")
    var json = false

    func run() throws {
        let envelope = CLIEnvelope(
            command: "doctor",
            status: .userActionRequired,
            data: [
                "platform": .string("macOS"),
                "cli": .string("ready"),
                "broker": .string("not_configured"),
                "remote_action_performed": .boolean(false),
            ],
            warnings: ["The signed broker and trusted setup app are not assembled yet."],
            nextAction: NextAction(
                kind: "trusted_setup",
                command: ["open", "-a", "SAFA"],
                safeForAgent: false
            )
        )
        try emit(envelope, humanMessage: "CLI ready; signed broker setup is required.")
        throw ExitCode(SAFAProcessExit.userActionRequired.rawValue)
    }
}
