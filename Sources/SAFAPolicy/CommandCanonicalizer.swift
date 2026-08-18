import CryptoKit
import Foundation
import SAFADomain

public enum CommandCanonicalizationError: Error, Equatable, Sendable {
    case emptyExecutable
    case containsNUL(field: String)
    case argumentTooLarge(index: Int)
    case argumentVectorTooLarge
    case workingDirectoryTooLarge
}

public struct CanonicalCommand: Equatable, Sendable {
    public let mode: CommandMode
    public let arguments: [String]?
    public let shellProgram: String?
    public let posixProgram: String
    public let fingerprint: String

    init(
        mode: CommandMode,
        arguments: [String]?,
        shellProgram: String?,
        posixProgram: String,
        fingerprint: String
    ) {
        self.mode = mode
        self.arguments = arguments
        self.shellProgram = shellProgram
        self.posixProgram = posixProgram
        self.fingerprint = fingerprint
    }
}

public struct CommandCanonicalizer: Sendable {
    public static let maximumArguments = 1_024
    public static let maximumArgumentBytes = 16 * 1_024
    public static let maximumArgumentVectorBytes = 64 * 1_024
    public static let maximumWorkingDirectoryBytes = 4 * 1_024

    public init() {}

    public func canonicalize(_ command: CommandSpec) throws -> CanonicalCommand {
        try validateCommonFields(command)

        let posixProgram: String
        switch command.mode {
        case .exec:
            guard let arguments = command.arguments, let executable = arguments.first,
                !executable.isEmpty
            else {
                throw CommandCanonicalizationError.emptyExecutable
            }
            try validate(arguments: arguments)
            posixProgram = arguments.map(Self.quotePOSIXArgument).joined(separator: " ")
        case .shell:
            guard let shellProgram = command.shellProgram else {
                throw CommandCanonicalizationError.emptyExecutable
            }
            try rejectNUL(shellProgram, field: "shell_program")
            posixProgram = shellProgram
        }

        let fingerprint = Self.fingerprint(for: command)
        return CanonicalCommand(
            mode: command.mode,
            arguments: command.arguments,
            shellProgram: command.shellProgram,
            posixProgram: posixProgram,
            fingerprint: fingerprint
        )
    }

    public static func quotePOSIXArgument(_ value: String) -> String {
        return "'" + value.replacingOccurrences(of: "'", with: "'\"'\"'") + "'"
    }

    private func validateCommonFields(_ command: CommandSpec) throws {
        if let workingDirectory = command.workingDirectory {
            try rejectNUL(workingDirectory, field: "working_directory")
            guard workingDirectory.utf8.count <= Self.maximumWorkingDirectoryBytes else {
                throw CommandCanonicalizationError.workingDirectoryTooLarge
            }
        }
    }

    private func validate(arguments: [String]) throws {
        guard arguments.count <= Self.maximumArguments else {
            throw CommandCanonicalizationError.argumentVectorTooLarge
        }

        var totalBytes = 0
        for (index, argument) in arguments.enumerated() {
            try rejectNUL(argument, field: "argument_\(index)")
            let byteCount = argument.utf8.count
            guard byteCount <= Self.maximumArgumentBytes else {
                throw CommandCanonicalizationError.argumentTooLarge(index: index)
            }
            totalBytes += byteCount
            guard totalBytes <= Self.maximumArgumentVectorBytes else {
                throw CommandCanonicalizationError.argumentVectorTooLarge
            }
        }
    }

    private func rejectNUL(_ value: String, field: String) throws {
        guard !value.unicodeScalars.contains(where: { $0.value == 0 }) else {
            throw CommandCanonicalizationError.containsNUL(field: field)
        }
    }

    private static func fingerprint(for command: CommandSpec) -> String {
        var material = Data("dev.safa.command/v1\n".utf8)
        append(command.mode.rawValue, tag: "mode", to: &material)
        append(command.arguments, tag: "arguments", to: &material)
        append(command.shellProgram, tag: "shell_program", to: &material)
        append(command.stdinMode.rawValue, tag: "stdin_mode", to: &material)
        append(command.tty ? "true" : "false", tag: "tty", to: &material)
        append(command.workingDirectory, tag: "working_directory", to: &material)
        append(String(command.timeoutSeconds), tag: "timeout_seconds", to: &material)
        append(String(command.outputLimitBytes), tag: "output_limit_bytes", to: &material)

        let digest = SHA256.hash(data: material)
        return "sha256:" + digest.map { String(format: "%02x", $0) }.joined()
    }

    private static func append(_ value: String, tag: String, to data: inout Data) {
        data.append(Data("\(tag):\(value.utf8.count):".utf8))
        data.append(Data(value.utf8))
        data.append(0x0A)
    }

    private static func append(_ value: String?, tag: String, to data: inout Data) {
        guard let value else {
            data.append(Data("\(tag):-1:\n".utf8))
            return
        }
        append(value, tag: tag, to: &data)
    }

    private static func append(_ values: [String]?, tag: String, to data: inout Data) {
        guard let values else {
            data.append(Data("\(tag):-1:\n".utf8))
            return
        }
        data.append(Data("\(tag):\(values.count):\n".utf8))
        for (index, value) in values.enumerated() {
            append(value, tag: "\(tag)[\(index)]", to: &data)
        }
    }
}
