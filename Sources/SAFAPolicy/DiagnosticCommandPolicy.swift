import Foundation
import SAFADomain

public struct DiagnosticCommandPolicy: Sendable {
    public static let processFields = "pid,ppid,user,stat,comm,%cpu,%mem"
    public static let dockerPSFormat = "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}"
    public static let dockerStatsFormat =
        "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t{{.BlockIO}}\t{{.PIDs}}"

    public init() {}

    public func allowsAutomaticExecution(_ command: CommandSpec) -> Bool {
        guard command.mode == .exec,
            let arguments = command.arguments,
            command.stdinMode == .none,
            !command.tty,
            command.workingDirectory == nil,
            (1...60).contains(command.timeoutSeconds),
            (1...1_048_576).contains(command.outputLimitBytes),
            let executable = arguments.first
        else {
            return false
        }

        switch executable {
        case "true", "date", "hostname", "id", "uptime", "whoami":
            return arguments.count == 1
        case "uname":
            return allowsUname(arguments)
        case "df":
            return allowsDiskUsage(arguments)
        case "free":
            return allowsMemoryUsage(arguments)
        case "systemctl":
            return allowsSystemdState(arguments)
        case "docker":
            return allowsDockerMetadata(arguments)
        case "ps":
            return allowsProcessMetrics(arguments)
        default:
            return false
        }
    }

    private func allowsUname(_ arguments: [String]) -> Bool {
        guard arguments.count == 2, let option = arguments.last, option.hasPrefix("-") else {
            return false
        }
        let flags = option.dropFirst()
        return !flags.isEmpty && flags.allSatisfy { "asnrvmpio".contains($0) }
    }

    private func allowsDiskUsage(_ arguments: [String]) -> Bool {
        guard arguments.count <= 9 else { return false }
        let allowedOptions: Set<String> = ["-h", "-H", "-i", "-P", "-T"]
        return arguments.dropFirst().allSatisfy { argument in
            if allowedOptions.contains(argument) { return true }
            return Self.isAbsoluteDiagnosticPath(argument)
        }
    }

    private func allowsMemoryUsage(_ arguments: [String]) -> Bool {
        guard arguments.count <= 3 else { return false }
        let allowedOptions: Set<String> = ["-b", "-k", "-m", "-g", "-h", "--si", "-w"]
        return arguments.dropFirst().allSatisfy(allowedOptions.contains)
    }

    private func allowsSystemdState(_ arguments: [String]) -> Bool {
        guard arguments.count == 3,
            ["is-active", "is-enabled"].contains(arguments[1])
        else {
            return false
        }
        return Self.isSafeUnitName(arguments[2])
    }

    private func allowsDockerMetadata(_ arguments: [String]) -> Bool {
        switch arguments {
        case ["docker", "version"]:
            true
        case ["docker", "ps", "--format", Self.dockerPSFormat]:
            true
        case ["docker", "stats", "--no-stream", "--format", Self.dockerStatsFormat]:
            true
        default:
            false
        }
    }

    private func allowsProcessMetrics(_ arguments: [String]) -> Bool {
        arguments == ["ps", "-eo", Self.processFields, "--sort=-%cpu"]
            || arguments == ["ps", "-eo", Self.processFields, "--sort=-%mem"]
    }

    private static func isAbsoluteDiagnosticPath(_ value: String) -> Bool {
        guard value.hasPrefix("/"), value.utf8.count <= 1_024, !value.contains("..") else {
            return false
        }
        return value.unicodeScalars.allSatisfy { scalar in
            !CharacterSet.controlCharacters.contains(scalar)
        }
    }

    private static func isSafeUnitName(_ value: String) -> Bool {
        value.range(of: "^[A-Za-z0-9@_.:-]{1,255}$", options: .regularExpression) != nil
    }
}
