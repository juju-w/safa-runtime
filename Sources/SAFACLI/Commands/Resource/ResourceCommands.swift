import ArgumentParser
import Foundation
import SAFAProtocol

struct ResourceCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "resource",
        subcommands: [
            ResourceListCommand.self,
            ResourceShowCommand.self,
            ResourceInspectCommand.self,
            ResourceAddCommand.self,
            ResourceEditCommand.self,
            ResourceSetupCommand.self,
            ResourceDisableCommand.self,
            ResourceRemoveCommand.self,
        ]
    )
}

protocol ResourceDirectoryCommand: JSONCommand {}

extension ResourceDirectoryCommand {
    func emitDirectory(command: String, reply: ResourceDirectoryReplyV1) throws {
        let status: CLIStatus
        switch reply.status {
        case .completed: status = .completed
        case .denied: status = .denied
        case .failed: status = .failed
        }
        var data: [String: JSONValue] = [:]
        if !reply.summaries.isEmpty {
            data["resources"] = .array(reply.summaries.map(\.jsonValue))
        }
        if let details = reply.details {
            data["resource"] = details.jsonValue
        }
        if let error = reply.error {
            data["error"] = .object(error.jsonObject)
        }
        let envelope = CLIEnvelope(command: command, status: status, data: data)
        let human: String
        if let error = reply.error {
            human = error.message
        } else if let details = reply.details {
            let endpoint = details.endpoint.map { "\($0.host):\($0.port)" } ?? "no endpoint"
            human = "\(details.alias) [\(details.resourceType)] \(endpoint)"
        } else {
            human = reply.summaries.map {
                "\($0.alias) [\($0.resourceType)] \($0.state)/\($0.health)"
            }.joined(separator: "\n")
        }
        try emit(envelope, humanMessage: human.isEmpty ? "No resources." : human)
        switch reply.status {
        case .completed:
            return
        case .denied:
            throw ExitCode(SAFAProcessExit.denied.rawValue)
        case .failed:
            throw ExitCode(SAFAProcessExit.map(errorCode: reply.error?.code).rawValue)
        }
    }

    func emitMutation(command: String, reply: ResourceMutationReplyV1) throws {
        let status: CLIStatus
        switch reply.status {
        case .completed: status = .completed
        case .userActionRequired: status = .userActionRequired
        case .denied: status = .denied
        case .failed: status = .failed
        }
        var data: [String: JSONValue] = [:]
        if let summary = reply.summary {
            data["resource"] = summary.jsonValue
        }
        if let error = reply.error {
            data["error"] = .object(error.jsonObject)
        }
        let envelope = CLIEnvelope(
            command: command,
            status: status,
            data: data,
            nextAction: status == .userActionRequired
                ? NextAction(kind: "complete_local_setup", command: [], safeForAgent: false)
                : nil
        )
        let human =
            reply.error?.message
            ?? reply.summary.map { "\($0.alias) \($0.state)/\($0.health)" }
            ?? "\(command) completed."
        try emit(envelope, humanMessage: human)
        switch reply.status {
        case .completed:
            return
        case .userActionRequired:
            throw ExitCode(SAFAProcessExit.userActionRequired.rawValue)
        case .denied:
            throw ExitCode(SAFAProcessExit.denied.rawValue)
        case .failed:
            throw ExitCode(SAFAProcessExit.map(errorCode: reply.error?.code).rawValue)
        }
    }
}
