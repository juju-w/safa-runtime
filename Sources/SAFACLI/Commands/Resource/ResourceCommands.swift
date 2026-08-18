import ArgumentParser
import Foundation
import SAFAProtocol

struct ResourceCommand: AsyncParsableCommand, AgentCommand {
    static let configuration = CommandConfiguration(
        commandName: "resource",
        subcommands: [
            ResourceListCommand.self,
            ResourceShowCommand.self,
            ResourceAddCommand.self,
            ResourceEditCommand.self,
            ResourceRemoveCommand.self,
        ]
    )

    mutating func run() async throws {
        do {
            let reply = try await XPCBrokerAgentClient().queryResourceDirectory(action: .list)
            try finishDirectory(command: "resource.list", reply: reply)
        } catch let exitCode as ExitCode {
            throw exitCode
        } catch {
            try brokerFailure(command: "resource.list")
        }
    }
}

protocol ResourceDirectoryCommand: AgentCommand {}

extension AgentCommand {
    func finishDirectory(
        command: String,
        reply: ResourceDirectoryReplyV1,
        limit: Int = 100,
        fields: [AgentResourceListFieldV2] = AgentResourceListFieldV2.defaultFields
    ) throws {
        if command == "resource.list" {
            let total = reply.status == .completed ? reply.summaries.count : 0
            let rows =
                reply.status == .completed
                ? reply.summaries.prefix(limit).map(\.agentRow)
                : []
            try finish(
                AgentCLIResponseV2(
                    command: command,
                    status: reply.agentStatus,
                    payload: try AgentResourceListV2(
                        total: total,
                        truncated: total > rows.count,
                        resources: rows,
                        fields: fields
                    ),
                    error: reply.error?.agentError,
                    next: rows.isEmpty
                        ? []
                        : [
                            AgentNextCommandV2(
                                command: "safa resource show <alias>",
                                reason: "Inspect one safe resource summary",
                                safeForAgent: true
                            )
                        ]
                )
            )
            return
        }
        if let details = reply.details {
            try finish(
                AgentCLIResponseV2(
                    command: command,
                    status: reply.agentStatus,
                    payload: AgentResourceDetailsPayloadV2(resource: details.agentDetails),
                    error: reply.error?.agentError
                )
            )
            return
        }
        if let summary = reply.summaries.first {
            try finish(
                AgentCLIResponseV2(
                    command: command,
                    status: reply.agentStatus,
                    payload: AgentResourceSummaryPayloadV2(resource: summary.agentSummary),
                    error: reply.error?.agentError
                )
            )
            return
        }
        try finish(
            AgentCLIResponseV2(
                command: command,
                status: reply.agentStatus,
                payload: AgentNoPayloadV2(),
                error: reply.error?.agentError
            )
        )
    }

    func finishMutation(command: String, reply: ResourceMutationReplyV1) throws {
        let protectedCommand: String
        if case let .string(value) = reply.error?.details["trusted_local_command"] {
            protectedCommand = value
        } else {
            protectedCommand = "complete resource setup in the trusted local workflow"
        }
        let next =
            reply.status == .userActionRequired
            ? [
                AgentNextCommandV2(
                    command: protectedCommand,
                    reason: reply.error?.message ?? "Local setup is required",
                    safeForAgent: false
                )
            ]
            : []
        if let summary = reply.summary {
            try finish(
                AgentCLIResponseV2(
                    command: command,
                    status: reply.agentStatus,
                    payload: AgentResourceSummaryPayloadV2(resource: summary.agentSummary),
                    error: reply.error?.agentError,
                    next: next
                )
            )
            return
        }
        try finish(
            AgentCLIResponseV2(
                command: command,
                status: reply.agentStatus,
                payload: AgentNoPayloadV2(),
                error: reply.error?.agentError,
                next: next
            )
        )
    }
}

private extension ResourceDirectoryReplyV1 {
    var agentStatus: AgentCLIStatusV2 {
        switch status {
        case .completed: .completed
        case .denied: .denied
        case .failed: .failed
        }
    }
}

private extension ResourceMutationReplyV1 {
    var agentStatus: AgentCLIStatusV2 {
        switch status {
        case .completed: .completed
        case .userActionRequired: .userActionRequired
        case .denied: .denied
        case .failed: .failed
        }
    }
}
