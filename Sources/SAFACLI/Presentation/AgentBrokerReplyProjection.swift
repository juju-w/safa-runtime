import Foundation
import SAFAProtocol

enum AgentReplyProjectionError: Error, Equatable {
    case invalidReply
}

extension AgentCommand {
    func finishBrokerReply(command: String, reply: BrokerReply) throws {
        if command == "doctor", reply.status == .completed {
            let payload = AgentRuntimeStatusV2(
                broker: reply.data.string(for: "broker") ?? "unknown",
                vault: reply.data.string(for: "vault") ?? "unknown"
            )
            try finish(
                AgentCLIResponseV2(
                    command: command,
                    status: .completed,
                    payload: payload
                )
            )
            return
        }

        guard command == "exec", reply.status == .completed else {
            try finish(
                AgentCLIResponseV2(
                    command: command,
                    status: reply.agentStatus,
                    requestID: reply.requestID,
                    payload: AgentNoPayloadV2(),
                    error: reply.error?.agentError,
                    next: reply.agentNext
                )
            )
            return
        }

        let execution = try reply.executionResult()
        try finish(
            AgentCLIResponseV2(
                command: command,
                status: execution.agentStatus,
                requestID: reply.requestID,
                payload: execution,
                error: execution.agentError,
                next: execution.fullOutputNext.map { [$0] } ?? []
            )
        )
    }
}

extension SAFAErrorPayload {
    var agentError: AgentCLIErrorV2 {
        AgentCLIErrorV2(code: code, message: message, retryable: retryable)
    }
}

extension BrokerReply {
    var agentStatus: AgentCLIStatusV2 {
        switch status {
        case .completed:
            .completed
        case .userActionRequired:
            .userActionRequired
        case .failed where error?.code == "transport_failure":
            .transportFailed
        case .failed:
            .failed
        }
    }

    var requestID: UUID? {
        data.string(for: "request_id").flatMap(UUID.init(uuidString:))
    }

    var agentNext: [AgentNextCommandV2] {
        guard status == .userActionRequired else { return [] }
        return [
            AgentNextCommandV2(
                command: "complete the requested action in the trusted local workflow",
                reason: error?.message ?? "Local user authorization is required",
                safeForAgent: false
            )
        ]
    }

    func executionResult() throws -> AgentExecutionResultV2 {
        guard let resource = data.string(for: "resource"),
            let intent = data.string(for: "intent"),
            case let .object(execution)? = data["execution"],
            let termination = execution.string(for: "termination"),
            case let .object(stdout)? = execution["stdout"],
            case let .object(stderr)? = execution["stderr"]
        else {
            throw AgentReplyProjectionError.invalidReply
        }
        return AgentExecutionResultV2(
            resource: resource,
            intent: intent,
            termination: termination,
            remoteExitCode: execution.int32(for: "remote_exit_code"),
            stdout: try stdout.textPreview(),
            stderr: try stderr.textPreview()
        )
    }
}

extension AgentExecutionResultV2 {
    var hasTruncatedOutput: Bool { stdout.truncated || stderr.truncated }

    var agentStatus: AgentCLIStatusV2 {
        switch termination {
        case "exit":
            guard let remoteExitCode else { return .failed }
            return remoteExitCode == 0 ? .completed : .remoteExecutionFailed
        case "cancelled":
            return .cancelled
        case "timeout", "signal":
            return .failed
        default:
            return .failed
        }
    }

    var agentError: AgentCLIErrorV2? {
        switch termination {
        case "timeout":
            return AgentCLIErrorV2(
                code: "execution.timeout",
                message: "The local execution deadline expired.",
                retryable: true
            )
        case "signal":
            return AgentCLIErrorV2(
                code: "execution.signal",
                message: "The local execution process ended after receiving a signal.",
                retryable: true
            )
        case "exit" where remoteExitCode == nil:
            return AgentCLIErrorV2(
                code: "execution.invalid_result",
                message: "The local execution result did not include a remote exit code.",
                retryable: false
            )
        case "exit", "cancelled":
            return nil
        default:
            return AgentCLIErrorV2(
                code: "execution.invalid_result",
                message: "The local execution result contained an unknown termination reason.",
                retryable: false
            )
        }
    }

    var fullOutputNext: AgentNextCommandV2? {
        guard hasTruncatedOutput else { return nil }
        return AgentNextCommandV2(
            command: "safa exec \(resource) --intent \"<intent>\" --full -- <args>",
            reason: "Retrieve a larger bounded preview",
            safeForAgent: true
        )
    }
}

private extension Dictionary where Key == String, Value == JSONValue {
    func string(for key: String) -> String? {
        guard case let .string(value)? = self[key] else { return nil }
        return value
    }

    func int(for key: String) -> Int? {
        guard case let .integer(value)? = self[key] else { return nil }
        return Int(exactly: value)
    }

    func int32(for key: String) -> Int32? {
        guard case let .integer(value)? = self[key] else { return nil }
        return Int32(exactly: value)
    }

    func bool(for key: String) -> Bool? {
        guard case let .boolean(value)? = self[key] else { return nil }
        return value
    }

    func textPreview() throws -> AgentTextPreviewV2 {
        guard let text = string(for: "text"),
            let capturedBytes = int(for: "captured_bytes"),
            let truncated = bool(for: "truncated")
        else {
            throw AgentReplyProjectionError.invalidReply
        }
        return AgentTextPreviewV2(
            text: text,
            capturedBytes: capturedBytes,
            originalBytes: int(for: "original_bytes") ?? capturedBytes,
            truncated: truncated
        )
    }
}
