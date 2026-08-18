import Foundation
import SAFAProtocol

struct AgentCLIToonPresenter: Sendable {
    private let encoder = TOONEncoderV4_1()

    func encode<Payload: AgentCLIToonPayload>(
        _ response: AgentCLIResponseV2<Payload>
    ) throws -> String {
        try encoder.encode(
            .object(
                commonFields(response)
                    + errorFields(response.error)
                    + response.payload.toonFields()
                    + tailFields(warnings: response.warnings, next: response.next)
            )
        )
    }

    private func commonFields<Payload: Sendable>(
        _ response: AgentCLIResponseV2<Payload>
    ) -> [TOONField] {
        var fields = [
            TOONField(key: "schema", value: .string(AgentCLIV2Contract.schema)),
            TOONField(key: "command", value: .string(response.command)),
            TOONField(key: "status", value: .string(response.status.rawValue)),
        ]
        if let requestID = response.requestID {
            fields.append(
                TOONField(
                    key: "request_id",
                    value: .string(requestID.uuidString.lowercased())
                )
            )
        }
        return fields
    }

    private func errorFields(_ error: AgentCLIErrorV2?) -> [TOONField] {
        guard let error else { return [] }
        return [
            TOONField(
                key: "error",
                value: .object([
                    TOONField(key: "code", value: .string(error.code)),
                    TOONField(key: "message", value: .string(error.message)),
                    TOONField(key: "retryable", value: .boolean(error.retryable)),
                ])
            )
        ]
    }

    private func tailFields(
        warnings: [String],
        next: [AgentNextCommandV2]
    ) -> [TOONField] {
        var fields: [TOONField] = []
        if !warnings.isEmpty {
            fields.append(
                TOONField(
                    key: "warnings",
                    value: .array(warnings.map(TOONValue.string))
                )
            )
        }
        if !next.isEmpty {
            fields.append(
                TOONField(
                    key: "next",
                    value: .array(next.map(nextCommand))
                )
            )
        }
        return fields
    }

    private func nextCommand(_ command: AgentNextCommandV2) -> TOONValue {
        .object([
            TOONField(key: "command", value: .string(command.command)),
            TOONField(key: "reason", value: .string(command.reason)),
            TOONField(key: "safe_for_agent", value: .boolean(command.safeForAgent)),
        ])
    }
}
