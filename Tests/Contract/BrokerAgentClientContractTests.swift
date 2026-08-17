import Foundation
import SAFADomain
import SAFAProtocol
import Testing

@testable import SAFACLI

@Suite("Broker Agent client lifecycle")
struct BrokerAgentClientContractTests {
    @Test("an XPC request without a reply fails at its bounded deadline")
    func boundedReplyDeadline() async {
        do {
            let _: Int = try await withCheckedThrowingContinuation { continuation in
                let connection = NSXPCConnection(
                    machServiceName: "dev.safa.tests.never-replies"
                )
                let box = XPCReplyContinuationBox(
                    connection: connection,
                    continuation: continuation
                )
                connection.invalidationHandler = {
                    box.fail(BrokerAgentClientError.unavailable)
                }
                box.scheduleTimeout(after: 0.01)
            }
            Issue.record("The request unexpectedly completed without a reply.")
        } catch let error as BrokerAgentClientError {
            #expect(error == .timedOut)
        } catch {
            Issue.record("The request failed with an unstable error type.")
        }
    }

    @Test("untrusted timeout values are capped before deadline arithmetic")
    func boundedTimeoutArithmetic() throws {
        let command = try CommandSpec.exec(
            arguments: ["uptime"],
            timeoutSeconds: .max
        )
        let execution = AgentClientOperation.submitExecution(
            resourceAlias: try ResourceAlias("nas.home"),
            command: command,
            privilege: .user,
            intent: "Synthetic contract check",
            expectedEffect: nil,
            rollback: nil
        )

        #expect(XPCReplyTimeout.interval(for: execution) == 70)
        #expect(
            XPCReplyTimeout.interval(
                for: .waitRequest(id: UUID(), timeoutSeconds: .max)
            ) == 310
        )
        #expect(XPCReplyTimeout.interval(for: .runtimeStatus) == 10)
    }

    @Test("user-present resource operations allow the system prompt to complete")
    func userPresenceOperationsUseInteractiveDeadline() {
        #expect(XPCReplyTimeout.interval(for: ResourceQueryActionV1.list) == 10)
        #expect(XPCReplyTimeout.interval(for: ResourceQueryActionV1.show) == 10)
        #expect(XPCReplyTimeout.interval(for: ResourceQueryActionV1.inspect) == 300)

        for action in [
            ResourceMutationActionV1.add,
            .edit,
            .setup,
            .disable,
            .enable,
            .remove,
        ] {
            #expect(XPCReplyTimeout.interval(for: action) == 300)
        }
    }
}
