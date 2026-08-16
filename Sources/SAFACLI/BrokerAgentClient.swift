@preconcurrency import Foundation
import SAFAProtocol

public enum BrokerAgentClientError: Error, Equatable, Sendable {
    case unavailable
    case invalidReply
}

public protocol BrokerAgentClient: Sendable {
    func send(_ operation: AgentClientOperation) async throws -> BrokerReply
}

private final class BrokerContinuationBox: @unchecked Sendable {
    private let lock = NSLock()
    private var completed = false
    private var connection: NSXPCConnection?
    private let continuation: CheckedContinuation<BrokerReply, any Error>

    init(connection: NSXPCConnection, continuation: CheckedContinuation<BrokerReply, any Error>) {
        self.connection = connection
        self.continuation = continuation
    }

    func succeed(_ reply: BrokerReply) { finish(.success(reply)) }
    func fail(_ error: any Error) { finish(.failure(error)) }

    private func finish(_ result: Result<BrokerReply, any Error>) {
        lock.lock()
        guard !completed else {
            lock.unlock()
            return
        }
        completed = true
        let retainedConnection = connection
        connection = nil
        lock.unlock()
        retainedConnection?.invalidate()
        continuation.resume(with: result)
    }
}

public struct XPCBrokerAgentClient: BrokerAgentClient {
    public init() {}

    public func send(_ operation: AgentClientOperation) async throws -> BrokerReply {
        let team = try CodeSigningRequirement.currentTeamIdentifier()
        let requirement = try CodeSigningRequirement.requirement(
            teamIdentifier: team,
            signingIdentifiers: ["dev.safa.broker"]
        )
        let now = Date()
        let message = AgentClientMessage(
            header: IPCHeader(sentAt: now, deadline: now.addingTimeInterval(30)),
            operation: operation
        )
        let request = try CanonicalCodec.encode(message)

        return try await withCheckedThrowingContinuation { continuation in
            let connection = NSXPCConnection(machServiceName: BrokerServiceNames.agent)
            let box = BrokerContinuationBox(connection: connection, continuation: continuation)
            connection.remoteObjectInterface = NSXPCInterface(
                with: (any SAFAAgentBrokerXPC).self
            )
            connection.setCodeSigningRequirement(requirement)
            connection.interruptionHandler = { box.fail(BrokerAgentClientError.unavailable) }
            connection.invalidationHandler = { box.fail(BrokerAgentClientError.unavailable) }
            connection.resume()
            guard
                let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in
                    box.fail(BrokerAgentClientError.unavailable)
                }) as? any SAFAAgentBrokerXPC
            else {
                box.fail(BrokerAgentClientError.unavailable)
                return
            }
            proxy.sendAgentMessage(request) { data in
                do {
                    let reply = try CanonicalCodec.decode(
                        BrokerReply.self,
                        from: data,
                        maxBytes: 2 * 1_048_576
                    )
                    guard reply.protocolVersion == IPCHeader.currentVersion,
                        reply.messageID == message.header.messageID
                    else {
                        throw BrokerAgentClientError.invalidReply
                    }
                    box.succeed(reply)
                } catch {
                    box.fail(error)
                }
            }
        }
    }
}
