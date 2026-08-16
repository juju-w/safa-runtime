import Dispatch
@preconcurrency import Foundation
import SAFADomain
import SAFAProtocol

public enum BrokerAgentClientError: Error, Equatable, Sendable {
    case unavailable
    case invalidReply
    case timedOut
}

public protocol BrokerAgentClient: Sendable {
    func send(_ operation: AgentClientOperation) async throws -> BrokerReply
    func queryResourceDirectory(
        action: ResourceQueryActionV1,
        alias: ResourceAlias?,
        state: ResourceState?
    ) async throws -> ResourceDirectoryReplyV1
    func mutateResource(
        action: ResourceMutationActionV1,
        alias: ResourceAlias,
        mutation: ResourceMutationV1?
    ) async throws -> ResourceMutationReplyV1
}

final class XPCReplyContinuationBox<Reply: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var completed = false
    private var connection: NSXPCConnection?
    private let continuation: CheckedContinuation<Reply, any Error>

    init(connection: NSXPCConnection, continuation: CheckedContinuation<Reply, any Error>) {
        self.connection = connection
        self.continuation = continuation
    }

    func succeed(_ reply: Reply) { finish(.success(reply)) }
    func fail(_ error: any Error) { finish(.failure(error)) }

    func scheduleTimeout(after interval: TimeInterval) {
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + interval) {
            [weak self] in
            self?.fail(BrokerAgentClientError.timedOut)
        }
    }

    private func finish(_ result: Result<Reply, any Error>) {
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

enum XPCReplyTimeout {
    static let standard: TimeInterval = 10
    static let commandGrace: UInt = 10
    static let maximumCommand: UInt = 60
    static let maximumWait: UInt = 300

    static func interval(for operation: AgentClientOperation) -> TimeInterval {
        switch operation {
        case let .submitExecution(_, command, _, _, _, _):
            TimeInterval(min(command.timeoutSeconds, maximumCommand) + commandGrace)
        case let .waitRequest(_, timeoutSeconds):
            TimeInterval(min(timeoutSeconds, maximumWait) + commandGrace)
        default:
            standard
        }
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
            let box = XPCReplyContinuationBox(
                connection: connection,
                continuation: continuation
            )
            box.scheduleTimeout(after: XPCReplyTimeout.interval(for: operation))
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

    public func queryResourceDirectory(
        action: ResourceQueryActionV1,
        alias: ResourceAlias? = nil,
        state: ResourceState? = nil
    ) async throws -> ResourceDirectoryReplyV1 {
        let team = try CodeSigningRequirement.currentTeamIdentifier()
        let requirement = try CodeSigningRequirement.requirement(
            teamIdentifier: team,
            signingIdentifiers: ["dev.safa.broker"]
        )
        let now = Date()
        let message = ResourceDirectoryRequestV1(
            header: IPCHeader(sentAt: now, deadline: now.addingTimeInterval(30)),
            action: action,
            alias: alias,
            state: state
        )
        let request = try CanonicalCodec.encode(message)

        return try await withCheckedThrowingContinuation { continuation in
            let connection = NSXPCConnection(machServiceName: BrokerServiceNames.agent)
            let box = XPCReplyContinuationBox(
                connection: connection,
                continuation: continuation
            )
            box.scheduleTimeout(after: XPCReplyTimeout.standard)
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
            proxy.queryResourceDirectory(request) { data in
                do {
                    let reply = try CanonicalCodec.decode(
                        ResourceDirectoryReplyV1.self,
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

    public func mutateResource(
        action: ResourceMutationActionV1,
        alias: ResourceAlias,
        mutation: ResourceMutationV1? = nil
    ) async throws -> ResourceMutationReplyV1 {
        let team = try CodeSigningRequirement.currentTeamIdentifier()
        let requirement = try CodeSigningRequirement.requirement(
            teamIdentifier: team,
            signingIdentifiers: ["dev.safa.broker"]
        )
        let now = Date()
        let message = ResourceMutationRequestV1(
            header: IPCHeader(sentAt: now, deadline: now.addingTimeInterval(30)),
            action: action,
            alias: alias,
            mutation: mutation
        )
        let request = try CanonicalCodec.encode(message)

        return try await withCheckedThrowingContinuation { continuation in
            let connection = NSXPCConnection(machServiceName: BrokerServiceNames.agent)
            let box = XPCReplyContinuationBox(
                connection: connection,
                continuation: continuation
            )
            box.scheduleTimeout(after: XPCReplyTimeout.standard)
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
            proxy.mutateResource(request) { data in
                do {
                    let reply = try CanonicalCodec.decode(
                        ResourceMutationReplyV1.self,
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
