import Dispatch
@preconcurrency import Foundation
import SAFADomain
import SAFAProtocol

enum TrustedLocalSetupClientError: Error, Equatable, Sendable {
    case unavailable
    case invalidReply
    case timedOut
    case brokerRejected(String)
}

protocol TrustedLocalSetupClient: Sendable {
    func begin(alias: ResourceAlias) async throws -> UUID
    func commit(sessionID: UUID, payload: ProtectedResourceSetupPayload) async throws
}

struct XPCTrustedLocalSetupClient: TrustedLocalSetupClient {
    func begin(alias: ResourceAlias) async throws -> UUID {
        let reply = try await send(.beginPrivateSetup(resourceAlias: alias))
        guard reply.status == .completed,
            case let .string(value) = reply.data["setup_session_id"],
            let sessionID = UUID(uuidString: value)
        else {
            throw Self.error(for: reply)
        }
        return sessionID
    }

    func commit(sessionID: UUID, payload: ProtectedResourceSetupPayload) async throws {
        let reply = try await send(
            .commitPrivateSetup(
                sessionID: sessionID,
                protectedPayload: try CanonicalCodec.encode(payload)
            )
        )
        guard reply.status == .completed else { throw Self.error(for: reply) }
    }

    private func send(_ operation: TrustedLocalOperation) async throws -> BrokerReply {
        let team = try CodeSigningRequirement.currentTeamIdentifier()
        let requirement = try CodeSigningRequirement.requirement(
            teamIdentifier: team,
            signingIdentifiers: ["dev.safa.broker"]
        )
        let now = Date()
        let message = TrustedLocalMessage(
            header: IPCHeader(sentAt: now, deadline: now.addingTimeInterval(180)),
            operation: operation
        )
        let request = try CanonicalCodec.encode(message)

        return try await withCheckedThrowingContinuation { continuation in
            let connection = NSXPCConnection(machServiceName: BrokerServiceNames.trustedLocal)
            let box = TrustedSetupReplyBox(connection: connection, continuation: continuation)
            box.scheduleTimeout(after: 185)
            connection.remoteObjectInterface = NSXPCInterface(
                with: (any SAFATrustedLocalBrokerXPC).self
            )
            connection.setCodeSigningRequirement(requirement)
            connection.interruptionHandler = { box.fail(TrustedLocalSetupClientError.unavailable) }
            connection.invalidationHandler = { box.fail(TrustedLocalSetupClientError.unavailable) }
            connection.resume()
            guard
                let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in
                    box.fail(TrustedLocalSetupClientError.unavailable)
                }) as? any SAFATrustedLocalBrokerXPC
            else {
                box.fail(TrustedLocalSetupClientError.unavailable)
                return
            }
            proxy.sendTrustedLocalMessage(request) { data in
                do {
                    let reply = try CanonicalCodec.decode(
                        BrokerReply.self,
                        from: data,
                        maxBytes: 2 * 1_048_576
                    )
                    guard reply.protocolVersion == IPCHeader.currentVersion,
                        reply.messageID == message.header.messageID
                    else {
                        throw TrustedLocalSetupClientError.invalidReply
                    }
                    box.succeed(reply)
                } catch {
                    box.fail(error)
                }
            }
        }
    }

    private static func error(for reply: BrokerReply) -> TrustedLocalSetupClientError {
        .brokerRejected(reply.error?.code ?? "private_setup_failed")
    }
}

private final class TrustedSetupReplyBox: @unchecked Sendable {
    private let lock = NSLock()
    private var completed = false
    private var connection: NSXPCConnection?
    private let continuation: CheckedContinuation<BrokerReply, any Error>

    init(
        connection: NSXPCConnection,
        continuation: CheckedContinuation<BrokerReply, any Error>
    ) {
        self.connection = connection
        self.continuation = continuation
    }

    func succeed(_ reply: BrokerReply) { finish(.success(reply)) }
    func fail(_ error: any Error) { finish(.failure(error)) }

    func scheduleTimeout(after interval: TimeInterval) {
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + interval) {
            [weak self] in
            self?.fail(TrustedLocalSetupClientError.timedOut)
        }
    }

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
