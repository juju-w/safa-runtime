@preconcurrency import Foundation
import SAFADomain
import SAFAProtocol

enum TrustedBrokerClientError: Error {
    case unavailable
    case invalidReply
}

private final class TrustedReplyBox: @unchecked Sendable {
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

    func finish(_ result: Result<BrokerReply, any Error>) {
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

struct TrustedBrokerClient: Sendable {
    func send(_ operation: TrustedAppOperation) async throws -> BrokerReply {
        let team = try CodeSigningRequirement.currentTeamIdentifier()
        let requirement = try CodeSigningRequirement.requirement(
            teamIdentifier: team,
            signingIdentifiers: ["dev.safa.broker"]
        )
        let now = Date()
        let message = TrustedAppMessage(
            header: IPCHeader(sentAt: now, deadline: now.addingTimeInterval(30)),
            operation: operation
        )
        let bytes = try CanonicalCodec.encode(message)

        return try await withCheckedThrowingContinuation { continuation in
            let connection = NSXPCConnection(machServiceName: BrokerServiceNames.trustedApp)
            let box = TrustedReplyBox(connection: connection, continuation: continuation)
            connection.remoteObjectInterface = NSXPCInterface(
                with: (any SAFATrustedAppBrokerXPC).self
            )
            connection.setCodeSigningRequirement(requirement)
            connection.interruptionHandler = {
                box.finish(.failure(TrustedBrokerClientError.unavailable))
            }
            connection.invalidationHandler = {
                box.finish(.failure(TrustedBrokerClientError.unavailable))
            }
            connection.resume()
            guard
                let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in
                    box.finish(.failure(TrustedBrokerClientError.unavailable))
                }) as? any SAFATrustedAppBrokerXPC
            else {
                box.finish(.failure(TrustedBrokerClientError.unavailable))
                return
            }
            proxy.sendTrustedAppMessage(bytes) { data in
                do {
                    let reply = try CanonicalCodec.decode(BrokerReply.self, from: data)
                    guard reply.messageID == message.header.messageID,
                        reply.protocolVersion == IPCHeader.currentVersion
                    else {
                        throw TrustedBrokerClientError.invalidReply
                    }
                    box.finish(.success(reply))
                } catch {
                    box.finish(.failure(error))
                }
            }
        }
    }

    func add(alias: ResourceAlias, payload: ProtectedResourceSetupPayload) async throws {
        let begin = try await send(.beginPrivateSetup(resourceAlias: alias))
        guard begin.status == .completed,
            case let .string(sessionValue)? = begin.data["setup_session_id"],
            let sessionID = UUID(uuidString: sessionValue)
        else {
            throw TrustedBrokerClientError.invalidReply
        }
        let committed = try await send(
            .commitPrivateSetup(
                sessionID: sessionID,
                protectedPayload: CanonicalCodec.encode(payload)
            )
        )
        guard committed.status == .completed else {
            throw TrustedBrokerClientError.invalidReply
        }
    }
}
