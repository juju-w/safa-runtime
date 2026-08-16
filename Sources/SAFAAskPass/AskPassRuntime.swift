import Darwin
@preconcurrency import Foundation
import SAFAProtocol

public protocol AskPassCredentialClient: Sendable {
    func consume(binding: String, parentPID: Int32) async throws -> Data
}

public struct AskPassResponder: Sendable {
    private let client: any AskPassCredentialClient

    public init(client: any AskPassCredentialClient) {
        self.client = client
    }

    public func response(binding: String, parentPID: Int32) async throws -> Data {
        guard !binding.isEmpty, binding.utf8.count <= 256 else {
            throw AskPassRuntimeError.invalidBinding
        }
        return try await client.consume(binding: binding, parentPID: parentPID)
    }
}

public enum AskPassRuntimeError: Error, Equatable, Sendable {
    case invalidBinding
    case brokerUnavailable
}

private final class AskPassContinuationBox: @unchecked Sendable {
    private let lock = NSLock()
    private var completed = false
    private var connection: NSXPCConnection?
    private let continuation: CheckedContinuation<Data, any Error>

    init(
        connection: NSXPCConnection,
        continuation: CheckedContinuation<Data, any Error>
    ) {
        self.connection = connection
        self.continuation = continuation
    }

    func succeed(_ data: Data) {
        finish(.success(data))
    }

    func fail(_ error: any Error) {
        finish(.failure(error))
    }

    private func finish(_ result: Result<Data, any Error>) {
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

public struct XPCAskPassCredentialClient: AskPassCredentialClient {
    public init() {}

    public func consume(binding: String, parentPID: Int32) async throws -> Data {
        let team = try CodeSigningRequirement.currentTeamIdentifier()
        let requirement = try CodeSigningRequirement.requirement(
            teamIdentifier: team,
            signingIdentifiers: ["dev.safa.broker"]
        )
        let request = try CanonicalCodec.encode(
            AskPassRequest(binding: binding, parentProcessID: parentPID)
        )

        return try await withCheckedThrowingContinuation { continuation in
            let connection = NSXPCConnection(machServiceName: BrokerServiceNames.askPass)
            let box = AskPassContinuationBox(
                connection: connection,
                continuation: continuation
            )
            connection.remoteObjectInterface = NSXPCInterface(
                with: (any SAFAAskPassBrokerXPC).self
            )
            connection.setCodeSigningRequirement(requirement)
            connection.interruptionHandler = {
                box.fail(AskPassRuntimeError.brokerUnavailable)
            }
            connection.invalidationHandler = {
                box.fail(AskPassRuntimeError.brokerUnavailable)
            }
            connection.resume()
            guard
                let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in
                    box.fail(AskPassRuntimeError.brokerUnavailable)
                }) as? any SAFAAskPassBrokerXPC
            else {
                box.fail(AskPassRuntimeError.brokerUnavailable)
                return
            }
            proxy.consumeCredential(request) { data in
                do {
                    let reply = try CanonicalCodec.decode(
                        AskPassReply.self,
                        from: data,
                        maxBytes: 32_768
                    )
                    guard reply.protocolVersion == IPCHeader.currentVersion,
                        reply.errorCode == nil,
                        let credential = reply.credential
                    else {
                        throw AskPassRuntimeError.invalidBinding
                    }
                    box.succeed(credential)
                } catch {
                    box.fail(error)
                }
            }
        }
    }
}

public enum SAFAAskPassRuntime {
    public static func main() async -> Never {
        guard let binding = ProcessInfo.processInfo.environment["SAFA_CHILD_BINDING"] else {
            Foundation.exit(45)
        }
        do {
            let response = try await AskPassResponder(client: XPCAskPassCredentialClient())
                .response(binding: binding, parentPID: getppid())
            FileHandle.standardOutput.write(response)
            FileHandle.standardOutput.write(Data([0x0A]))
            Foundation.exit(0)
        } catch {
            Foundation.exit(43)
        }
    }
}
