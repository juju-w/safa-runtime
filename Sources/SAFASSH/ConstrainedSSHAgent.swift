import Foundation
import SAFACrypto

public enum ConstrainedSSHAgentError: Error, Equatable, Sendable {
    case unauthorizedChild
    case requestMismatch
    case expired
    case exhausted
}

public actor ConstrainedSSHAgent {
    private let key: SecureEnclaveSSHKey
    private let requestID: UUID
    private let childProcessID: Int32
    private let expiresAt: Date
    private var signaturesRemaining: UInt

    public init(
        key: SecureEnclaveSSHKey,
        requestID: UUID,
        childProcessID: Int32,
        expiresAt: Date,
        maximumSignatures: UInt = 8
    ) {
        self.key = key
        self.requestID = requestID
        self.childProcessID = childProcessID
        self.expiresAt = expiresAt
        signaturesRemaining = maximumSignatures
    }

    public func sign(
        _ message: Data,
        requestID: UUID,
        childProcessID: Int32,
        now: Date = Date()
    ) throws -> Data {
        guard requestID == self.requestID else {
            throw ConstrainedSSHAgentError.requestMismatch
        }
        guard childProcessID == self.childProcessID else {
            throw ConstrainedSSHAgentError.unauthorizedChild
        }
        guard now <= expiresAt else { throw ConstrainedSSHAgentError.expired }
        guard signaturesRemaining > 0 else { throw ConstrainedSSHAgentError.exhausted }
        signaturesRemaining -= 1
        return try key.sign(message)
    }
}
