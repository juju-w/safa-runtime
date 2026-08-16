import Foundation
import Security

public enum ChildCredentialBindingError: Error, Equatable, Sendable {
    case notFound
    case childMismatch
    case expired
    case alreadyConsumed
    case randomFailure
}

private struct ChildCredentialBinding: Sendable {
    let secret: Data
    let requestID: UUID
    var childProcessID: Int32
    let expiresAt: Date
    var consumed: Bool
}

public final class ChildCredentialBindingStore: @unchecked Sendable {
    private let condition = NSCondition()
    private var bindings: [String: ChildCredentialBinding] = [:]

    public init() {}

    @discardableResult
    public func issue(
        secret: Data,
        requestID: UUID,
        childProcessID: Int32,
        expiresAt: Date
    ) -> String {
        let byteCount = 32
        var bytes = Data(repeating: 0, count: byteCount)
        let status = bytes.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, byteCount, $0.baseAddress!)
        }
        precondition(status == errSecSuccess, "secure randomness is required")
        let token = bytes.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        condition.lock()
        bindings[token] = ChildCredentialBinding(
            secret: secret,
            requestID: requestID,
            childProcessID: childProcessID,
            expiresAt: expiresAt,
            consumed: false
        )
        condition.unlock()
        return token
    }

    public func bind(token: String, childProcessID: Int32) throws {
        condition.lock()
        defer { condition.unlock() }
        guard var binding = bindings[token] else {
            throw ChildCredentialBindingError.notFound
        }
        guard binding.childProcessID == 0 || binding.childProcessID == childProcessID else {
            throw ChildCredentialBindingError.childMismatch
        }
        binding.childProcessID = childProcessID
        bindings[token] = binding
        condition.broadcast()
    }

    public func consume(
        token: String,
        childProcessID: Int32,
        now: Date = Date()
    ) throws -> Data {
        condition.lock()
        defer { condition.unlock() }
        guard var binding = bindings[token] else {
            throw ChildCredentialBindingError.notFound
        }
        let bindingDeadline = min(binding.expiresAt, now.addingTimeInterval(1))
        while binding.childProcessID == 0, Date() < bindingDeadline {
            _ = condition.wait(until: bindingDeadline)
            guard let refreshed = bindings[token] else {
                throw ChildCredentialBindingError.notFound
            }
            binding = refreshed
        }
        guard binding.childProcessID == childProcessID else {
            throw ChildCredentialBindingError.childMismatch
        }
        guard binding.expiresAt >= Date() else {
            bindings.removeValue(forKey: token)
            throw ChildCredentialBindingError.expired
        }
        guard !binding.consumed else {
            throw ChildCredentialBindingError.alreadyConsumed
        }
        binding.consumed = true
        bindings[token] = binding
        return binding.secret
    }

    public func revoke(requestID: UUID) {
        condition.lock()
        bindings = bindings.filter { $0.value.requestID != requestID }
        condition.broadcast()
        condition.unlock()
    }
}
