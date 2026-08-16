import Foundation
@preconcurrency import LocalAuthentication

public protocol UserPresenceAuthorizing: Sendable {
    func authorize(reason: String) async -> Bool
}

/// Uses the macOS-owned Touch ID / device passcode sheet. SAFA does not render
/// or receive the user's biometric or login credential.
public struct LocalAuthenticationUserPresenceAuthorizer: UserPresenceAuthorizing {
    public init() {}

    public func authorize(reason: String) async -> Bool {
        let context = LAContext()
        context.localizedCancelTitle = "Cancel"
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            return false
        }
        do {
            return try await context.evaluatePolicy(
                .deviceOwnerAuthentication,
                localizedReason: reason
            )
        } catch {
            return false
        }
    }
}
