public enum SAFAProcessExit: Int32, Sendable {
    case success = 0
    case remoteFailure = 10
    case pending = 20
    case approvalRequired = 21
    case userActionRequired = 22
    case denied = 30
    case cancelled = 31
    case expired = 32
    case invalidInvocation = 40
    case notFound = 41
    case vaultUnavailable = 42
    case securityFailure = 43
    case transportFailure = 44
    case runtimeFailure = 45
    case unexpected = 70

    public static func map(status: CLIStatus, remoteExitCode: Int32? = nil) -> Self {
        switch status {
        case .completed:
            if let remoteExitCode, remoteExitCode != 0 { return .remoteFailure }
            return .success
        case .accepted: return .pending
        case .approvalRequired: return .approvalRequired
        case .userActionRequired: return .userActionRequired
        case .denied: return .denied
        case .cancelled: return .cancelled
        case .expired: return .expired
        case .failed: return .unexpected
        }
    }
}
