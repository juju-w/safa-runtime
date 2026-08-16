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

    public static func map(errorCode: String?) -> Self {
        switch errorCode {
        case "invalid_invocation", "invalid_message", "message_expired", "message_too_large",
            "resource_alias_required", "resource_mutation_required", "resource_adapter_unsupported",
            "resource_alias_conflict", "resource_mutation_invalid", "resource_query_invalid",
            "ssh_config_alias_not_found", "ssh_config_invalid":
            .invalidInvocation
        case "resource_not_found":
            .notFound
        case "vault_locked", "vault_unavailable":
            .vaultUnavailable
        case "resource_not_ready", "host_identity_changed", "resource_retarget_requires_setup",
            "resource_still_referenced", "resource_state_invalid", "resource_revision_conflict":
            .securityFailure
        case "transport_failure", "ssh_config_timeout":
            .transportFailure
        case "broker_unavailable", "ssh_config_unavailable", "resource_lifecycle_unavailable":
            .runtimeFailure
        default:
            .unexpected
        }
    }
}
