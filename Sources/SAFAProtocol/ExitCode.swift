public enum AgentCLIProcessExitV2: Int32, Sendable {
    case success = 0
    case failure = 1
    case usage = 2

    public static func map(status: AgentCLIStatusV2) -> Self {
        switch status {
        case .completed, .accepted, .noOp:
            .success
        case .approvalRequired, .userActionRequired, .denied, .cancelled, .expired,
            .transportFailed, .remoteExecutionFailed, .failed:
            .failure
        }
    }
}
