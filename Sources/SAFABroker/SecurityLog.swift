import Foundation
import OSLog

public struct SecurityLog: Sendable {
    private let logger: Logger

    public init(subsystem: String = "dev.safa.runtime", category: String = "security") {
        logger = Logger(subsystem: subsystem, category: category)
    }

    public func peerRejected(role: PeerRole, reason: PeerValidationError) {
        logger.warning(
            "XPC peer rejected role=\(role.rawValue, privacy: .public) reason=\(String(describing: reason), privacy: .public)"
        )
    }

    public func invalidMessage(role: PeerRole, code: String) {
        logger.warning(
            "XPC message rejected role=\(role.rawValue, privacy: .public) code=\(code, privacy: .public)"
        )
    }

    public func execution(
        alias: String,
        fingerprint: String,
        outcome: String
    ) {
        logger.info(
            "Execution alias=\(alias, privacy: .private(mask: .hash)) fingerprint=\(fingerprint, privacy: .public) outcome=\(outcome, privacy: .public)"
        )
    }
}
