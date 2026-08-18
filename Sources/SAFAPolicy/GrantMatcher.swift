import Foundation
import SAFADomain

public enum GrantRejection: String, Equatable, Sendable {
    case grantInactive = "grant_inactive"
    case grantMalformed = "grant_malformed"
    case invalidExactGrant = "invalid_exact_grant"
    case invalidPrefixGrant = "invalid_prefix_grant"
    case requestStateInvalid = "request_state_invalid"
    case requestMalformed = "request_malformed"
    case requestExpired = "request_expired"
    case wallClockRollback = "wall_clock_rollback"
    case wallClockExpired = "wall_clock_expired"
    case monotonicClockRollback = "monotonic_clock_rollback"
    case monotonicClockExpired = "monotonic_clock_expired"
    case callerMismatch = "caller_mismatch"
    case resourceMismatch = "resource_mismatch"
    case resourceRevisionMismatch = "resource_revision_mismatch"
    case privilegeExceeded = "privilege_exceeded"
    case policyVersionMismatch = "policy_version_mismatch"
    case useLimitReached = "use_limit_reached"
    case scopeMismatch = "scope_mismatch"
}

public enum GrantMatchResult: Equatable, Sendable {
    case authorized
    case rejected(GrantRejection)
}

public struct GrantMatcher: Sendable {
    private static let clockToleranceNanoseconds: UInt64 = 5_000_000_000
    private let canonicalizer: CommandCanonicalizer

    public init(canonicalizer: CommandCanonicalizer = CommandCanonicalizer()) {
        self.canonicalizer = canonicalizer
    }

    public func match(
        grant: ApprovalGrant,
        request: ExecutionRequest,
        policyVersion: String,
        now: Date,
        monotonicNowNanoseconds: UInt64
    ) -> GrantMatchResult {
        guard grant.state == .active else {
            return .rejected(.grantInactive)
        }
        guard grant.expiresAt > grant.issuedAt,
            grant.monotonicDeadlineNanoseconds > 0
        else {
            return .rejected(.grantMalformed)
        }
        switch grant.scope {
        case .exact:
            guard grant.maxUses == 1 else {
                return .rejected(.invalidExactGrant)
            }
        case let .prefix(arguments):
            guard isValidPrefix(arguments) else {
                return .rejected(.invalidPrefixGrant)
            }
        case .fullAccess:
            break
        }

        guard request.state == .evaluating || request.state == .awaitingApproval else {
            return .rejected(.requestStateInvalid)
        }
        guard let canonicalCommand = try? canonicalizer.canonicalize(request.command) else {
            return .rejected(.requestMalformed)
        }
        guard request.deadline > request.createdAt, request.deadline > now else {
            return .rejected(.requestExpired)
        }
        guard now >= grant.issuedAt, now >= request.createdAt else {
            return .rejected(.wallClockRollback)
        }
        guard now < grant.expiresAt else {
            return .rejected(.wallClockExpired)
        }
        guard let monotonicIssuedAt = inferredMonotonicIssuedAt(for: grant) else {
            return .rejected(.grantMalformed)
        }
        guard
            monotonicNowNanoseconds >= monotonicIssuedAt
                || monotonicIssuedAt - monotonicNowNanoseconds
                    <= Self.clockToleranceNanoseconds
        else {
            return .rejected(.monotonicClockRollback)
        }
        guard monotonicNowNanoseconds < grant.monotonicDeadlineNanoseconds else {
            return .rejected(.monotonicClockExpired)
        }
        let monotonicElapsed =
            monotonicNowNanoseconds >= monotonicIssuedAt
            ? monotonicNowNanoseconds - monotonicIssuedAt : 0
        guard let wallElapsed = nanoseconds(from: now.timeIntervalSince(grant.issuedAt)) else {
            return .rejected(.grantMalformed)
        }
        guard monotonicElapsed <= wallElapsed + Self.clockToleranceNanoseconds else {
            return .rejected(.wallClockRollback)
        }
        guard grant.callerBinding == request.caller else {
            return .rejected(.callerMismatch)
        }
        guard grant.resourceID == request.resourceID else {
            return .rejected(.resourceMismatch)
        }
        guard grant.resourceRevision == request.resourceRevision else {
            return .rejected(.resourceRevisionMismatch)
        }
        guard permits(grant.privilegeCeiling, requested: request.privilege) else {
            return .rejected(.privilegeExceeded)
        }
        guard grant.policyVersion == policyVersion else {
            return .rejected(.policyVersionMismatch)
        }
        if let maximumUses = grant.maxUses, grant.uses >= maximumUses {
            return .rejected(.useLimitReached)
        }
        guard scopeMatches(grant.scope, command: request.command, canonical: canonicalCommand)
        else {
            return .rejected(.scopeMismatch)
        }
        return .authorized
    }

    private func isValidPrefix(_ arguments: [String]) -> Bool {
        guard !arguments.isEmpty else { return false }
        return (try? canonicalizer.canonicalize(CommandSpec.exec(arguments: arguments))) != nil
    }

    private func inferredMonotonicIssuedAt(for grant: ApprovalGrant) -> UInt64? {
        let duration = grant.expiresAt.timeIntervalSince(grant.issuedAt)
        guard let durationNanoseconds = nanoseconds(from: duration), durationNanoseconds > 0 else {
            return nil
        }
        guard grant.monotonicDeadlineNanoseconds >= durationNanoseconds else { return nil }
        return grant.monotonicDeadlineNanoseconds - durationNanoseconds
    }

    private func nanoseconds(from duration: TimeInterval) -> UInt64? {
        let maximum = Double(UInt64.max - Self.clockToleranceNanoseconds) / 1_000_000_000
        guard duration.isFinite, duration >= 0, duration <= maximum else { return nil }
        return UInt64((duration * 1_000_000_000).rounded())
    }

    private func permits(_ ceiling: Privilege, requested: Privilege) -> Bool {
        switch (ceiling, requested) {
        case (.user, .user), (.sudo, .user), (.sudo, .sudo):
            true
        case (.user, .sudo):
            false
        }
    }

    private func scopeMatches(
        _ scope: ApprovalScope,
        command: CommandSpec,
        canonical: CanonicalCommand
    ) -> Bool {
        switch scope {
        case let .exact(expectedFingerprint):
            return canonical.fingerprint == expectedFingerprint
        case let .prefix(prefix):
            guard command.mode == .exec,
                command.stdinMode == .none,
                !command.tty,
                command.workingDirectory == nil,
                let arguments = command.arguments,
                arguments.count >= prefix.count
            else {
                return false
            }
            return Array(arguments.prefix(prefix.count)) == prefix
        case .fullAccess:
            return true
        }
    }
}
