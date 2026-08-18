import Foundation
import SAFADomain
import SAFAPolicy
import Testing

@Suite("Approval grant binding")
struct ApprovalBindingTests {
    private let matcher = GrantMatcher()
    private let canonicalizer = CommandCanonicalizer()
    private let now = Date(timeIntervalSince1970: 1_800_000_000)
    private let monotonicNow: UInt64 = 1_000_000_000_000
    private let resourceID = UUID(uuidString: "00000000-0000-0000-0000-000000000101")!
    private let caller = CallerIdentity(
        signingIdentifier: "dev.safa.cli",
        teamIdentifier: "TESTTEAM1",
        effectiveUserID: 501,
        auditSessionID: 77,
        agentSession: "agent-session-a"
    )

    @Test("an exact one-shot grant authorizes only the canonical command")
    func exactScope() throws {
        let command = try CommandSpec.exec(arguments: ["systemctl", "restart", "api"])
        let request = try makeRequest(command: command, privilege: .sudo)
        let fingerprint = try canonicalizer.canonicalize(command).fingerprint
        let grant = makeGrant(
            scope: .exact(fingerprint: fingerprint),
            privilegeCeiling: .sudo,
            maxUses: 1
        )

        #expect(match(grant, request) == .authorized)

        let mutated = try makeRequest(
            command: CommandSpec.exec(arguments: ["systemctl", "restart", "worker"]),
            privilege: .sudo
        )
        #expect(match(grant, mutated) == .rejected(.scopeMismatch))
    }

    @Test("caller, resource, revision, privilege, and policy bindings are exact")
    func authorityBindings() throws {
        let command = try CommandSpec.exec(arguments: ["uptime"])
        let request = try makeRequest(command: command)
        let grant = makeGrant(
            scope: .exact(fingerprint: try canonicalizer.canonicalize(command).fingerprint),
            maxUses: 1
        )

        let otherCaller = CallerIdentity(
            signingIdentifier: caller.signingIdentifier,
            teamIdentifier: caller.teamIdentifier,
            effectiveUserID: caller.effectiveUserID,
            auditSessionID: caller.auditSessionID + 1,
            agentSession: caller.agentSession
        )
        #expect(
            match(grant, try makeRequest(command: command, caller: otherCaller))
                == .rejected(.callerMismatch)
        )
        #expect(
            match(
                grant,
                try makeRequest(
                    command: command,
                    resourceID: UUID(uuidString: "00000000-0000-0000-0000-000000000102")!
                )
            ) == .rejected(.resourceMismatch)
        )
        #expect(
            match(grant, try makeRequest(command: command, resourceRevision: 8))
                == .rejected(.resourceRevisionMismatch)
        )
        #expect(
            match(grant, try makeRequest(command: command, privilege: .sudo))
                == .rejected(.privilegeExceeded)
        )
        #expect(
            matcher.match(
                grant: grant,
                request: request,
                policyVersion: "policy-v2",
                now: now,
                monotonicNowNanoseconds: monotonicNow
            ) == .rejected(.policyVersionMismatch)
        )
    }

    @Test("wall, monotonic, and rollback clocks all fail closed")
    func expiry() throws {
        let command = try CommandSpec.exec(arguments: ["uptime"])
        let request = try makeRequest(command: command)
        let scope = ApprovalScope.exact(
            fingerprint: try canonicalizer.canonicalize(command).fingerprint
        )

        #expect(
            match(
                makeGrant(scope: scope, maxUses: 1, expiresAt: now),
                request
            ) == .rejected(.wallClockExpired)
        )
        #expect(
            match(
                makeGrant(
                    scope: scope,
                    maxUses: 1,
                    monotonicDeadlineNanoseconds: monotonicNow
                ),
                request
            ) == .rejected(.monotonicClockExpired)
        )
        #expect(
            matcher.match(
                grant: makeGrant(scope: scope, maxUses: 1),
                request: request,
                policyVersion: "policy-v1",
                now: now.addingTimeInterval(-120),
                monotonicNowNanoseconds: monotonicNow
            ) == .rejected(.wallClockRollback)
        )
        #expect(
            matcher.match(
                grant: makeGrant(scope: scope, maxUses: 1),
                request: request,
                policyVersion: "policy-v1",
                now: now,
                monotonicNowNanoseconds: monotonicNow - 60_000_000_000
            ) == .rejected(.monotonicClockRollback)
        )
    }

    @Test("revoked, consumed, malformed, and replayed exact grants are rejected")
    func replayAndState() throws {
        let command = try CommandSpec.exec(arguments: ["uptime"])
        let request = try makeRequest(command: command)
        let scope = ApprovalScope.exact(
            fingerprint: try canonicalizer.canonicalize(command).fingerprint
        )

        #expect(
            match(makeGrant(scope: scope, maxUses: 1, state: .revoked), request)
                == .rejected(.grantInactive)
        )
        #expect(
            match(makeGrant(scope: scope, maxUses: 1, uses: 1), request)
                == .rejected(.useLimitReached)
        )
        #expect(
            match(makeGrant(scope: scope, maxUses: nil), request)
                == .rejected(.invalidExactGrant)
        )
        #expect(
            match(makeGrant(scope: .prefix(arguments: [])), request)
                == .rejected(.invalidPrefixGrant)
        )
    }

    @Test("prefix grants match argument boundaries and no additional execution authority")
    func prefixScope() throws {
        let grant = makeGrant(scope: .prefix(arguments: ["journalctl", "-u"]))
        #expect(
            match(
                grant,
                try makeRequest(
                    command: CommandSpec.exec(arguments: ["journalctl", "-u", "api", "-n", "20"])
                )
            ) == .authorized
        )
        #expect(
            match(
                grant,
                try makeRequest(command: CommandSpec.exec(arguments: ["journalctl", "-user"]))
            ) == .rejected(.scopeMismatch)
        )
        #expect(
            match(
                grant,
                try makeRequest(command: CommandSpec.shell(program: "journalctl -u api"))
            ) == .rejected(.scopeMismatch)
        )
        #expect(
            match(
                grant,
                try makeRequest(
                    command: CommandSpec.exec(
                        arguments: ["journalctl", "-u", "api"],
                        stdinMode: .boundedAgentData
                    )
                )
            ) == .rejected(.scopeMismatch)
        )
        #expect(
            match(
                grant,
                try makeRequest(
                    command: CommandSpec.exec(
                        arguments: ["journalctl", "-u", "api"],
                        workingDirectory: "/tmp"
                    )
                )
            ) == .rejected(.scopeMismatch)
        )
    }

    @Test("full access remains bound to the same caller, resource, privilege, and expiry")
    func fullAccess() throws {
        let grant = makeGrant(scope: .fullAccess, privilegeCeiling: .sudo)
        let request = try makeRequest(
            command: CommandSpec.shell(program: "journalctl -u api | tail -n 20"),
            privilege: .sudo
        )

        #expect(match(grant, request) == .authorized)
        #expect(
            match(
                grant,
                try makeRequest(
                    command: request.command,
                    resourceRevision: request.resourceRevision + 1,
                    privilege: .sudo
                )
            ) == .rejected(.resourceRevisionMismatch)
        )
    }

    @Test("expired and terminal requests cannot consume a grant")
    func requestLifecycle() throws {
        let command = try CommandSpec.exec(arguments: ["uptime"])
        let grant = makeGrant(
            scope: .exact(fingerprint: try canonicalizer.canonicalize(command).fingerprint),
            maxUses: 1
        )
        #expect(
            match(
                grant,
                try makeRequest(command: command, deadline: now)
            ) == .rejected(.requestExpired)
        )
        #expect(
            match(
                grant,
                try makeRequest(command: command, state: .completed)
            ) == .rejected(.requestStateInvalid)
        )
        #expect(
            match(
                makeGrant(scope: .fullAccess),
                try makeRequest(command: CommandSpec.exec(arguments: ["printf", "bad\0value"]))
            ) == .rejected(.requestMalformed)
        )
    }

    private func match(_ grant: ApprovalGrant, _ request: ExecutionRequest) -> GrantMatchResult {
        matcher.match(
            grant: grant,
            request: request,
            policyVersion: "policy-v1",
            now: now,
            monotonicNowNanoseconds: monotonicNow
        )
    }

    private func makeRequest(
        command: CommandSpec,
        caller: CallerIdentity? = nil,
        resourceID: UUID? = nil,
        resourceRevision: UInt64 = 7,
        privilege: Privilege = .user,
        state: RequestState = .evaluating,
        deadline: Date? = nil
    ) throws -> ExecutionRequest {
        ExecutionRequest(
            id: UUID(),
            caller: caller ?? self.caller,
            resourceID: resourceID ?? self.resourceID,
            resourceRevision: resourceRevision,
            command: command,
            privilege: privilege,
            intent: "synthetic test",
            fingerprint: "request-fingerprint",
            state: state,
            createdAt: now.addingTimeInterval(-30),
            deadline: deadline ?? now.addingTimeInterval(60)
        )
    }

    private func makeGrant(
        scope: ApprovalScope,
        caller: CallerIdentity? = nil,
        resourceID: UUID? = nil,
        resourceRevision: UInt64 = 7,
        privilegeCeiling: Privilege = .user,
        policyVersion: String = "policy-v1",
        maxUses: UInt? = nil,
        uses: UInt = 0,
        issuedAt: Date? = nil,
        expiresAt: Date? = nil,
        monotonicDeadlineNanoseconds: UInt64 = 1_600_000_000_000,
        state: GrantState = .active
    ) -> ApprovalGrant {
        ApprovalGrant(
            id: UUID(),
            capabilityHash: "sha256:synthetic-capability",
            scope: scope,
            callerBinding: caller ?? self.caller,
            resourceID: resourceID ?? self.resourceID,
            resourceRevision: resourceRevision,
            privilegeCeiling: privilegeCeiling,
            policyVersion: policyVersion,
            maxUses: maxUses,
            uses: uses,
            issuedAt: issuedAt ?? now.addingTimeInterval(-30),
            expiresAt: expiresAt ?? now.addingTimeInterval(600),
            monotonicDeadlineNanoseconds: monotonicDeadlineNanoseconds,
            approvalProof: ApprovalProof(
                method: "device_owner_authentication",
                authenticatedAt: now.addingTimeInterval(-30)
            ),
            state: state
        )
    }
}
