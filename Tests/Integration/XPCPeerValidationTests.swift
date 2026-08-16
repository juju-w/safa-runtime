import SAFABroker
import Testing

@Suite("XPC peer validation")
struct XPCPeerValidationTests {
    private let policy = PeerValidationPolicy(
        brokerUserID: 501,
        auditSessionID: 77,
        teamIdentifier: "TESTTEAM1",
        agentSigningIdentifiers: ["dev.safa.cli", "dev.safa.askpass"],
        trustedAppSigningIdentifier: "dev.safa.app"
    )

    @Test("the exact signed same-user Agent peer is accepted")
    func acceptsExactAgent() throws {
        let evidence = PeerIdentityEvidence(
            effectiveUserID: 501,
            auditSessionID: 77,
            signingIdentifier: "dev.safa.cli",
            teamIdentifier: "TESTTEAM1"
        )

        let identity = try PeerValidator(policy: policy).validate(evidence, as: .agent)
        #expect(identity.signingIdentifier == "dev.safa.cli")
        #expect(identity.effectiveUserID == 501)
    }

    @Test(
        "unsigned, wrong-user, wrong-session, wrong-team, and role-confused peers fail closed",
        arguments: [
            PeerIdentityEvidence(
                effectiveUserID: 501,
                auditSessionID: 77,
                signingIdentifier: nil,
                teamIdentifier: nil
            ),
            PeerIdentityEvidence(
                effectiveUserID: 0,
                auditSessionID: 77,
                signingIdentifier: "dev.safa.cli",
                teamIdentifier: "TESTTEAM1"
            ),
            PeerIdentityEvidence(
                effectiveUserID: 501,
                auditSessionID: 99,
                signingIdentifier: "dev.safa.cli",
                teamIdentifier: "TESTTEAM1"
            ),
            PeerIdentityEvidence(
                effectiveUserID: 501,
                auditSessionID: 77,
                signingIdentifier: "dev.safa.cli",
                teamIdentifier: "ATTACKER1"
            ),
            PeerIdentityEvidence(
                effectiveUserID: 501,
                auditSessionID: 77,
                signingIdentifier: "dev.safa.app",
                teamIdentifier: "TESTTEAM1"
            ),
        ]
    )
    func rejectsUnauthorizedPeer(_ evidence: PeerIdentityEvidence) {
        #expect(throws: PeerValidationError.self) {
            try PeerValidator(policy: policy).validate(evidence, as: .agent)
        }
    }

    @Test("the trusted app cannot be substituted with the Agent CLI")
    func separatesTrustedAppAuthority() {
        let evidence = PeerIdentityEvidence(
            effectiveUserID: 501,
            auditSessionID: 77,
            signingIdentifier: "dev.safa.cli",
            teamIdentifier: "TESTTEAM1"
        )
        #expect(throws: PeerValidationError.self) {
            try PeerValidator(policy: policy).validate(evidence, as: .trustedApp)
        }
    }
}
