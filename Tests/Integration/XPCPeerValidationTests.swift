import SAFABroker
import Testing

@Suite("XPC peer validation")
struct XPCPeerValidationTests {
    private let policy = PeerValidationPolicy(
        brokerUserID: 501,
        auditSessionID: 77,
        teamIdentifier: "TESTTEAM1",
        agentSigningIdentifiers: ["dev.safa.cli", "dev.safa.askpass"],
        trustedLocalSigningIdentifier: "dev.safa.trusted-local"
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
                signingIdentifier: "dev.safa.trusted-local",
                teamIdentifier: "TESTTEAM1"
            ),
        ]
    )
    func rejectsUnauthorizedPeer(_ evidence: PeerIdentityEvidence) {
        #expect(throws: PeerValidationError.self) {
            try PeerValidator(policy: policy).validate(evidence, as: .agent)
        }
    }

    @Test("the trusted local peer cannot be substituted with the Agent CLI")
    func separatesTrustedLocalAuthority() {
        let evidence = PeerIdentityEvidence(
            effectiveUserID: 501,
            auditSessionID: 77,
            signingIdentifier: "dev.safa.cli",
            teamIdentifier: "TESTTEAM1"
        )
        #expect(throws: PeerValidationError.self) {
            try PeerValidator(policy: policy).validate(evidence, as: .trustedLocal)
        }
    }
}
