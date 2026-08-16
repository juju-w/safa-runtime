import Foundation
import SAFADomain
import SAFAProtocol
import Testing

@Suite("Canonical execution request fingerprints")
struct RequestFingerprintTests {
    private let caller = CallerIdentity(
        signingIdentifier: "dev.safa.cli",
        teamIdentifier: "TESTTEAM",
        effectiveUserID: 501,
        auditSessionID: 42,
        agentSession: "codex-task-1"
    )
    private let resourceID = UUID(uuidString: "018f0000-0000-7000-8000-000000000010")!

    @Test("equal authority produces the same SHA-256 digest")
    func stableFingerprint() throws {
        let command = try CommandSpec.exec(arguments: ["systemctl", "is-active", "nginx"])
        let material = RequestFingerprintMaterial(
            caller: caller,
            resourceID: resourceID,
            resourceRevision: 7,
            command: command,
            privilege: .user
        )

        let first = try CanonicalCodec.requestFingerprint(material)
        let second = try CanonicalCodec.requestFingerprint(material)
        #expect(first == second)
        #expect(first.count == 64)
        #expect(first.allSatisfy { $0.isHexDigit && !$0.isUppercase })
    }

    @Test("every authority-bearing mutation changes the digest")
    func mutationsChangeFingerprint() throws {
        let command = try CommandSpec.exec(arguments: ["systemctl", "is-active", "nginx"])
        let base = RequestFingerprintMaterial(
            caller: caller,
            resourceID: resourceID,
            resourceRevision: 7,
            command: command,
            privilege: .user
        )
        let sudo = RequestFingerprintMaterial(
            caller: caller,
            resourceID: resourceID,
            resourceRevision: 7,
            command: command,
            privilege: .sudo
        )
        let changedRevision = RequestFingerprintMaterial(
            caller: caller,
            resourceID: resourceID,
            resourceRevision: 8,
            command: command,
            privilege: .user
        )

        let baseDigest = try CanonicalCodec.requestFingerprint(base)
        #expect(try CanonicalCodec.requestFingerprint(sudo) != baseDigest)
        #expect(try CanonicalCodec.requestFingerprint(changedRevision) != baseDigest)
    }
}
