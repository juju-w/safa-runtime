import Foundation
import SAFAProtocol
import Testing

@Suite("CLI v1 envelope contract")
struct CLIEnvelopeContractTests {
    @Test("Swift matches the canonical version fixture")
    func canonicalVersionFixture() throws {
        let repositoryRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let fixtureData = try Data(
            contentsOf:
                repositoryRoot
                .appendingPathComponent("conformance")
                .appendingPathComponent("cli-v1")
                .appendingPathComponent("version.completed.json")
        )
        let fixture = try CanonicalCodec.decode(CLIEnvelope.self, from: fixtureData)
        let expected = CLIEnvelope(
            command: "version",
            status: .completed,
            timestamp: Date(timeIntervalSince1970: 1_786_872_600),
            data: [
                "runtime_version": .string("0.0.0"),
                "cli_schema": .string("dev.safa.cli/v1"),
                "platform": .string("linux"),
            ]
        )

        #expect(fixture == expected)
    }

    @Test("envelope uses stable snake-case keys and UTC timestamps")
    func envelopeEncoding() throws {
        let envelope = CLIEnvelope(
            command: "resource.list",
            status: .completed,
            requestID: UUID(uuidString: "018f0000-0000-7000-8000-000000000001"),
            timestamp: Date(timeIntervalSince1970: 1_776_336_600),
            data: ["resources": .array([])],
            warnings: [],
            nextAction: nil
        )

        let encoded = try CanonicalCodec.encode(envelope)
        let object = try #require(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )

        #expect(object["schema"] as? String == "dev.safa.cli/v1")
        #expect(object["command"] as? String == "resource.list")
        #expect(object["request_id"] as? String == "018F0000-0000-7000-8000-000000000001")
        #expect(object["next_action"] is NSNull)
        #expect((object["timestamp"] as? String)?.hasSuffix("Z") == true)
    }

    @Test("stable errors expose only allowlisted details")
    func errorRoundTrip() throws {
        let error = SAFAErrorPayload(
            code: "resource_not_found",
            message: "The requested resource is not registered.",
            retryable: false,
            details: ["resource": .string("nas.home")],
            remediation: nil
        )
        let envelope = CLIEnvelope(
            command: "resource.show",
            status: .failed,
            data: ["error": .object(error.jsonObject)]
        )

        let decoded = try CanonicalCodec.decode(
            CLIEnvelope.self,
            from: CanonicalCodec.encode(envelope)
        )
        #expect(decoded == envelope)
    }

    @Test("oversized envelopes are rejected before decoding")
    func boundedDecoding() {
        let oversized = Data(repeating: 0x20, count: 129)
        #expect(throws: ProtocolCodecError.inputTooLarge(limit: 128)) {
            try CanonicalCodec.decode(CLIEnvelope.self, from: oversized, maxBytes: 128)
        }
    }

    @Test("unknown schema versions fail closed")
    func unknownSchema() throws {
        let envelope = CLIEnvelope(
            schema: "dev.safa.cli/v2",
            command: "version",
            status: .completed
        )
        #expect(throws: ProtocolCodecError.invalidSchema) {
            try CanonicalCodec.decode(CLIEnvelope.self, from: CanonicalCodec.encode(envelope))
        }
    }

    @Test("SAFA exit codes never overload the remote exit code")
    func exitMapping() {
        #expect(SAFAProcessExit.map(status: .completed, remoteExitCode: 0) == .success)
        #expect(SAFAProcessExit.map(status: .completed, remoteExitCode: 2) == .remoteFailure)
        #expect(SAFAProcessExit.map(status: .approvalRequired) == .approvalRequired)
        #expect(SAFAProcessExit.map(status: .userActionRequired) == .userActionRequired)
    }
}
