import SAFADomain
import Testing

@Suite("Resource metadata policy")
struct ResourceMetadataPolicyTests {
    @Test("unknown metadata is encrypted inventory but not Agent-visible detail")
    func unknownMetadataIsQuarantined() throws {
        let entry = try ResourceMetadataEntry(
            key: "service.future-status",
            value: .text("ready")
        )

        try ResourceMetadataPolicy.validateForPersistence([entry])

        #expect(ResourceMetadataPolicy.authorizedEntries(from: [entry]).isEmpty)
    }

    @Test("registered protected metadata has an exact key and value shape")
    func registeredProtectedMetadata() throws {
        let approved = [
            try ResourceMetadataEntry(key: "host.kernel.release", value: .text("6.8.0")),
            try ResourceMetadataEntry(key: "host.cpu.logical-count", value: .integer(64)),
            try ResourceMetadataEntry(
                key: "host.memory.total-bytes",
                value: .byteCount(274_877_906_944)
            ),
        ]
        let wrongType = try ResourceMetadataEntry(
            key: "host.cpu.logical-count",
            value: .text("64")
        )
        let corruptedText = try ResourceMetadataEntry(
            key: "host.docker.version",
            value: .text("Authorization: Bearer synthetic-token")
        )

        try ResourceMetadataPolicy.validateForPersistence(approved)

        #expect(ResourceMetadataPolicy.authorizedEntries(from: approved) == approved)
        #expect(ResourceMetadataPolicy.authorizedEntries(from: [wrongType]).isEmpty)
        #expect(ResourceMetadataPolicy.authorizedEntries(from: [corruptedText]).isEmpty)
    }

    @Test("reserved credential keys and obvious credential text are rejected")
    func credentialsAreRejected() throws {
        let cases = [
            try ResourceMetadataEntry(
                key: "service.api-token",
                value: .text("synthetic-secret")
            ),
            try ResourceMetadataEntry(
                key: "service.notes",
                value: .text("Authorization: Bearer synthetic-token")
            ),
            try ResourceMetadataEntry(
                key: "service.notes",
                value: .text("-----BEGIN PRIVATE KEY-----")
            ),
            try ResourceMetadataEntry(
                key: "service.notes",
                value: .text("https://operator:secret@example.invalid/status")
            ),
        ]

        for entry in cases {
            #expect(throws: ResourceMetadataPolicyError.self) {
                try ResourceMetadataPolicy.validateForPersistence([entry])
            }
        }
    }

    @Test("public summary metadata remains a closed source-reviewed schema")
    func publicSummarySchema() throws {
        let approved = try ResourceMetadataEntry(
            key: "host.os.family",
            value: .text("linux")
        )
        let invalid = try ResourceMetadataEntry(
            key: "host.os.family",
            value: .text("internal-build")
        )

        try ResourceMetadataPolicy.validateForPersistence([approved])

        #expect(ResourceSummaryDisclosure.publicEntries(from: [approved]) == [approved])
        #expect(throws: ResourceMetadataPolicyError.self) {
            try ResourceMetadataPolicy.validateForPersistence([invalid])
        }
    }
}
