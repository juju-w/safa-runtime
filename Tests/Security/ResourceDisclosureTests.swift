import Foundation
import SAFABroker
import SAFACrypto
import SAFADomain
import SAFAProtocol
import SAFATestFixtures
import Testing

@Suite("Resource detail disclosure authorization")
struct ResourceDisclosureTests {
    @Test("list and show never request user presence")
    func publicQueriesDoNotPrompt() async throws {
        let authorizer = RecordingUserPresenceAuthorizer(result: false)
        let service = makeService(authorizer: authorizer)

        _ = await service.handle(
            request(action: .list),
            caller: .syntheticAgent,
            now: Date(timeIntervalSince1970: 1_700_000_000)
        )
        _ = await service.handle(
            request(action: .show, alias: "hm-105"),
            caller: .syntheticAgent,
            now: Date(timeIntervalSince1970: 1_700_000_001)
        )

        #expect(await authorizer.reasons.isEmpty)
    }

    @Test("denied inspect returns no protected resource object")
    func deniedInspectFailsClosed() async throws {
        let authorizer = RecordingUserPresenceAuthorizer(result: false)
        let service = makeService(authorizer: authorizer)

        let reply = await service.handle(
            request(action: .inspect, alias: "hm-105"),
            caller: .syntheticAgent,
            now: Date(timeIntervalSince1970: 1_700_000_000)
        )

        #expect(reply.status == .denied)
        #expect(reply.details == nil)
        #expect(reply.summaries.isEmpty)
        #expect(reply.error?.code == "resource_details_denied")
        let text = try #require(
            String(data: CanonicalCodec.encode(reply), encoding: .utf8)
        )
        #expect(!text.contains("203.0.113.105"))
        #expect(!text.contains("operator"))
    }

    @Test("approved inspect exposes inventory but never credentials or key material")
    func approvedInspect() async throws {
        let authorizer = RecordingUserPresenceAuthorizer(result: true)
        let service = makeService(authorizer: authorizer)

        let reply = await service.handle(
            request(action: .inspect, alias: "gpu-worker"),
            caller: .syntheticAgent,
            now: Date(timeIntervalSince1970: 1_700_000_000)
        )

        #expect(reply.status == .completed)
        #expect(reply.details?.alias == "hm-105")
        #expect(reply.details?.endpoint?.host == "203.0.113.105")
        #expect(reply.details?.metadata.contains { $0.key == "host.kernel.release" } == true)
        #expect(await authorizer.reasons == ["Inspect details for resource hm-105"])
        let text = try #require(
            String(data: CanonicalCodec.encode(reply), encoding: .utf8)
        )
        #expect(!text.contains("synthetic-fingerprint"))
        #expect(!text.contains("credential_id"))
        #expect(!text.contains("storage_locator"))
    }

    @Test("a denied prompt is rate limited to prevent agent prompt spam")
    func promptRateLimit() async throws {
        let authorizer = RecordingUserPresenceAuthorizer(result: false)
        let service = makeService(authorizer: authorizer)
        let now = Date(timeIntervalSince1970: 1_700_000_000)

        _ = await service.handle(
            request(action: .inspect, alias: "hm-105"),
            caller: .syntheticAgent,
            now: now
        )
        let second = await service.handle(
            request(action: .inspect, alias: "hm-105"),
            caller: .syntheticAgent,
            now: now.addingTimeInterval(1)
        )

        #expect(second.status == .denied)
        #expect(second.error?.code == "resource_details_rate_limited")
        #expect(await authorizer.reasons.count == 1)
    }

    private func makeService(
        authorizer: RecordingUserPresenceAuthorizer
    ) -> ResourceDirectoryService {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let resource = Resource(
            id: UUID(uuidString: "10000000-0000-4000-8000-000000000001")!,
            alias: try! ResourceAlias("hm-105"),
            resourceType: .hostLinux,
            alternateAliases: [try! ResourceAlias("gpu-worker")],
            accessMethods: [.ssh],
            metadata: [
                try! ResourceMetadataEntry(key: "host.os.family", value: .text("linux")),
                try! ResourceMetadataEntry(key: "host.kernel.release", value: .text("6.8.0")),
                try! ResourceMetadataEntry(key: "host.cpu.logical-count", value: .integer(64)),
                try! ResourceMetadataEntry(
                    key: "host.memory.total-bytes",
                    value: .byteCount(274_877_906_944)
                ),
                try! ResourceMetadataEntry(key: "host.docker.available", value: .boolean(true)),
            ],
            endpoint: ResourceEndpoint(scheme: "ssh", host: "203.0.113.105", port: 8105),
            username: "operator",
            securityDomain: "production",
            hostIdentity: HostIdentity(
                algorithm: "ssh-ed25519",
                publicKey: Data(repeating: 9, count: 32),
                fingerprint: "synthetic-fingerprint",
                verifiedAt: now,
                verificationMethod: .manual,
                status: .trusted
            ),
            authRef: UUID(),
            state: .active,
            createdAt: now,
            updatedAt: now
        )
        return ResourceDirectoryService(
            vault: InMemoryVaultDocumentStore(
                document: VaultDocument(schemaVersion: 1, resources: [resource])
            ),
            disclosureAuthorizer: ResourceDisclosureAuthorizationService(
                userPresenceAuthorizer: authorizer,
                cooldown: 5
            )
        )
    }

    private func request(
        action: ResourceDirectoryActionV1,
        alias: String? = nil
    ) -> ResourceDirectoryRequestV1 {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        return ResourceDirectoryRequestV1(
            header: IPCHeader(sentAt: now, deadline: now.addingTimeInterval(30)),
            action: action,
            alias: try! alias.map(ResourceAlias.init)
        )
    }
}

private actor RecordingUserPresenceAuthorizer: UserPresenceAuthorizing {
    private(set) var reasons: [String] = []
    private let result: Bool

    init(result: Bool) {
        self.result = result
    }

    func authorize(reason: String) async -> Bool {
        reasons.append(reason)
        return result
    }
}

extension CallerIdentity {
    fileprivate static let syntheticAgent = Self(
        signingIdentifier: "dev.safa.cli",
        teamIdentifier: "SYNTHETIC",
        effectiveUserID: 501,
        auditSessionID: 456,
        agentSession: "synthetic"
    )
}
