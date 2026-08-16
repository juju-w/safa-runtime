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
        #expect(reply.details?.metadata.contains { $0.key == "database.replica-count" } == true)
        #expect(reply.details?.metadata.contains { $0.key == "host.keyboard.layout" } == true)
        #expect(reply.details?.metadata.contains { $0.key == "service.health" } == true)
        #expect(reply.details?.metadata.contains { $0.key == "service.documentation-url" } == true)
        #expect(reply.details?.metadata.contains { $0.key == "service.transport-status" } == true)
        #expect(reply.details?.metadata.contains { $0.key == "service.process-status" } == true)
        #expect(reply.details?.metadata.contains { $0.key == "service.artifact-digest" } == true)
        #expect(await authorizer.reasons == ["Inspect details for resource hm-105"])
        let text = try #require(
            String(data: CanonicalCodec.encode(reply), encoding: .utf8)
        )
        #expect(!text.contains("synthetic-fingerprint"))
        #expect(!text.contains("synthetic-api-secret"))
        #expect(!text.contains("synthetic-docker-secret"))
        #expect(!text.contains("synthetic-public-material"))
        #expect(!text.contains("synthetic-host-fingerprint"))
        #expect(!text.contains("synthetic-private-public-keypair"))
        #expect(!text.contains("synthetic-private-public-keypairs"))
        #expect(!text.contains("synthetic-private-key-locator"))
        #expect(!text.contains("synthetic-pem-material"))
        #expect(!text.contains("synthetic-certificate-material"))
        #expect(!text.contains("com.example.synthetic"))
        #expect(!text.contains("dXNlcjpwYXNz"))
        #expect(!text.contains("eyJhbGciOiJIUzI1NiJ9"))
        #expect(!text.contains("MIIBTDCB/6ADAgECAhQNU6SL"))
        #expect(!text.contains("YWRtaW46c2VjcmV0"))
        #expect(!text.contains("opaque-reference-42"))
        #expect(!text.contains("hunter2"))
        #expect(!text.contains("db-readonly.internal"))
        #expect(!text.contains("AAAAC3NzaC1lZDI1NTE5AAAAISyntheticPublicMaterial"))
        #expect(!text.contains("AAAAB3NzaSyntheticLegacyMaterial"))
        #expect(!text.contains("correct horse battery staple"))
        #expect(!text.contains("873901"))
        #expect(!text.contains("420731"))
        #expect(!text.contains("c3ludGhldGlj"))
        #expect(!text.contains("ABCDEFGHIJKLMNOP"))
        #expect(!text.contains("MC4CAQAwBQYDK2VwBCIEI"))
        #expect(!text.contains("MIGjMF8GCSqGSIb3DQEF"))
        #expect(!text.contains("MCowBQYDK2VwAyEA"))
        #expect(!text.contains("MEgCQQDO+8KOZfLsNVYt"))
        #expect(!text.contains("MC4CAQAwBQ YDK2VwBCIE"))
        #expect(!text.contains("MC4CAQAwBQYDK2VwBCIEIFAzV2A2yFQSoeeXJT6eOFT0d-fH"))
        #expect(!text.contains("AAAAC3NzaC1lZDI1NTE5AAAAIDFz4JJt"))
        #expect(!text.contains("MBQCAQMwDwYJKoZI"))
        #expect(!text.contains("hvcNAQcCoAIEAA=="))
        #expect(reply.details?.metadata.contains { $0.key == "service.headers" } == false)
        #expect(reply.details?.metadata.contains { $0.key == "service.fragment-flood" } == false)
        #expect(!text.contains("PuTTY-User-Key-File-3"))
        #expect(!text.contains("synthetic-private-ppk-material"))
        #expect(!text.contains("synthetic-private-mac"))
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
                try! ResourceMetadataEntry(
                    key: "host.docker.available",
                    value: .text("synthetic-docker-secret")
                ),
                try! ResourceMetadataEntry(
                    key: "service.api-token",
                    value: .text("synthetic-api-secret")
                ),
                try! ResourceMetadataEntry(
                    key: "ssh.public-key",
                    value: .text("ssh-ed25519 synthetic-public-material")
                ),
                try! ResourceMetadataEntry(
                    key: "host.fingerprint",
                    value: .text("SHA256:synthetic-host-fingerprint")
                ),
                try! ResourceMetadataEntry(
                    key: "ssh.keypair",
                    value: .text("synthetic-private-public-keypair")
                ),
                try! ResourceMetadataEntry(
                    key: "ssh.keypairs",
                    value: .text("synthetic-private-public-keypairs")
                ),
                try! ResourceMetadataEntry(
                    key: "ssh.identity-file",
                    value: .text("synthetic-private-key-locator")
                ),
                try! ResourceMetadataEntry(
                    key: "ssh.pem",
                    value: .text("synthetic-pem-material")
                ),
                try! ResourceMetadataEntry(
                    key: "ssh.certificate",
                    value: .text("synthetic-certificate-material")
                ),
                try! ResourceMetadataEntry(
                    key: "service.keychain",
                    value: .text("com.example.synthetic")
                ),
                try! ResourceMetadataEntry(
                    key: "service.authorization",
                    value: .text("Basic dXNlcjpwYXNz")
                ),
                try! ResourceMetadataEntry(
                    key: "service.auth-header",
                    value: .text("opaque-reference-42")
                ),
                try! ResourceMetadataEntry(
                    key: "service.configuration",
                    value: .text("Basic dXNlcjpwYXNz")
                ),
                try! ResourceMetadataEntry(
                    key: "service.runtime",
                    value: .text(
                        "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.deadbeef"
                    )
                ),
                try! ResourceMetadataEntry(
                    key: "service.compact-jwt",
                    value: .text(
                        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.deadbeef"
                    )
                ),
                try! ResourceMetadataEntry(
                    key: "service.headers",
                    value: .textList(["Basic", "dXNl", "cjpwYXNz"])
                ),
                try! ResourceMetadataEntry(
                    key: "database.passphrase",
                    value: .text("correct horse battery staple")
                ),
                try! ResourceMetadataEntry(
                    key: "service.passcode",
                    value: .text("873901")
                ),
                try! ResourceMetadataEntry(
                    key: "database.pin",
                    value: .text("420731")
                ),
                try! ResourceMetadataEntry(
                    key: "service.jwk",
                    value: .text(#"{"kty":"oct","k":"c3ludGhldGlj"}"#)
                ),
                try! ResourceMetadataEntry(
                    key: "service.runtime-config",
                    value: .text(#"{"kty":"oct","k":"c3ludGhldGlj"}"#)
                ),
                try! ResourceMetadataEntry(
                    key: "service.alpha-bearer",
                    value: .text("Authorization: Bearer ABCDEFGHIJKLMNOP")
                ),
                try! ResourceMetadataEntry(
                    key: "service.binary-config",
                    value: .text(
                        "MC4CAQAwBQYDK2VwBCIEIFAzV2A2yFQSoeeXJT6eOFT0d+fHXGbR3G2Eetp4eWI5"
                    )
                ),
                try! ResourceMetadataEntry(
                    key: "service.encrypted-config",
                    value: .text(
                        "MIGjMF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBBV+3Y2CBVtXSO7ursZ8YLDAgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQ/yY20LZR0Wy53ryidfpYGgRANRZZeU+qiyai0m/v38SdQmAlIWnyIDyjeigkSqNuILLh2OIwLDDFype8nVpuwD1cxCtp3zeKa2oyloA+cUH+Tw=="
                    )
                ),
                try! ResourceMetadataEntry(
                    key: "service.der-certificate",
                    value: .textList([
                        "MIIBTDCB/6ADAgECAhQNU6SL7ZiRRb2c2nHMfAbxK1/qVzAFBgMrZXAwHDEaMBgGA1UEAwwRc3ludGhldGljLmludmFsaWQwHhcNMjYwODE2MDg0NzE0WhcNMjYwODE3MDg0NzE0WjAcMRowGAYDVQQDDBFzeW50",
                        "aGV0aWMuaW52YWxpZDAqMAUGAytlcAMhANhvz6T7SomfyMONlzmOdGpUAA/oZGG1kaPgcuM9XxrMo1MwUTAdBgNVHQ4EFgQUpmdfUgngIDV/h5Y3y1TRQTKOI+EwHwYDVR0jBBgwFoAUpmdfUgngIDV/h5Y3y1TR",
                        "QTKOI+EwDwYDVR0TAQH/BAUwAwEB/zAFBgMrZXADQQA0LZRmhlONVtG02Vz4wcA8sf0wGaTfbNziQK6mlaDbDdgy/KS/ytGjtEZ4UkLmPBUAkB90iDEG163lYS6ZUeED",
                    ])
                ),
                try! ResourceMetadataEntry(
                    key: "service.pkcs12-container",
                    value: .textList([
                        "MBQCAQMwDwYJKoZI",
                        "hvcNAQcBoAIEAA==",
                    ])
                ),
                try! ResourceMetadataEntry(
                    key: "service.signed-pkcs12-container",
                    value: .textList([
                        "MBQCAQMwDwYJKoZI",
                        "hvcNAQcCoAIEAA==",
                    ])
                ),
                try! ResourceMetadataEntry(
                    key: "service.public-material",
                    value: .text(
                        "MCowBQYDK2VwAyEAMXPgkm0Ch5sng3bHqTw6+kibp0nmIuej4RUH62qb+5w="
                    )
                ),
                try! ResourceMetadataEntry(
                    key: "service.rsa-public-material",
                    value: .text(
                        "MEgCQQDO+8KOZfLsNVYtf8cyybQc9C77wN2oMdwZJ/3lNf55FlEnoiOdMDnGSfIuY8ka4ps4Dy2ODnHuReF+EwYi/xeDAgMBAAE="
                    )
                ),
                try! ResourceMetadataEntry(
                    key: "service.grouped-config",
                    value: .text(
                        "MC4CAQAwBQ YDK2VwBCIE IFAzV2A2yF QSoeeXJT6e OFT0d+fHXG bR3G2Eetp4 eWI5"
                    )
                ),
                try! ResourceMetadataEntry(
                    key: "service.url-safe-config",
                    value: .text(
                        "MC4CAQAwBQYDK2VwBCIEIFAzV2A2yFQSoeeXJT6eOFT0d-fHXGbR3G2Eetp4eWI5"
                    )
                ),
                try! ResourceMetadataEntry(
                    key: "service.ssh-wire-config",
                    value: .text(
                        "AAAAC3NzaC1lZDI1NTE5AAAAIDFz4JJtAoebJ4N2x6k8OvpIm6dJ5iLno+EVB+tqm/uc"
                    )
                ),
                try! ResourceMetadataEntry(
                    key: "service.fragment-flood",
                    value: .text(String(repeating: "A ", count: 65))
                ),
                try! ResourceMetadataEntry(
                    key: "database.connection-string",
                    value: .text("postgresql://db-readonly.internal/app")
                ),
                try! ResourceMetadataEntry(
                    key: "service.endpoint-description",
                    value: .text("postgresql://operator:hunter2@db.internal/app")
                ),
                try! ResourceMetadataEntry(
                    key: "service.bootstrap",
                    value: .textList([
                        "ssh-ed25519",
                        "AAAAC3NzaC1lZDI1NTE5AAAAISyntheticPublicMaterial",
                    ])
                ),
                try! ResourceMetadataEntry(
                    key: "service.legacy-bootstrap",
                    value: .text("ssh-dss AAAAB3NzaSyntheticLegacyMaterial")
                ),
                try! ResourceMetadataEntry(
                    key: "database.replica-count",
                    value: .integer(2)
                ),
                try! ResourceMetadataEntry(
                    key: "host.keyboard.layout",
                    value: .text("us")
                ),
                try! ResourceMetadataEntry(
                    key: "service.health",
                    value: .text("uncertain")
                ),
                try! ResourceMetadataEntry(
                    key: "service.documentation-url",
                    value: .text("https://docs.example.invalid/health")
                ),
                try! ResourceMetadataEntry(
                    key: "service.transport-status",
                    value: .text("ssh-service running")
                ),
                try! ResourceMetadataEntry(
                    key: "service.process-status",
                    value: .text("bearer process active")
                ),
                try! ResourceMetadataEntry(
                    key: "service.artifact-digest",
                    value: .text(
                        "MDEwDQYJYIZIAWUDBAIBBQAEIBERERERERERERERERERERERERERERERERERERERERER"
                    )
                ),
                try! ResourceMetadataEntry(
                    key: "host.configuration",
                    value: .textList([
                        "PuTTY-User-Key-File-3: ssh-ed25519",
                        "Private-Lines: 1",
                        "synthetic-private-ppk-material",
                        "Private-MAC: synthetic-private-mac",
                    ])
                ),
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
