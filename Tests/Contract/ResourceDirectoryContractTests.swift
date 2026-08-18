import Foundation
import SAFADomain
import SAFAProtocol
import Testing

@Suite("Resource directory v1 wire contract")
struct ResourceDirectoryContractTests {
    @Test("request uses an explicit versioned action schema")
    func requestKeys() throws {
        let date = Date(timeIntervalSince1970: 1_700_000_000)
        let request = ResourceDirectoryRequestV1(
            header: IPCHeader(
                messageID: UUID(uuidString: "10000000-0000-4000-8000-000000000001")!,
                sentAt: date,
                deadline: date.addingTimeInterval(30)
            ),
            action: .inspect,
            alias: try ResourceAlias("gpu.lab")
        )

        let object = try #require(
            JSONSerialization.jsonObject(with: CanonicalCodec.encode(request))
                as? [String: Any]
        )
        #expect(Set(object.keys) == ["header", "action", "alias"])
        #expect(object["action"] as? String == "inspect")
        #expect(object["alias"] as? String == "gpu.lab")
    }

    @Test("resource mutation imports only by logical SSH config alias")
    func mutationRequestDoesNotCarryPrivateConnectionMaterial() throws {
        let date = Date(timeIntervalSince1970: 1_700_000_000)
        let request = ResourceMutationRequestV1(
            header: IPCHeader(sentAt: date, deadline: date.addingTimeInterval(30)),
            action: .add,
            alias: try ResourceAlias("nas.home"),
            mutation: ResourceMutationV1(
                sourceSSHConfigAlias: try ResourceAlias("home-nas"),
                resourceType: .hostLinux
            )
        )

        let text = try #require(
            String(data: CanonicalCodec.encode(request), encoding: .utf8)
        )
        #expect(text.contains("home-nas"))
        #expect(text.contains("host.linux"))
        #expect(!text.contains("display_name"))
        #expect(!text.contains("endpoint"))
        #expect(!text.contains("username"))
        #expect(!text.contains("password"))
        #expect(!text.contains("private_key"))
        #expect(!text.contains("sudo"))
    }

    @Test("resource edit state is explicit and carries no private connection material")
    func editStateRequestIsSafe() throws {
        let date = Date(timeIntervalSince1970: 1_700_000_000)
        let request = ResourceMutationRequestV1(
            header: IPCHeader(sentAt: date, deadline: date.addingTimeInterval(30)),
            action: .edit,
            alias: try ResourceAlias("nas.home"),
            mutation: ResourceMutationV1(
                sourceSSHConfigAlias: try ResourceAlias("home-nas"),
                desiredState: .disabled
            )
        )

        let text = try #require(
            String(data: CanonicalCodec.encode(request), encoding: .utf8)
        )
        #expect(text.contains(#""action":"edit""#))
        #expect(text.contains(#""desired_state":"disabled""#))
        #expect(!text.contains("endpoint"))
        #expect(!text.contains("username"))
        #expect(!text.contains("password"))
        #expect(!text.contains("credential"))
    }

    @Test("public summary cannot encode connection or credential material")
    func publicSummaryIsSafe() throws {
        let summary = ResourceSummaryV1(
            alias: "gpu.lab",
            displayName: "GPU worker",
            resourceType: "host.linux",
            kind: "host",
            templateID: "ssh",
            templateVersion: 1,
            hostPlatform: "linux",
            roles: ["gpu"],
            state: "active",
            health: "ready",
            capabilities: ["exec"],
            metadata: [
                ResourceMetadataEntryV1(
                    key: "host.os.family",
                    value: .text("linux")
                )
            ]
        )
        let text = try #require(
            String(data: CanonicalCodec.encode(summary), encoding: .utf8)
        )

        #expect(!text.contains("endpoint"))
        #expect(!text.contains("username"))
        #expect(!text.contains("credential"))
        #expect(!text.contains("fingerprint"))
        #expect(!text.contains("public_key"))
    }

    @Test("authorized details remain non-secret and explicitly typed")
    func protectedDetailsAreTypedAndNonSecret() throws {
        let details = ResourceDetailsV1(
            alias: "gpu.lab",
            displayName: "GPU worker",
            resourceType: "host.linux",
            kind: "host",
            templateID: "ssh",
            templateVersion: 1,
            hostPlatform: "linux",
            roles: ["gpu"],
            alternateAliases: ["gpu-worker"],
            accessMethods: ["ssh"],
            state: "active",
            health: "ready",
            capabilities: ["exec", "sudo"],
            endpoint: ResourceEndpointV1(
                scheme: "ssh",
                host: "203.0.113.105",
                port: 8105,
                path: nil
            ),
            username: "operator",
            securityDomain: "production",
            metadata: [
                ResourceMetadataEntryV1(
                    key: "host.memory.total-bytes",
                    value: .byteCount(274_877_906_944)
                )
            ],
            relationships: [],
            hostIdentityStatus: "trusted",
            updatedAt: Date(timeIntervalSince1970: 1_700_000_000)
        )
        let text = try #require(
            String(data: CanonicalCodec.encode(details), encoding: .utf8)
        )

        #expect(text.contains("203.0.113.105"))
        #expect(text.contains("host.memory.total-bytes"))
        #expect(!text.contains("credential_id"))
        #expect(!text.contains("storage_locator"))
        #expect(!text.contains("public_key"))
        #expect(!text.contains("fingerprint"))
    }
}
