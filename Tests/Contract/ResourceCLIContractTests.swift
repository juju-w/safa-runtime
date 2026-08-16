import Foundation
import SAFADomain
import SAFAProtocol
import Testing

@Suite("Safe resource CLI projection")
struct ResourceCLIContractTests {
    @Test("resource list exposes only logical operational metadata")
    func safeProjection() throws {
        let resource = TestResourceFactory.active(alias: "nas.home")
        let registry = try ResourceRegistry(resources: [resource])
        let projection = try #require(registry.list(state: .active).first)
        let bytes = try CanonicalCodec.encode(projection)
        let text = try #require(String(data: bytes, encoding: .utf8))

        #expect(projection.alias.rawValue == "nas.home")
        #expect(projection.capabilities == ["exec"])
        #expect(!text.contains("203.0.113.10"))
        #expect(!text.contains("diagnostic-user"))
        #expect(!text.contains(resource.id.uuidString))
        #expect(!text.contains(resource.authRef!.uuidString))
    }

    @Test("unknown aliases produce a non-secret not-found error")
    func unknownResource() throws {
        let registry = try ResourceRegistry(resources: [])
        #expect(throws: ResourceRegistryError.notFound(alias: "missing.host")) {
            try registry.resource(alias: ResourceAlias("missing.host"))
        }
    }
}

enum TestResourceFactory {
    static func active(alias: String) -> Resource {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        return Resource(
            id: UUID(uuidString: "10000000-0000-4000-8000-000000000001")!,
            alias: try! ResourceAlias(alias),
            endpoint: ResourceEndpoint(host: "203.0.113.10", port: 2222),
            username: "diagnostic-user",
            securityDomain: "synthetic",
            hostIdentity: HostIdentity(
                algorithm: "ssh-ed25519",
                publicKey: Data(repeating: 7, count: 32),
                fingerprint: "SHA256:synthetic",
                verifiedAt: now,
                verificationMethod: .manual,
                status: .trusted
            ),
            authRef: UUID(uuidString: "20000000-0000-4000-8000-000000000001"),
            revision: 1,
            state: .active,
            createdAt: now,
            updatedAt: now
        )
    }
}
