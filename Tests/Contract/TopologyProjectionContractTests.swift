import Foundation
import SAFADomain
import SAFAProtocol
import Testing

@Suite("Topology projection v1 wire contract")
struct TopologyProjectionContractTests {
    @Test("canonical CLI fixtures decode into the typed projection")
    func canonicalFixtures() throws {
        let path = try loadProjectionFixture("topology.path.completed.json")
        #expect(path.task == .reachability)
        #expect(path.answer.outcome == .confirmed)
        #expect(path.answer.proofEdgeIDs == ["20000000-0000-4000-8000-000000000001"])

        let impact = try loadProjectionFixture("topology.impact.completed.json")
        #expect(impact.task == .dependencyImpact)
        #expect(impact.answer.affectedAliases == ["service.data-api"])
    }

    @Test("query request is explicit and bounded")
    func queryRequestShape() throws {
        let date = Date(timeIntervalSince1970: 1_700_000_000)
        let request = TopologyQueryRequestV1(
            header: IPCHeader(sentAt: date, deadline: date.addingTimeInterval(30)),
            task: .reachability,
            source: try ResourceAlias("host.compute-a"),
            target: try ResourceAlias("service.data-api"),
            bounds: TopologyQueryBoundsV1(maximumHops: 6, maximumNodes: 64, maximumEdges: 128)
        )
        let object = try #require(
            JSONSerialization.jsonObject(with: CanonicalCodec.encode(request)) as? [String: Any]
        )

        #expect(
            Set(object.keys) == ["header", "task", "source", "target", "bounds"])
        #expect(object["task"] as? String == "reachability")
        #expect(object["source"] as? String == "host.compute-a")
        #expect(object["target"] as? String == "service.data-api")
        #expect(
            !String(decoding: try CanonicalCodec.encode(request), as: UTF8.self).contains(
                "endpoint"))
    }

    @Test("projection uses a simple answer before structural evidence")
    func projectionShape() throws {
        let projection = TopologyProjectionV1(
            graphRevision: 7,
            task: .reachability,
            ordering: .sourceRootedBreadthFirst,
            roots: ["host.compute-a", "service.data-api"],
            nodes: [
                TopologyNodeV1(alias: "host.compute-a", kind: "resource", resourceKind: "host"),
                TopologyNodeV1(
                    alias: "service.data-api", kind: "resource", resourceKind: "service"),
            ],
            edges: [
                TopologyEdgeV1(
                    id: "20000000-0000-4000-8000-000000000001",
                    from: "host.compute-a",
                    relation: "can-reach",
                    to: "service.data-api",
                    layer: "derived",
                    verification: "verified",
                    freshness: "fresh"
                )
            ],
            answer: TopologyAnswerV1(
                outcome: .confirmed,
                source: "host.compute-a",
                target: "service.data-api",
                affectedAliases: [],
                proofEdgeIDs: ["20000000-0000-4000-8000-000000000001"]
            ),
            matrix: nil,
            truncated: false
        )
        let text = try #require(
            String(data: CanonicalCodec.encode(projection), encoding: .utf8)
        )

        #expect(text.contains(#""schema":"dev.safa.topology/v1""#))
        #expect(text.contains(#""outcome":"confirmed""#))
        #expect(text.contains(#""proof_edge_ids""#))
        #expect(!text.contains("endpoint"))
        #expect(!text.contains("username"))
        #expect(!text.contains("evidence_reference"))
        #expect(!text.contains("credential"))
    }

    @Test("mutation cannot carry trust or credential claims")
    func mutationRequestIsOnlyALogicalClaim() throws {
        let date = Date(timeIntervalSince1970: 1_700_000_000)
        let request = TopologyMutationRequestV1(
            header: IPCHeader(sentAt: date, deadline: date.addingTimeInterval(30)),
            action: .link,
            source: try ResourceAlias("service.worker"),
            relation: .dependsOn,
            target: try ResourceAlias("service.data-api"),
            expectedGraphRevision: 4
        )
        let text = try #require(
            String(data: CanonicalCodec.encode(request), encoding: .utf8)
        )

        #expect(text.contains(#""action":"link""#))
        #expect(text.contains(#""relation":"depends-on""#))
        for forbidden in [
            "layer", "verification", "evidence", "credential", "endpoint", "username",
        ] {
            #expect(!text.contains(forbidden))
        }
    }

    @Test("unknown topology schemas fail closed")
    func unknownSchema() throws {
        let projection = TopologyProjectionV1(
            schema: "dev.safa.topology/v2",
            graphRevision: 0,
            task: .inventory,
            ordering: .aliasAscending,
            roots: [],
            nodes: [],
            edges: [],
            answer: TopologyAnswerV1(outcome: .listed),
            matrix: nil,
            truncated: false
        )

        #expect(throws: ProtocolCodecError.invalidSchema) {
            _ = try CanonicalCodec.decode(
                TopologyProjectionV1.self,
                from: CanonicalCodec.encode(projection)
            )
        }
    }

    @Test("dense and truncated projections keep an explicit bounded shape")
    func denseTruncatedShape() throws {
        let projection = TopologyProjectionV1(
            graphRevision: 12,
            task: .denseComparison,
            ordering: .aliasAscending,
            roots: [],
            nodes: [
                TopologyNodeV1(alias: "service.a", kind: "resource", resourceKind: "service"),
                TopologyNodeV1(alias: "service.b", kind: "resource", resourceKind: "service"),
            ],
            edges: [],
            answer: TopologyAnswerV1(outcome: .listed),
            matrix: TopologyMatrixV1(
                aliases: ["service.a", "service.b"],
                values: [[false, true], [false, false]]
            ),
            truncated: true
        )
        let decoded = try CanonicalCodec.decode(
            TopologyProjectionV1.self,
            from: CanonicalCodec.encode(projection)
        )

        #expect(decoded.matrix?.aliases == ["service.a", "service.b"])
        #expect(decoded.matrix?.values == [[false, true], [false, false]])
        #expect(decoded.truncated)
    }

    private func loadProjectionFixture(_ name: String) throws -> TopologyProjectionV1 {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let envelope = try CanonicalCodec.decode(
            CLIEnvelope.self,
            from: Data(contentsOf: root.appendingPathComponent("conformance/cli-v1/\(name)"))
        )
        guard case let .object(value)? = envelope.data["topology"] else {
            throw TopologyFixtureError.missingProjection
        }
        return try CanonicalCodec.decode(
            TopologyProjectionV1.self,
            from: CanonicalCodec.encode(JSONValue.object(value))
        )
    }
}

private enum TopologyFixtureError: Error {
    case missingProjection
}
