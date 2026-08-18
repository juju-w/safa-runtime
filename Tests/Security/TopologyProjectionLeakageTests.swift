import Foundation
import SAFADomain
import SAFAProtocol
import Testing

@Suite("Topology projection disclosure boundary")
struct TopologyProjectionLeakageTests {
    @Test("protected nodes, routes, and evidence never enter the Agent projection")
    func protectedGraphDataIsFiltered() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let visible = try TopologyNode(
            id: UUID(uuidString: "10000000-0000-4000-8000-000000000001")!,
            alias: ResourceAlias("service.public-view"),
            kind: .resource,
            resourceKind: ResourceKindIdentifier("service"),
            resourceID: UUID(uuidString: "10000000-0000-4000-8000-000000000001")!,
            visibility: .agent
        )
        let protected = try TopologyNode(
            id: UUID(uuidString: "10000000-0000-4000-8000-000000000002")!,
            alias: ResourceAlias("network.private-segment"),
            kind: .networkSegment,
            visibility: .protected
        )
        let evidenceID = UUID(uuidString: "30000000-0000-4000-8000-000000000001")!
        let edge = try TopologyEdge.observed(
            id: UUID(uuidString: "20000000-0000-4000-8000-000000000001")!,
            fromNodeID: visible.id,
            relation: .memberOf,
            toNodeID: protected.id,
            verification: .verified,
            origin: .adapter,
            observedAt: now,
            validUntil: now.addingTimeInterval(300),
            visibility: .protected,
            evidenceReference: evidenceID
        )
        let graph = try TopologyGraph(revision: 2, nodes: [visible, protected], edges: [edge])
        let result = try TopologyQueryEngine.query(
            graph: graph,
            query: .inventory(),
            now: now
        )
        let projection = TopologyProjectionV1(result)
        let text = String(decoding: try CanonicalCodec.encode(projection), as: UTF8.self)

        #expect(projection.nodes.map(\.alias) == ["service.public-view"])
        #expect(projection.edges.isEmpty)
        #expect(!text.contains("network.private-segment"))
        #expect(!text.contains(evidenceID.uuidString.lowercased()))
    }
}
