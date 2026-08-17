import Foundation

public extension TopologyGraph {
    func recordingObservation(
        source: ResourceAlias,
        relation: TopologyRelation,
        target: ResourceAlias,
        verification: TopologyVerification,
        observedAt: Date,
        validUntil: Date,
        origin: TopologyOrigin = .adapter,
        visibility: TopologyVisibility = .agent,
        evidenceReference: UUID
    ) throws -> Self {
        var updatedNodes = nodes
        let sourceNode: TopologyNode
        if let existing = updatedNodes.first(where: { $0.alias == source }) {
            sourceNode = existing
        } else {
            sourceNode = try TopologyNode.context(alias: source, visibility: visibility)
            updatedNodes.append(sourceNode)
        }
        guard let targetNode = updatedNodes.first(where: { $0.alias == target }) else {
            throw TopologyQueryError.aliasNotFound(target.rawValue)
        }
        let observation = try TopologyEdge.observed(
            fromNodeID: sourceNode.id,
            relation: relation,
            toNodeID: targetNode.id,
            verification: verification,
            origin: origin,
            observedAt: observedAt,
            validUntil: validUntil,
            visibility: visibility,
            evidenceReference: evidenceReference
        )
        var updatedEdges = edges.filter {
            !($0.layer == .observed
                && $0.origin == origin
                && $0.fromNodeID == sourceNode.id
                && $0.relation == relation
                && $0.toNodeID == targetNode.id)
        }
        updatedEdges.append(observation)
        return try Self(
            revision: revision + 1,
            nodes: updatedNodes,
            edges: updatedEdges
        )
    }
}
