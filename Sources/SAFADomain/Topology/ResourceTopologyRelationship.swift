import CryptoKit
import Foundation

public extension ResourceRelationshipKind {
    var topologyRelation: TopologyRelation? {
        switch self {
        case .hostedOn: .runsOn
        case .dependsOn: .dependsOn
        case .backedBy: .backedBy
        default: nil
        }
    }
}

public extension TopologyRelation {
    var resourceRelationshipKind: ResourceRelationshipKind? {
        switch self {
        case .runsOn: .hostedOn
        case .dependsOn: .dependsOn
        case .backedBy: .backedBy
        default: nil
        }
    }
}

struct ResourceTopologyRelationshipKey: Hashable {
    let sourceID: UUID
    let relation: TopologyRelation
    let targetID: UUID

    var stableEdgeID: UUID {
        var input = Data("dev.safa.resource-relationship/v1".utf8)
        input.append(contentsOf: sourceID.uuidString.lowercased().utf8)
        input.append(0)
        input.append(contentsOf: relation.rawValue.utf8)
        input.append(0)
        input.append(contentsOf: targetID.uuidString.lowercased().utf8)
        var bytes = Array(Insecure.SHA1.hash(data: input).prefix(16))
        bytes[6] = (bytes[6] & 0x0f) | 0x50
        bytes[8] = (bytes[8] & 0x3f) | 0x80
        return UUID(
            uuid: (
                bytes[0], bytes[1], bytes[2], bytes[3],
                bytes[4], bytes[5], bytes[6], bytes[7],
                bytes[8], bytes[9], bytes[10], bytes[11],
                bytes[12], bytes[13], bytes[14], bytes[15]
            )
        )
    }
}
