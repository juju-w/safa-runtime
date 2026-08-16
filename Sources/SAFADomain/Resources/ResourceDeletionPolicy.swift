import Foundation

public enum ResourceDeletionPolicyError: Error, Equatable, Sendable {
    case referencedBy(alias: String)
}

public enum ResourceDeletionPolicy {
    public static func validateRemoval(
        resourceID: UUID,
        from resources: [Resource]
    ) throws {
        for resource in resources where resource.state != .deleted && resource.id != resourceID {
            if resource.resolvedRelationships.contains(where: {
                $0.targetResourceID == resourceID
            }) {
                throw ResourceDeletionPolicyError.referencedBy(
                    alias: resource.alias.rawValue
                )
            }
        }
    }
}
