import Foundation

public enum ResourceRegistryError: Error, Equatable, Sendable {
    case duplicateAlias(alias: String)
    case notFound(alias: String)
}

public enum ResourceHealth: String, Codable, Sendable {
    case ready
    case needsSetup = "needs_setup"
    case disabled
}

public struct SafeResourceProjection: Codable, Equatable, Sendable {
    public let alias: ResourceAlias
    public let transport: TransportKind
    public let state: ResourceState
    public let capabilities: [String]
    public let health: ResourceHealth

    public init(resource: Resource) {
        alias = resource.alias
        transport = resource.transport
        state = resource.state
        var values = ["exec"]
        if resource.sudoRef != nil { values.append("sudo") }
        capabilities = values
        if resource.state == .disabled || resource.state == .deleted {
            health = .disabled
        } else if resource.state == .active,
            resource.authRef != nil,
            resource.hostIdentity?.status == .trusted
        {
            health = .ready
        } else {
            health = .needsSetup
        }
    }
}

public struct ResourceRegistry: Sendable {
    private let resourcesByAlias: [ResourceAlias: Resource]

    public init(resources: [Resource]) throws {
        var index: [ResourceAlias: Resource] = [:]
        for resource in resources where resource.state != .deleted {
            guard index.updateValue(resource, forKey: resource.alias) == nil else {
                throw ResourceRegistryError.duplicateAlias(alias: resource.alias.rawValue)
            }
        }
        resourcesByAlias = index
    }

    public func list(state: ResourceState? = nil) -> [SafeResourceProjection] {
        resourcesByAlias.values
            .filter { state == nil || $0.state == state }
            .sorted { $0.alias.rawValue < $1.alias.rawValue }
            .map(SafeResourceProjection.init)
    }

    public func resource(alias: ResourceAlias) throws -> Resource {
        guard let resource = resourcesByAlias[alias] else {
            throw ResourceRegistryError.notFound(alias: alias.rawValue)
        }
        return resource
    }
}
