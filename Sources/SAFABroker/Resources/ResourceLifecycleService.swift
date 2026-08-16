import Foundation
import SAFACrypto
import SAFADomain
import SAFAProtocol

public enum ResourceLifecycleError: Error, Equatable, Sendable {
    case unsupportedAction
    case mutationRequired
    case invalidDisplayName
    case unsupportedResourceType(String)
    case denied
    case rateLimited
}

public protocol ResourceLifecycleHandling: Sendable {
    func mutate(
        action: ResourceDirectoryActionV1,
        alias: ResourceAlias,
        mutation: ResourceMutationV1?,
        now: Date
    ) async throws -> Resource
}

public actor ResourceLifecycleService: ResourceLifecycleHandling {
    private let resources: ResourceService
    private let sshConfigResolver: any SSHConfigResolving
    private let userPresenceAuthorizer: any UserPresenceAuthorizing
    private let cooldown: TimeInterval
    private var lastAttemptAt: Date?

    public init(
        resources: ResourceService,
        sshConfigResolver: any SSHConfigResolving = OpenSSHConfigResolver(),
        userPresenceAuthorizer: any UserPresenceAuthorizing,
        cooldown: TimeInterval = 10
    ) {
        self.resources = resources
        self.sshConfigResolver = sshConfigResolver
        self.userPresenceAuthorizer = userPresenceAuthorizer
        self.cooldown = max(0, cooldown)
    }

    public func mutate(
        action: ResourceDirectoryActionV1,
        alias: ResourceAlias,
        mutation: ResourceMutationV1?,
        now: Date = Date()
    ) async throws -> Resource {
        switch action {
        case .add, .edit:
            guard let mutation else { throw ResourceLifecycleError.mutationRequired }
            try Self.validate(displayName: mutation.displayName)
            if let resourceType = mutation.resourceType,
                !Self.isSSHHostType(resourceType)
            {
                throw ResourceLifecycleError.unsupportedResourceType(resourceType.rawValue)
            }
        case .disable, .remove:
            break
        case .list, .show, .inspect:
            throw ResourceLifecycleError.unsupportedAction
        }

        if let lastAttemptAt, now.timeIntervalSince(lastAttemptAt) < cooldown {
            throw ResourceLifecycleError.rateLimited
        }
        lastAttemptAt = now
        let approved = await userPresenceAuthorizer.authorize(
            reason: Self.authorizationReason(action: action, alias: alias)
        )
        guard approved else { throw ResourceLifecycleError.denied }

        switch action {
        case .add, .edit:
            guard let mutation else { throw ResourceLifecycleError.mutationRequired }
            let resolved = try await sshConfigResolver.resolve(
                alias: mutation.sourceSSHConfigAlias
            )
            let draft = DiscoveredResourceDraft(
                alias: alias,
                resourceType: mutation.resourceType,
                displayName: mutation.displayName,
                endpoint: resolved.endpoint,
                username: resolved.username,
                securityDomain: "local-ssh-config"
            )
            if action == .add {
                return try await resources.addDiscoveredResource(draft, now: now)
            }
            return try await resources.editDiscoveredResource(
                alias: alias,
                draft: draft,
                now: now
            )
        case .disable:
            return try await resources.disable(alias: alias, now: now)
        case .remove:
            return try await resources.remove(alias: alias, now: now)
        case .list, .show, .inspect:
            throw ResourceLifecycleError.unsupportedAction
        }
    }

    private static func validate(displayName: String?) throws {
        guard let displayName else { return }
        guard !displayName.isEmpty,
            displayName.utf8.count <= 128,
            !displayName.contains(where: \Character.isNewline)
        else {
            throw ResourceLifecycleError.invalidDisplayName
        }
    }

    private static func isSSHHostType(_ resourceType: ResourceTypeIdentifier) -> Bool {
        resourceType == .hostLinux
            || resourceType == .hostMacOS
            || resourceType == .hostNAS
    }

    private static func authorizationReason(
        action: ResourceDirectoryActionV1,
        alias: ResourceAlias
    ) -> String {
        let verb: String
        switch action {
        case .add: verb = "Add"
        case .edit: verb = "Edit"
        case .disable: verb = "Disable"
        case .remove: verb = "Remove"
        case .list, .show, .inspect: verb = "Modify"
        }
        return "\(verb) SAFA resource \(alias.rawValue)"
    }
}
