import Foundation
import SAFACrypto
import SAFADomain
import SAFAProtocol

public enum ResourceLifecycleError: Error, Equatable, Sendable {
    case unsupportedAction
    case mutationRequired
    case invalidRequest
    case unsupportedResourceType(String)
    case unsupportedTemplate(String)
    case trustedServiceSetupRequired(String)
    case denied
    case rateLimited
}

public protocol ResourceLifecycleHandling: Sendable {
    func mutate(
        action: ResourceMutationActionV1,
        alias: ResourceAlias,
        mutation: ResourceMutationV1?,
        now: Date
    ) async throws -> Resource
}

public actor ResourceLifecycleService: ResourceLifecycleHandling {
    private let resources: ResourceService
    private let sshConfigResolver: any SSHConfigResolving
    private let setup: (any ResourceSetupHandling)?
    private let userPresenceAuthorizer: any UserPresenceAuthorizing
    private let cooldown: TimeInterval
    private var lastDeniedAt: Date?

    public init(
        resources: ResourceService,
        sshConfigResolver: any SSHConfigResolving = OpenSSHConfigResolver(),
        userPresenceAuthorizer: any UserPresenceAuthorizing,
        cooldown: TimeInterval = 10
    ) {
        self.resources = resources
        self.sshConfigResolver = sshConfigResolver
        setup = nil
        self.userPresenceAuthorizer = userPresenceAuthorizer
        self.cooldown = max(0, cooldown)
    }

    init(
        resources: ResourceService,
        sshConfigResolver: any SSHConfigResolving = OpenSSHConfigResolver(),
        setup: any ResourceSetupHandling,
        userPresenceAuthorizer: any UserPresenceAuthorizing,
        cooldown: TimeInterval = 10
    ) {
        self.resources = resources
        self.sshConfigResolver = sshConfigResolver
        self.setup = setup
        self.userPresenceAuthorizer = userPresenceAuthorizer
        self.cooldown = max(0, cooldown)
    }

    public func mutate(
        action: ResourceMutationActionV1,
        alias: ResourceAlias,
        mutation: ResourceMutationV1?,
        now: Date = Date()
    ) async throws -> Resource {
        switch action {
        case .add, .edit, .setup:
            guard let mutation else { throw ResourceLifecycleError.mutationRequired }
            if action == .setup, mutation.resourceType != nil {
                throw ResourceLifecycleError.invalidRequest
            }
            if let templateID = mutation.templateID {
                guard let template = ResourceTemplateRegistry.builtIn.template(id: templateID)
                else {
                    throw ResourceLifecycleError.unsupportedTemplate(templateID.rawValue)
                }
                if let resourceType = mutation.resourceType,
                    !template.resourceTypes.contains(resourceType)
                {
                    throw ResourceLifecycleError.unsupportedResourceType(resourceType.rawValue)
                }
                if templateID != .ssh {
                    throw ResourceLifecycleError.trustedServiceSetupRequired(templateID.rawValue)
                }
            }
            if let resourceType = mutation.resourceType, !Self.isSSHHostType(resourceType) {
                throw ResourceLifecycleError.unsupportedResourceType(resourceType.rawValue)
            }
        case .disable, .enable, .remove:
            guard mutation == nil else { throw ResourceLifecycleError.invalidRequest }
        }

        if let lastDeniedAt, now.timeIntervalSince(lastDeniedAt) < cooldown {
            throw ResourceLifecycleError.rateLimited
        }
        let approved = await userPresenceAuthorizer.authorize(
            reason: Self.authorizationReason(action: action, alias: alias)
        )
        guard approved else {
            lastDeniedAt = now
            throw ResourceLifecycleError.denied
        }

        switch action {
        case .add, .edit:
            guard let mutation else { throw ResourceLifecycleError.mutationRequired }
            let resolved = try await sshConfigResolver.resolve(
                alias: mutation.sourceSSHConfigAlias
            )
            let draft = DiscoveredResourceDraft(
                alias: alias,
                resourceType: mutation.resourceType,
                displayName: nil,
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
        case .setup:
            guard let mutation, let setup else {
                throw ResourceLifecycleError.unsupportedAction
            }
            return try await setup.setup(
                alias: alias,
                sourceSSHConfigAlias: mutation.sourceSSHConfigAlias,
                now: now
            )
        case .disable:
            return try await resources.disable(alias: alias, now: now)
        case .enable:
            return try await resources.enable(alias: alias, now: now)
        case .remove:
            return try await resources.remove(alias: alias, now: now)
        }
    }

    private static func isSSHHostType(_ resourceType: ResourceTypeIdentifier) -> Bool {
        resourceType == .hostLinux
            || resourceType == .hostMacOS
            || resourceType == .hostWindows
    }

    private static func authorizationReason(
        action: ResourceMutationActionV1,
        alias: ResourceAlias
    ) -> String {
        let verb: String
        switch action {
        case .add: verb = "Add"
        case .edit: verb = "Edit"
        case .setup: verb = "Set up"
        case .disable: verb = "Disable"
        case .enable: verb = "Enable"
        case .remove: verb = "Remove"
        }
        return "\(verb) SAFA resource \(alias.rawValue)"
    }
}
