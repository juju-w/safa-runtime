import Foundation
import SAFACrypto
import SAFADomain

public enum ResourceDisclosureAuthorizationError: Error, Equatable, Sendable {
    case denied
    case rateLimited
}

public protocol ResourceDisclosureAuthorizing: Sendable {
    func authorize(alias: ResourceAlias, now: Date) async throws
}

public actor ResourceDisclosureAuthorizationService: ResourceDisclosureAuthorizing {
    private let userPresenceAuthorizer: any UserPresenceAuthorizing
    private let cooldown: TimeInterval
    private var lastAttemptAt: Date?

    public init(
        userPresenceAuthorizer: any UserPresenceAuthorizing,
        cooldown: TimeInterval = 10
    ) {
        self.userPresenceAuthorizer = userPresenceAuthorizer
        self.cooldown = max(0, cooldown)
    }

    public func authorize(alias: ResourceAlias, now: Date) async throws {
        if let lastAttemptAt, now.timeIntervalSince(lastAttemptAt) < cooldown {
            throw ResourceDisclosureAuthorizationError.rateLimited
        }
        lastAttemptAt = now
        let approved = await userPresenceAuthorizer.authorize(
            reason: "Inspect details for resource \(alias.rawValue)"
        )
        guard approved else { throw ResourceDisclosureAuthorizationError.denied }
    }
}
