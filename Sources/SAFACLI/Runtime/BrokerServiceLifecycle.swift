import OSLog
@preconcurrency import ServiceManagement

public enum BrokerServiceStatus: String, Codable, Equatable, Sendable {
    case notRegistered = "not_registered"
    case enabled
    case requiresApproval = "requires_approval"
    case notFound = "not_found"
}

public protocol BrokerServiceLifecycle: Sendable {
    func status() async -> BrokerServiceStatus
    func register() async throws
    func unregister() async throws
}

public enum BrokerActivationResult: Equatable, Sendable {
    case activated
    case alreadyEnabled
    case approvalRequired
    case runtimeNotBundled
    case registrationFailed
}

public enum BrokerDeactivationResult: Equatable, Sendable {
    case deactivated
    case alreadyInactive
    case unregistrationFailed
}

public struct BrokerActivationUseCase: Sendable {
    private let service: any BrokerServiceLifecycle

    public init(service: any BrokerServiceLifecycle) {
        self.service = service
    }

    public func activate() async -> BrokerActivationResult {
        switch await service.status() {
        case .enabled:
            return .alreadyEnabled
        case .requiresApproval:
            return .approvalRequired
        case .notFound:
            // A never-registered service can report notFound until Background Task Management
            // has created its first record. Registration is the authoritative bundle check.
            break
        case .notRegistered:
            break
        }

        do {
            try await service.register()
        } catch {
            return await resultAfterRegistrationFailure()
        }

        switch await service.status() {
        case .enabled:
            return .activated
        case .requiresApproval:
            return .approvalRequired
        case .notFound:
            return .runtimeNotBundled
        case .notRegistered:
            return .registrationFailed
        }
    }

    private func resultAfterRegistrationFailure() async -> BrokerActivationResult {
        switch await service.status() {
        case .enabled:
            return .alreadyEnabled
        case .requiresApproval:
            return .approvalRequired
        case .notFound:
            return .runtimeNotBundled
        case .notRegistered:
            return .registrationFailed
        }
    }
}

public struct BrokerDeactivationUseCase: Sendable {
    private let service: any BrokerServiceLifecycle

    public init(service: any BrokerServiceLifecycle) {
        self.service = service
    }

    public func deactivate() async -> BrokerDeactivationResult {
        switch await service.status() {
        case .notRegistered, .notFound:
            return .alreadyInactive
        case .enabled, .requiresApproval:
            break
        }

        do {
            try await service.unregister()
        } catch {
            return await isInactive() ? .deactivated : .unregistrationFailed
        }
        return await isInactive() ? .deactivated : .unregistrationFailed
    }

    private func isInactive() async -> Bool {
        switch await service.status() {
        case .notRegistered, .notFound:
            true
        case .enabled, .requiresApproval:
            false
        }
    }
}

public struct SystemBrokerServiceLifecycle: BrokerServiceLifecycle {
    public static let launchAgentPlistName = "dev.safa.broker.plist"
    private static let log = Logger(subsystem: "dev.safa.cli", category: "broker-lifecycle")

    public init() {}

    public func status() async -> BrokerServiceStatus {
        switch SMAppService.agent(plistName: Self.launchAgentPlistName).status {
        case .notRegistered:
            .notRegistered
        case .enabled:
            .enabled
        case .requiresApproval:
            .requiresApproval
        case .notFound:
            .notFound
        @unknown default:
            .notFound
        }
    }

    public func register() async throws {
        do {
            try SMAppService.agent(plistName: Self.launchAgentPlistName).register()
        } catch {
            let error = error as NSError
            Self.log.error(
                "Broker registration failed: domain=\(error.domain, privacy: .public) code=\(error.code, privacy: .public)"
            )
            throw error
        }
    }

    public func unregister() async throws {
        do {
            try await SMAppService.agent(
                plistName: Self.launchAgentPlistName
            ).unregister()
        } catch {
            let error = error as NSError
            Self.log.error(
                "Broker unregistration failed: domain=\(error.domain, privacy: .public) code=\(error.code, privacy: .public)"
            )
            throw error
        }
    }
}
