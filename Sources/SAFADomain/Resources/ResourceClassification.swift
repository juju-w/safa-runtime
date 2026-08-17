import Foundation

public struct ResourceKindIdentifier: RawRepresentable, Codable, Hashable, Sendable {
    public let rawValue: String

    public init(_ rawValue: String) throws {
        guard NamespacedIdentifier.validate(rawValue, maximumLength: 64) else {
            throw ResourceDirectoryValidationError.invalidIdentifier(rawValue)
        }
        self.rawValue = rawValue
    }

    public init?(rawValue: String) {
        try? self.init(rawValue)
    }

    public static let host = try! Self("host")
    public static let database = try! Self("database")
    public static let objectStorage = try! Self("object-storage")
    public static let cache = try! Self("cache")
    public static let messaging = try! Self("messaging")
    public static let search = try! Self("search")
    public static let graph = try! Self("graph")
    public static let service = try! Self("service")
}

public enum HostPlatform: String, Codable, CaseIterable, Sendable {
    case linux
    case macOS = "macos"
    case windows
}

public struct ResourceRoleIdentifier: RawRepresentable, Codable, Hashable, Sendable {
    public let rawValue: String

    public init(_ rawValue: String) throws {
        guard NamespacedIdentifier.validate(rawValue, maximumLength: 64) else {
            throw ResourceDirectoryValidationError.invalidIdentifier(rawValue)
        }
        self.rawValue = rawValue
    }

    public init?(rawValue: String) {
        try? self.init(rawValue)
    }

    public static let nas = try! Self("nas")
    public static let gpu = try! Self("gpu")
    public static let jumpServer = try! Self("jump-server")
}

public struct ResourceTemplateBinding: Codable, Equatable, Sendable {
    public let id: ResourceTemplateIdentifier
    public let version: UInt

    public init(id: ResourceTemplateIdentifier, version: UInt) {
        self.id = id
        self.version = version
    }

    public static let sshV1 = Self(id: .ssh, version: 1)
}

public struct ResourceClassification: Codable, Equatable, Sendable {
    public let kind: ResourceKindIdentifier
    public let template: ResourceTemplateBinding
    public var hostPlatform: HostPlatform?
    public var roles: [ResourceRoleIdentifier]

    public init(
        kind: ResourceKindIdentifier,
        template: ResourceTemplateBinding,
        hostPlatform: HostPlatform? = nil,
        roles: [ResourceRoleIdentifier] = []
    ) {
        self.kind = kind
        self.template = template
        self.hostPlatform = hostPlatform
        self.roles = roles
    }

    public static func host(
        platform: HostPlatform,
        roles: [ResourceRoleIdentifier] = []
    ) -> Self {
        Self(
            kind: .host,
            template: .sshV1,
            hostPlatform: platform,
            roles: roles
        )
    }

    /// Reads the pre-classification resource type without preserving its mixed semantics.
    /// `host.nas` is accepted only here so old vault records migrate to a Linux host with a NAS
    /// role on their next write.
    public static func migratingLegacyType(_ resourceType: ResourceTypeIdentifier) -> Self {
        switch resourceType.rawValue {
        case ResourceTypeIdentifier.hostLinux.rawValue:
            return .host(platform: .linux)
        case ResourceTypeIdentifier.hostMacOS.rawValue:
            return .host(platform: .macOS)
        case ResourceTypeIdentifier.hostWindows.rawValue:
            return .host(platform: .windows)
        case "host.nas":
            return .host(platform: .linux, roles: [.nas])
        default:
            let components = resourceType.rawValue.split(separator: ".").map(String.init)
            let kindValue = components.dropLast().joined(separator: ".")
            let templateValue = components.last ?? ResourceTemplateIdentifier.http.rawValue
            return Self(
                kind: ResourceKindIdentifier(rawValue: kindValue) ?? .service,
                template: ResourceTemplateBinding(
                    id: ResourceTemplateIdentifier(rawValue: templateValue) ?? .http,
                    version: 1
                )
            )
        }
    }

    /// Keeps the additive CLI v1 `resource_type` field stable while the authoritative model uses
    /// kind, template, and platform independently.
    public var compatibilityResourceType: ResourceTypeIdentifier {
        if kind == .host {
            switch hostPlatform ?? .linux {
            case .linux:
                return .hostLinux
            case .macOS:
                return .hostMacOS
            case .windows:
                return .hostWindows
            }
        }
        let value = "\(kind.rawValue).\(template.id.rawValue)"
        return ResourceTypeIdentifier(rawValue: value) ?? .serviceHTTP
    }
}
