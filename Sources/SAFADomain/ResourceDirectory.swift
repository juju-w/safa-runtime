import Foundation

public enum ResourceDirectoryValidationError: Error, Equatable, Sendable {
    case invalidIdentifier(String)
}

enum NamespacedIdentifier {
    static func validate(_ rawValue: String, maximumLength: Int = 96) -> Bool {
        guard !rawValue.isEmpty, rawValue.utf8.count <= maximumLength else { return false }
        return rawValue.range(
            of: "^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$",
            options: .regularExpression
        ) != nil
    }
}

/// An open, validated identifier such as `host.linux`, `database.mysql`, or
/// `object-storage.s3`. New resource profiles do not require a vault schema change.
public struct ResourceTypeIdentifier: RawRepresentable, Codable, Hashable, Sendable {
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

    public static let hostLinux = try! Self("host.linux")
    public static let hostMacOS = try! Self("host.macos")
    public static let hostNAS = try! Self("host.nas")
    public static let databaseMySQL = try! Self("database.mysql")
    public static let databasePostgreSQL = try! Self("database.postgresql")
    public static let objectStorageS3 = try! Self("object-storage.s3")
    public static let cacheRedis = try! Self("cache.redis")
    public static let serviceHTTP = try! Self("service.http")
}

/// Identifies how a broker can reach a resource. It is deliberately open so
/// database, object-storage, cache, and service adapters can be added later.
public struct AccessMethodIdentifier: RawRepresentable, Codable, Hashable, Sendable {
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

    public static let ssh = try! Self("ssh")
    public static let mysql = try! Self("database.mysql")
    public static let postgresql = try! Self("database.postgresql")
    public static let s3 = try! Self("object-storage.s3")
    public static let redis = try! Self("cache.redis")
    public static let http = try! Self("http")
}

public struct ResourceMetadataKey: RawRepresentable, Codable, Hashable, Sendable {
    public let rawValue: String

    public init(_ rawValue: String) throws {
        guard NamespacedIdentifier.validate(rawValue) else {
            throw ResourceDirectoryValidationError.invalidIdentifier(rawValue)
        }
        self.rawValue = rawValue
    }

    public init?(rawValue: String) {
        try? self.init(rawValue)
    }
}

/// Typed values prevent adapters from turning the persistent resource model into
/// an unreviewable bag of arbitrary JSON.
public enum ResourceMetadataValue: Equatable, Sendable {
    case text(String)
    case integer(Int64)
    case boolean(Bool)
    case byteCount(UInt64)
    case textList([String])
}

extension ResourceMetadataValue: Codable {
    private enum ValueType: String, Codable {
        case text
        case integer
        case boolean
        case byteCount = "byte_count"
        case textList = "text_list"
    }

    private enum CodingKeys: String, CodingKey {
        case type
        case value
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(ValueType.self, forKey: .type) {
        case .text:
            self = .text(try container.decode(String.self, forKey: .value))
        case .integer:
            self = .integer(try container.decode(Int64.self, forKey: .value))
        case .boolean:
            self = .boolean(try container.decode(Bool.self, forKey: .value))
        case .byteCount:
            self = .byteCount(try container.decode(UInt64.self, forKey: .value))
        case .textList:
            self = .textList(try container.decode([String].self, forKey: .value))
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case let .text(value):
            try container.encode(ValueType.text, forKey: .type)
            try container.encode(value, forKey: .value)
        case let .integer(value):
            try container.encode(ValueType.integer, forKey: .type)
            try container.encode(value, forKey: .value)
        case let .boolean(value):
            try container.encode(ValueType.boolean, forKey: .type)
            try container.encode(value, forKey: .value)
        case let .byteCount(value):
            try container.encode(ValueType.byteCount, forKey: .type)
            try container.encode(value, forKey: .value)
        case let .textList(value):
            try container.encode(ValueType.textList, forKey: .type)
            try container.encode(value, forKey: .value)
        }
    }
}

public struct ResourceMetadataEntry: Codable, Equatable, Sendable {
    public let key: ResourceMetadataKey
    public var value: ResourceMetadataValue
    public var observedAt: Date?

    public init(
        key: ResourceMetadataKey,
        value: ResourceMetadataValue,
        observedAt: Date? = nil
    ) {
        self.key = key
        self.value = value
        self.observedAt = observedAt
    }

    public init(key: String, value: ResourceMetadataValue, observedAt: Date? = nil) throws {
        self.init(key: try ResourceMetadataKey(key), value: value, observedAt: observedAt)
    }
}

public struct ResourceRelationshipKind: RawRepresentable, Codable, Hashable, Sendable {
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

    public static let hostedOn = try! Self("hosted-on")
    public static let dependsOn = try! Self("depends-on")
    public static let backedBy = try! Self("backed-by")
}

public struct ResourceRelationship: Codable, Equatable, Sendable {
    public let kind: ResourceRelationshipKind
    public let targetResourceID: UUID

    public init(kind: ResourceRelationshipKind, targetResourceID: UUID) {
        self.kind = kind
        self.targetResourceID = targetResourceID
    }

    private enum CodingKeys: String, CodingKey {
        case kind
        case targetResourceID = "target_resource_id"
    }
}

public struct ResourceCredentialRole: RawRepresentable, Codable, Hashable, Sendable {
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

    public static let primary = try! Self("primary")
    public static let privileged = try! Self("privileged")
    public static let readOnly = try! Self("read-only")
}

public struct ResourceCredentialBinding: Codable, Equatable, Sendable {
    public let role: ResourceCredentialRole
    public let credentialID: UUID

    public init(role: ResourceCredentialRole, credentialID: UUID) {
        self.role = role
        self.credentialID = credentialID
    }

    private enum CodingKeys: String, CodingKey {
        case role
        case credentialID = "credential_id"
    }
}

/// Cohesive, transport-independent configuration attached to a resource. A nil
/// profile is reserved for vault records written before the resource-directory
/// migration and resolves to the legacy SSH-host defaults.
public struct ResourceProfile: Codable, Equatable, Sendable {
    public let resourceType: ResourceTypeIdentifier
    public var alternateAliases: [ResourceAlias]
    public var accessMethods: [AccessMethodIdentifier]
    public var metadata: [ResourceMetadataEntry]
    public var relationships: [ResourceRelationship]
    public var credentialBindings: [ResourceCredentialBinding]

    public init(
        resourceType: ResourceTypeIdentifier,
        alternateAliases: [ResourceAlias] = [],
        accessMethods: [AccessMethodIdentifier] = [],
        metadata: [ResourceMetadataEntry] = [],
        relationships: [ResourceRelationship] = [],
        credentialBindings: [ResourceCredentialBinding] = []
    ) {
        self.resourceType = resourceType
        self.alternateAliases = alternateAliases
        self.accessMethods = accessMethods
        self.metadata = metadata
        self.relationships = relationships
        self.credentialBindings = credentialBindings
    }
}
