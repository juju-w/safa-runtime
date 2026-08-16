import Foundation

public enum ResourceMetadataPolicyError: Error, Equatable, Sendable {
    case credentialLikeKey(String)
    case invalidPublicSummaryValue(String)
}

/// Keeps credential material out of generic metadata and defines the exact
/// key, type, and value shapes that may cross the non-interactive boundary.
public enum ResourceMetadataPolicy {
    public static func validateForPersistence(_ entries: [ResourceMetadataEntry]) throws {
        for entry in entries {
            if isCredentialLike(entry.key) {
                throw ResourceMetadataPolicyError.credentialLikeKey(entry.key.rawValue)
            }
            if ResourceSummaryDisclosure.allowedMetadataKeys.contains(entry.key),
                !ResourceSummaryDisclosure.isApprovedPublicEntry(entry)
            {
                throw ResourceMetadataPolicyError.invalidPublicSummaryValue(entry.key.rawValue)
            }
        }
    }

    public static func authorizedEntries(from entries: [ResourceMetadataEntry])
        -> [ResourceMetadataEntry]
    {
        entries.filter { entry in
            guard !isCredentialLike(entry.key) else { return false }
            return !ResourceSummaryDisclosure.allowedMetadataKeys.contains(entry.key)
                || ResourceSummaryDisclosure.isApprovedPublicEntry(entry)
        }
    }

    private static func isCredentialLike(_ key: ResourceMetadataKey) -> Bool {
        let components = key.rawValue.split(whereSeparator: { $0 == "." || $0 == "-" })
            .map(String.init)
        let forbiddenComponents: Set<String> = [
            "credential", "credentials", "keychain", "locator", "passwd", "password", "secret",
            "token",
        ]
        if components.contains(where: forbiddenComponents.contains) {
            return true
        }

        let forbiddenPairs: Set<String> = ["access-key", "api-key", "private-key"]
        return zip(components, components.dropFirst()).contains { lhs, rhs in
            forbiddenPairs.contains("\(lhs)-\(rhs)")
        }
    }
}

public enum ResourceSummaryDisclosure {
    /// Only keys reviewed in source code may cross the non-interactive public
    /// projection. Imported or future keys fail closed as private.
    public static let allowedMetadataKeys: Set<ResourceMetadataKey> = Set(
        [
            "host.os.family",
            "host.docker.available",
            "database.engine",
            "object-storage.provider",
            "cache.engine",
            "service.protocol",
        ].compactMap(ResourceMetadataKey.init(rawValue:))
    )

    public static func publicEntries(from entries: [ResourceMetadataEntry])
        -> [ResourceMetadataEntry]
    {
        entries
            .filter(isApprovedPublicEntry)
            .sorted { $0.key.rawValue < $1.key.rawValue }
    }

    public static func isApprovedPublicEntry(_ entry: ResourceMetadataEntry) -> Bool {
        switch (entry.key.rawValue, entry.value) {
        case ("host.docker.available", .boolean):
            return true
        case ("host.os.family", .text(let value)):
            return [
                "aix", "freebsd", "illumos", "linux", "macos", "netbsd", "openbsd", "truenas",
                "windows",
            ].contains(value)
        case ("database.engine", .text(let value)):
            return ["mariadb", "mysql", "oracle", "postgresql", "sql-server", "sqlite"]
                .contains(value)
        case ("object-storage.provider", .text(let value)):
            return ["aliyun-oss", "aws-s3", "ceph", "minio", "s3", "truenas"]
                .contains(value)
        case ("cache.engine", .text(let value)):
            return ["memcached", "redis", "valkey"].contains(value)
        case ("service.protocol", .text(let value)):
            return ["grpc", "http", "https", "tcp", "udp"].contains(value)
        default:
            return false
        }
    }
}
