import Foundation
import SAFAProtocol

extension ResourceSummaryV1 {
    var jsonValue: JSONValue {
        .object([
            "alias": .string(alias),
            "display_name": displayName.map(JSONValue.string) ?? .null,
            "resource_type": .string(resourceType),
            "state": .string(state),
            "health": .string(health),
            "capabilities": .array(capabilities.map(JSONValue.string)),
            "metadata": .object(
                Dictionary(
                    uniqueKeysWithValues: metadata.map {
                        ($0.key, $0.value.jsonValue)
                    })),
        ])
    }
}

extension ResourceDetailsV1 {
    var jsonValue: JSONValue {
        var value: [String: JSONValue] = [
            "alias": .string(alias),
            "display_name": displayName.map(JSONValue.string) ?? .null,
            "resource_type": .string(resourceType),
            "alternate_aliases": .array(alternateAliases.map(JSONValue.string)),
            "access_methods": .array(accessMethods.map(JSONValue.string)),
            "state": .string(state),
            "health": .string(health),
            "capabilities": .array(capabilities.map(JSONValue.string)),
            "username": username.map(JSONValue.string) ?? .null,
            "security_domain": .string(securityDomain),
            "metadata": .object(
                Dictionary(
                    uniqueKeysWithValues: metadata.map {
                        ($0.key, $0.value.jsonValue)
                    })),
            "relationships": .array(
                relationships.map {
                    .object([
                        "kind": .string($0.kind),
                        "target_alias": .string($0.targetAlias),
                    ])
                }),
            "host_identity_status": hostIdentityStatus.map(JSONValue.string) ?? .null,
            "updated_at": .string(ISO8601DateFormatter().string(from: updatedAt)),
        ]
        value["endpoint"] =
            endpoint.map {
                .object([
                    "scheme": $0.scheme.map(JSONValue.string) ?? .null,
                    "host": .string($0.host),
                    "port": .integer(Int64($0.port)),
                    "path": $0.path.map(JSONValue.string) ?? .null,
                ])
            } ?? .null
        return .object(value)
    }
}

extension ResourceMetadataValueV1 {
    var jsonValue: JSONValue {
        switch self {
        case let .text(value): .string(value)
        case let .integer(value): .integer(value)
        case let .boolean(value): .boolean(value)
        case let .byteCount(value): .integer(Int64(clamping: value))
        case let .textList(value): .array(value.map(JSONValue.string))
        }
    }
}
