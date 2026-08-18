import Foundation
import SAFAProtocol

extension AgentResourceSummaryPayloadV2: AgentCLIToonPayload {
    func toonFields() -> [TOONField] {
        [TOONField(key: "resource", value: resource.toonValue)]
    }
}

extension AgentResourceDetailsPayloadV2: AgentCLIToonPayload {
    func toonFields() -> [TOONField] {
        [TOONField(key: "resource", value: resource.toonValue)]
    }
}

private extension AgentResourceSummaryV2 {
    var toonValue: TOONValue {
        .object([
            TOONField(key: "alias", value: .string(alias)),
            TOONField(key: "display_name", value: displayName.map(TOONValue.string) ?? .null),
            TOONField(key: "resource_type", value: .string(resourceType)),
            TOONField(key: "kind", value: .string(kind)),
            TOONField(key: "template_id", value: .string(templateID)),
            TOONField(key: "template_version", value: .integer(Int64(templateVersion))),
            TOONField(key: "host_platform", value: hostPlatform.map(TOONValue.string) ?? .null),
            TOONField(key: "roles", value: .array(roles.map(TOONValue.string))),
            TOONField(key: "state", value: .string(state)),
            TOONField(key: "health", value: .string(health)),
            TOONField(key: "capabilities", value: .array(capabilities.map(TOONValue.string))),
            TOONField(key: "metadata", value: .array(metadata.map(\.toonValue))),
        ])
    }
}

private extension AgentResourceDetailsV2 {
    var toonValue: TOONValue {
        guard case let .object(summaryFields) = summary.toonValue else {
            return .object([])
        }
        return .object(
            summaryFields
                + [
                    TOONField(
                        key: "alternate_aliases",
                        value: .array(alternateAliases.map(TOONValue.string))
                    ),
                    TOONField(
                        key: "access_methods",
                        value: .array(accessMethods.map(TOONValue.string))
                    ),
                    TOONField(key: "endpoint", value: endpoint?.toonValue ?? .null),
                    TOONField(key: "username", value: username.map(TOONValue.string) ?? .null),
                    TOONField(key: "security_domain", value: .string(securityDomain)),
                    TOONField(
                        key: "relationships",
                        value: .array(relationships.map(\.toonValue))
                    ),
                    TOONField(
                        key: "host_identity_status",
                        value: hostIdentityStatus.map(TOONValue.string) ?? .null
                    ),
                    TOONField(key: "updated_at", value: .string(Self.timestamp(updatedAt))),
                ]
        )
    }

    private static func timestamp(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        return formatter.string(from: date)
    }
}

private extension AgentResourceEndpointV2 {
    var toonValue: TOONValue {
        .object([
            TOONField(key: "scheme", value: scheme.map(TOONValue.string) ?? .null),
            TOONField(key: "host", value: .string(host)),
            TOONField(key: "port", value: .integer(Int64(port))),
            TOONField(key: "path", value: path.map(TOONValue.string) ?? .null),
        ])
    }
}

private extension AgentResourceRelationshipV2 {
    var toonValue: TOONValue {
        .object([
            TOONField(key: "kind", value: .string(kind)),
            TOONField(key: "target_alias", value: .string(targetAlias)),
        ])
    }
}

private extension AgentResourceMetadataV2 {
    var toonValue: TOONValue {
        .object([
            TOONField(key: "key", value: .string(key)),
            TOONField(key: "value", value: value.toonValue),
        ])
    }
}

private extension AgentResourceMetadataValueV2 {
    var toonValue: TOONValue {
        switch self {
        case let .text(value): .string(value)
        case let .integer(value): .integer(value)
        case let .boolean(value): .boolean(value)
        case let .byteCount(value): .integer(Int64(clamping: value))
        case let .textList(value): .array(value.map(TOONValue.string))
        }
    }
}
