import SAFAProtocol

extension ResourceSummaryV1 {
    var agentRow: AgentResourceRowV2 {
        AgentResourceRowV2(
            alias: alias,
            kind: kind,
            state: state,
            health: health,
            resourceType: resourceType,
            templateID: templateID,
            hostPlatform: hostPlatform
        )
    }

    var agentSummary: AgentResourceSummaryV2 {
        AgentResourceSummaryV2(
            alias: alias,
            displayName: displayName,
            resourceType: resourceType,
            kind: kind,
            templateID: templateID,
            templateVersion: templateVersion,
            hostPlatform: hostPlatform,
            roles: roles,
            state: state,
            health: health,
            capabilities: capabilities,
            metadata: metadata.map(\.agentMetadata)
        )
    }
}

extension ResourceDetailsV1 {
    var agentDetails: AgentResourceDetailsV2 {
        AgentResourceDetailsV2(
            summary: AgentResourceSummaryV2(
                alias: alias,
                displayName: displayName,
                resourceType: resourceType,
                kind: kind,
                templateID: templateID,
                templateVersion: templateVersion,
                hostPlatform: hostPlatform,
                roles: roles,
                state: state,
                health: health,
                capabilities: capabilities,
                metadata: metadata.map(\.agentMetadata)
            ),
            alternateAliases: alternateAliases,
            accessMethods: accessMethods,
            endpoint: endpoint.map {
                AgentResourceEndpointV2(
                    scheme: $0.scheme,
                    host: $0.host,
                    port: $0.port,
                    path: $0.path
                )
            },
            username: username,
            securityDomain: securityDomain,
            relationships: relationships.map {
                AgentResourceRelationshipV2(kind: $0.kind, targetAlias: $0.targetAlias)
            },
            hostIdentityStatus: hostIdentityStatus,
            updatedAt: updatedAt
        )
    }
}

private extension ResourceMetadataEntryV1 {
    var agentMetadata: AgentResourceMetadataV2 {
        AgentResourceMetadataV2(key: key, value: value.agentValue)
    }
}

private extension ResourceMetadataValueV1 {
    var agentValue: AgentResourceMetadataValueV2 {
        switch self {
        case let .text(value): .text(value)
        case let .integer(value): .integer(value)
        case let .boolean(value): .boolean(value)
        case let .byteCount(value): .byteCount(value)
        case let .textList(value): .textList(value)
        }
    }
}

extension Dictionary where Key == String, Value == JSONValue {
    func agentString(for key: String) -> String? {
        guard case let .string(value)? = self[key] else { return nil }
        return value
    }
}
