import Foundation
import SAFACrypto
import SAFADomain
import SAFAProtocol

public protocol ResourceDirectoryHandling: Sendable {
    func handle(
        _ request: ResourceDirectoryRequestV1,
        caller: CallerIdentity,
        now: Date
    ) async -> ResourceDirectoryReplyV1
}

public actor ResourceDirectoryService: ResourceDirectoryHandling {
    private let vault: any VaultDocumentStoring
    private let disclosureAuthorizer: any ResourceDisclosureAuthorizing
    private let lifecycle: (any ResourceLifecycleHandling)?

    public init(
        vault: any VaultDocumentStoring,
        disclosureAuthorizer: any ResourceDisclosureAuthorizing,
        lifecycle: (any ResourceLifecycleHandling)? = nil
    ) {
        self.vault = vault
        self.disclosureAuthorizer = disclosureAuthorizer
        self.lifecycle = lifecycle
    }

    public func handle(
        _ request: ResourceDirectoryRequestV1,
        caller _: CallerIdentity,
        now: Date = Date()
    ) async -> ResourceDirectoryReplyV1 {
        do {
            let document = try await vault.readDocument()
            let registry = try ResourceRegistry(resources: document.resources)
            switch request.action {
            case .list:
                return ResourceDirectoryReplyV1(
                    messageID: request.header.messageID,
                    status: .completed,
                    summaries: registry.list(state: request.state).map(Self.summary)
                )
            case .show:
                let alias = try requiredAlias(request)
                let resource = try registry.resource(alias: alias)
                return ResourceDirectoryReplyV1(
                    messageID: request.header.messageID,
                    status: .completed,
                    summaries: [Self.summary(SafeResourceProjection(resource: resource))]
                )
            case .inspect:
                let alias = try requiredAlias(request)
                let resource = try registry.resource(alias: alias)
                do {
                    try await disclosureAuthorizer.authorize(alias: resource.alias, now: now)
                } catch ResourceDisclosureAuthorizationError.rateLimited {
                    return denial(
                        messageID: request.header.messageID,
                        code: "resource_details_rate_limited",
                        message: "Resource detail authorization is temporarily rate limited."
                    )
                } catch {
                    return denial(
                        messageID: request.header.messageID,
                        code: "resource_details_denied",
                        message: "Resource details were not authorized by the user."
                    )
                }
                return ResourceDirectoryReplyV1(
                    messageID: request.header.messageID,
                    status: .completed,
                    details: Self.details(resource, allResources: document.resources)
                )
            case .add, .edit, .disable, .remove:
                let alias = try requiredAlias(request)
                guard let lifecycle else {
                    return failure(
                        messageID: request.header.messageID,
                        code: "resource_lifecycle_unavailable",
                        message: "Resource lifecycle management is not available."
                    )
                }
                do {
                    let resource = try await lifecycle.mutate(
                        action: request.action,
                        alias: alias,
                        mutation: request.mutation,
                        now: now
                    )
                    return ResourceDirectoryReplyV1(
                        messageID: request.header.messageID,
                        status: .completed,
                        summaries: [Self.summary(SafeResourceProjection(resource: resource))]
                    )
                } catch ResourceLifecycleError.denied {
                    return denial(
                        messageID: request.header.messageID,
                        code: "resource_change_denied",
                        message: "The resource change was not authorized by the user."
                    )
                } catch ResourceLifecycleError.rateLimited {
                    return denial(
                        messageID: request.header.messageID,
                        code: "resource_change_rate_limited",
                        message: "Resource change authorization is temporarily rate limited."
                    )
                } catch ResourceLifecycleError.mutationRequired {
                    return failure(
                        messageID: request.header.messageID,
                        code: "resource_mutation_required",
                        message: "This resource change requires typed import settings."
                    )
                } catch ResourceLifecycleError.invalidDisplayName {
                    return failure(
                        messageID: request.header.messageID,
                        code: "resource_display_name_invalid",
                        message: "The display name is invalid."
                    )
                } catch ResourceLifecycleError.unsupportedResourceType(let resourceType) {
                    return failure(
                        messageID: request.header.messageID,
                        code: "resource_adapter_unsupported",
                        message: "SSH config import supports host resource types only.",
                        details: ["resource_type": .string(resourceType)]
                    )
                } catch ResourceServiceError.duplicate(let duplicate) {
                    return failure(
                        messageID: request.header.messageID,
                        code: "resource_alias_conflict",
                        message: "The resource alias is already registered.",
                        details: ["resource": .string(duplicate)]
                    )
                } catch ResourceServiceError.notFound(let missing) {
                    return failure(
                        messageID: request.header.messageID,
                        code: "resource_not_found",
                        message: "The requested resource is not registered.",
                        details: ["resource": .string(missing)]
                    )
                } catch ResourceServiceError.unsafeConnectionChange {
                    return failure(
                        messageID: request.header.messageID,
                        code: "resource_retarget_requires_setup",
                        message: "A trusted resource cannot be retargeted by SSH config refresh."
                    )
                } catch ResourceServiceError.unsupportedDiscoveredResourceType(let resourceType) {
                    return failure(
                        messageID: request.header.messageID,
                        code: "resource_adapter_unsupported",
                        message: "SSH config import supports host resource types only.",
                        details: ["resource_type": .string(resourceType)]
                    )
                } catch ResourceServiceError.referencedByResource(let owner) {
                    return failure(
                        messageID: request.header.messageID,
                        code: "resource_still_referenced",
                        message: "Another live resource still references this resource.",
                        details: ["resource": .string(owner)]
                    )
                } catch SSHConfigResolverError.timedOut {
                    return failure(
                        messageID: request.header.messageID,
                        code: "ssh_config_timeout",
                        message: "The local SSH configuration resolver timed out."
                    )
                } catch SSHConfigResolverError.unavailable {
                    return failure(
                        messageID: request.header.messageID,
                        code: "ssh_config_unavailable",
                        message: "The local OpenSSH configuration resolver is unavailable."
                    )
                } catch SSHConfigResolverError.invalidConfiguration {
                    return failure(
                        messageID: request.header.messageID,
                        code: "ssh_config_invalid",
                        message: "The SSH config alias did not resolve to a valid host."
                    )
                } catch {
                    return failure(
                        messageID: request.header.messageID,
                        code: "resource_change_failed",
                        message: "The resource change could not be completed."
                    )
                }
            }
        } catch ResourceRegistryError.notFound(let alias) {
            return failure(
                messageID: request.header.messageID,
                code: "resource_not_found",
                message: "The requested resource is not registered.",
                details: ["resource": .string(alias)]
            )
        } catch ResourceDirectoryRequestError.aliasRequired {
            return failure(
                messageID: request.header.messageID,
                code: "resource_alias_required",
                message: "This resource query requires an alias."
            )
        } catch {
            return failure(
                messageID: request.header.messageID,
                code: "resource_directory_failure",
                message: "The resource directory could not complete the request."
            )
        }
    }

    private enum ResourceDirectoryRequestError: Error {
        case aliasRequired
    }

    private func requiredAlias(_ request: ResourceDirectoryRequestV1) throws -> ResourceAlias {
        guard let alias = request.alias else {
            throw ResourceDirectoryRequestError.aliasRequired
        }
        return alias
    }

    private func denial(
        messageID: UUID,
        code: String,
        message: String
    ) -> ResourceDirectoryReplyV1 {
        ResourceDirectoryReplyV1(
            messageID: messageID,
            status: .denied,
            error: SAFAErrorPayload(code: code, message: message, retryable: false)
        )
    }

    private func failure(
        messageID: UUID,
        code: String,
        message: String,
        details: [String: JSONValue] = [:]
    ) -> ResourceDirectoryReplyV1 {
        ResourceDirectoryReplyV1(
            messageID: messageID,
            status: .failed,
            error: SAFAErrorPayload(
                code: code,
                message: message,
                retryable: false,
                details: details
            )
        )
    }

    private static func summary(_ projection: SafeResourceProjection) -> ResourceSummaryV1 {
        ResourceSummaryV1(
            alias: projection.alias.rawValue,
            displayName: projection.displayName,
            resourceType: projection.resourceType.rawValue,
            state: projection.state.rawValue,
            health: projection.health.rawValue,
            capabilities: projection.capabilities,
            metadata: projection.summaryMetadata.map(metadata)
        )
    }

    private static func details(
        _ resource: Resource,
        allResources: [Resource]
    ) -> ResourceDetailsV1 {
        let projection = SafeResourceProjection(resource: resource)
        let aliasesByID =
            allResources
            .filter { $0.state != .deleted }
            .reduce(into: [UUID: ResourceAlias]()) { aliases, item in
                aliases[item.id] = item.alias
            }
        let relationships = resource.resolvedRelationships.compactMap { relationship in
            aliasesByID[relationship.targetResourceID].map {
                ResourceRelationshipV1(
                    kind: relationship.kind.rawValue,
                    targetAlias: $0.rawValue
                )
            }
        }
        return ResourceDetailsV1(
            alias: resource.alias.rawValue,
            displayName: resource.displayName,
            resourceType: resource.resolvedResourceType.rawValue,
            alternateAliases: resource.resolvedAlternateAliases.map(\.rawValue).sorted(),
            accessMethods: resource.resolvedAccessMethods.map(\.rawValue).sorted(),
            state: resource.state.rawValue,
            health: projection.health.rawValue,
            capabilities: projection.capabilities,
            endpoint: resource.endpoint.map {
                ResourceEndpointV1(
                    scheme: $0.scheme,
                    host: $0.host,
                    port: $0.port,
                    path: $0.path
                )
            },
            username: resource.username,
            securityDomain: resource.securityDomain,
            metadata: ResourceMetadataPolicy.authorizedEntries(
                from: resource.resolvedMetadata
            ).sorted {
                $0.key.rawValue < $1.key.rawValue
            }.map(metadata),
            relationships: relationships.sorted { lhs, rhs in
                if lhs.kind == rhs.kind { return lhs.targetAlias < rhs.targetAlias }
                return lhs.kind < rhs.kind
            },
            hostIdentityStatus: resource.hostIdentity?.status.rawValue,
            updatedAt: resource.updatedAt
        )
    }

    private static func metadata(_ entry: ResourceMetadataEntry) -> ResourceMetadataEntryV1 {
        ResourceMetadataEntryV1(
            key: entry.key.rawValue,
            value: metadataValue(entry.value),
            observedAt: entry.observedAt
        )
    }

    private static func metadataValue(
        _ value: ResourceMetadataValue
    ) -> ResourceMetadataValueV1 {
        switch value {
        case let .text(value): .text(value)
        case let .integer(value): .integer(value)
        case let .boolean(value): .boolean(value)
        case let .byteCount(value): .byteCount(value)
        case let .textList(value): .textList(value)
        }
    }
}
