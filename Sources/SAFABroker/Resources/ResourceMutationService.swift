import Foundation
import SAFADomain
import SAFAProtocol

public protocol ResourceMutationHandling: Sendable {
    func handle(
        _ request: ResourceMutationRequestV1,
        caller: CallerIdentity,
        now: Date
    ) async -> ResourceMutationReplyV1
}

public actor ResourceMutationService: ResourceMutationHandling {
    private let lifecycle: any ResourceLifecycleHandling

    public init(lifecycle: any ResourceLifecycleHandling) {
        self.lifecycle = lifecycle
    }

    public func handle(
        _ request: ResourceMutationRequestV1,
        caller _: CallerIdentity,
        now: Date = Date()
    ) async -> ResourceMutationReplyV1 {
        do {
            let resource = try await lifecycle.mutate(
                action: request.action,
                alias: request.alias,
                mutation: request.mutation,
                now: now
            )
            return ResourceMutationReplyV1(
                messageID: request.header.messageID,
                status: .completed,
                summary: ResourceProjectionMapper.summary(resource)
            )
        } catch ResourceLifecycleError.denied {
            return denial(
                request,
                code: "resource_change_denied",
                message: "The resource change was not authorized by the user."
            )
        } catch ResourceLifecycleError.rateLimited {
            return denial(
                request,
                code: "resource_change_rate_limited",
                message: "Resource change authorization is temporarily rate limited."
            )
        } catch ResourceLifecycleError.mutationRequired {
            return failure(
                request,
                code: "resource_mutation_required",
                message: "This resource change requires typed import settings."
            )
        } catch ResourceLifecycleError.invalidRequest {
            return failure(
                request,
                code: "resource_mutation_invalid",
                message: "This resource change contains fields that are not valid for its action."
            )
        } catch ResourceLifecycleError.unsupportedResourceType(let resourceType) {
            return failure(
                request,
                code: "resource_adapter_unsupported",
                message: "SSH config import supports host resource types only.",
                details: ["resource_type": .string(resourceType)]
            )
        } catch ResourceLifecycleError.unsupportedTemplate(let template) {
            return failure(
                request,
                code: "resource_template_unknown",
                message: "The requested resource template is not installed.",
                details: ["template": .string(template)]
            )
        } catch ResourceLifecycleError.trustedServiceSetupRequired(let template) {
            return userActionRequired(
                request,
                code: "trusted_service_setup_required",
                message: "This service template needs protected local connection setup.",
                details: ["template": .string(template)]
            )
        } catch ResourceLifecycleError.unsupportedAction {
            return userActionRequired(
                request,
                code: "trusted_setup_required",
                message: "The resource needs a supported local setup route."
            )
        } catch ResourceSetupError.hostIdentityUnavailable {
            return userActionRequired(
                request,
                code: "host_identity_setup_required",
                message: "The host is not present in the user's trusted known_hosts files."
            )
        } catch ResourceSetupError.authenticationUnavailable {
            return userActionRequired(
                request,
                code: "ssh_authentication_setup_required",
                message: "No available OpenSSH identity or agent was found for this alias."
            )
        } catch ResourceSetupError.unsupportedRoute {
            return userActionRequired(
                request,
                code: "ssh_route_setup_required",
                message: "ProxyJump and ProxyCommand routes require a reviewed route snapshot."
            )
        } catch ResourceSetupError.connectionChanged {
            return failure(
                request,
                code: "resource_retarget_requires_setup",
                message: "The SSH config no longer matches the imported draft."
            )
        } catch ResourceSetupError.resourceNotDraft {
            return failure(
                request,
                code: "resource_state_invalid",
                message: "Only a needs_setup draft can complete initial setup."
            )
        } catch ResourceSetupError.verificationFailed {
            return failure(
                request,
                code: "transport_failure",
                message: "OpenSSH verification did not complete successfully."
            )
        } catch ResourceSetupError.invalidCredentialLocator {
            return failure(
                request,
                code: "resource_change_failed",
                message: "The local OpenSSH credential route is invalid."
            )
        } catch ResourceServiceError.duplicate(let duplicate) {
            return failure(
                request,
                code: "resource_alias_conflict",
                message: "The resource alias is already registered.",
                details: ["resource": .string(duplicate)]
            )
        } catch ResourceServiceError.notFound(let missing) {
            return failure(
                request,
                code: "resource_not_found",
                message: "The requested resource is not registered.",
                details: ["resource": .string(missing)]
            )
        } catch ResourceServiceError.unsafeConnectionChange {
            return failure(
                request,
                code: "resource_retarget_requires_setup",
                message: "A trusted resource cannot be retargeted by SSH config refresh."
            )
        } catch ResourceServiceError.unsupportedDiscoveredResourceType(let resourceType) {
            return failure(
                request,
                code: "resource_adapter_unsupported",
                message: "SSH config import supports host resource types only.",
                details: ["resource_type": .string(resourceType)]
            )
        } catch ResourceServiceError.referencedByResource(let owner) {
            return failure(
                request,
                code: "resource_still_referenced",
                message: "Another live resource still references this resource.",
                details: ["resource": .string(owner)]
            )
        } catch ResourceServiceError.staleResource {
            return failure(
                request,
                code: "resource_revision_conflict",
                message: "The resource changed during setup; retry with the latest draft."
            )
        } catch DomainValidationError.invalidTransition {
            return failure(
                request,
                code: "resource_state_invalid",
                message: "The resource is not in a state that supports this change."
            )
        } catch SSHConfigResolverError.aliasNotConfigured {
            return failure(
                request,
                code: "ssh_config_alias_not_found",
                message: "The SSH config alias is not explicitly configured."
            )
        } catch SSHConfigResolverError.timedOut {
            return failure(
                request,
                code: "ssh_config_timeout",
                message: "The local SSH configuration resolver timed out."
            )
        } catch SSHConfigResolverError.unavailable {
            return failure(
                request,
                code: "ssh_config_unavailable",
                message: "The local OpenSSH configuration resolver is unavailable."
            )
        } catch SSHConfigResolverError.invalidConfiguration {
            return failure(
                request,
                code: "ssh_config_invalid",
                message: "The SSH config alias did not resolve to a valid host."
            )
        } catch {
            return failure(
                request,
                code: "resource_change_failed",
                message: "The resource change could not be completed."
            )
        }
    }

    private func denial(
        _ request: ResourceMutationRequestV1,
        code: String,
        message: String
    ) -> ResourceMutationReplyV1 {
        ResourceMutationReplyV1(
            messageID: request.header.messageID,
            status: .denied,
            error: SAFAErrorPayload(code: code, message: message, retryable: false)
        )
    }

    private func userActionRequired(
        _ request: ResourceMutationRequestV1,
        code: String,
        message: String,
        details: [String: JSONValue] = [:]
    ) -> ResourceMutationReplyV1 {
        ResourceMutationReplyV1(
            messageID: request.header.messageID,
            status: .userActionRequired,
            error: SAFAErrorPayload(
                code: code,
                message: message,
                retryable: false,
                details: details
            )
        )
    }

    private func failure(
        _ request: ResourceMutationRequestV1,
        code: String,
        message: String,
        details: [String: JSONValue] = [:]
    ) -> ResourceMutationReplyV1 {
        ResourceMutationReplyV1(
            messageID: request.header.messageID,
            status: .failed,
            error: SAFAErrorPayload(
                code: code,
                message: message,
                retryable: false,
                details: details
            )
        )
    }
}
