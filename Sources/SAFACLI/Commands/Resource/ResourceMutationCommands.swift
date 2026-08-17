import ArgumentParser
import SAFADomain
import SAFAProtocol

protocol SSHConfigMutationCommand: ResourceDirectoryCommand {
    var alias: String { get }
    var fromSSHConfig: String? { get }
    var resourceType: String? { get }
    var template: String? { get }
    var desiredState: String? { get }
}

extension SSHConfigMutationCommand {
    func mutationInput() throws -> (ResourceAlias, ResourceMutationV1) {
        let parsedAlias = try ResourceAlias(alias)
        let sourceAlias = try ResourceAlias(fromSSHConfig ?? alias)
        let templateID = try template.map { try ResourceTemplateIdentifier($0) }
        let parsedDesiredState: ResourceState?
        if let desiredState {
            guard let state = ResourceState(rawValue: desiredState),
                state == .active || state == .disabled
            else {
                throw ResourceMutationInputError.unsupportedDesiredState
            }
            guard resourceType == nil, template == nil else {
                throw ResourceMutationInputError.stateCannotCombineWithConfiguration
            }
            parsedDesiredState = state
        } else {
            parsedDesiredState = nil
        }
        let definition = templateID.flatMap { ResourceTemplateRegistry.builtIn.template(id: $0) }
        if templateID != nil, definition == nil {
            throw ResourceMutationInputError.unknownTemplate
        }
        let parsedType =
            try resourceType.map { try ResourceTypeIdentifier($0) }
            ?? definition?.resourceTypes.first
        if let definition, let parsedType, !definition.resourceTypes.contains(parsedType) {
            throw ResourceMutationInputError.typeDoesNotMatchTemplate
        }
        return (
            parsedAlias,
            ResourceMutationV1(
                sourceSSHConfigAlias: sourceAlias,
                resourceType: parsedType,
                templateID: templateID,
                desiredState: parsedDesiredState
            )
        )
    }

    func runMutation(action: ResourceMutationActionV1, command: String) async throws {
        do {
            let (parsedAlias, mutation) = try mutationInput()
            try emitMutation(
                command: command,
                reply: try await XPCBrokerAgentClient().mutateResource(
                    action: action,
                    alias: parsedAlias,
                    mutation: mutation
                )
            )
        } catch let exit as ExitCode {
            throw exit
        } catch is DomainValidationError {
            try invalidInvocation(command: command, message: "The resource alias is invalid.")
        } catch is ResourceDirectoryValidationError {
            try invalidInvocation(command: command, message: "The resource type is invalid.")
        } catch ResourceMutationInputError.unknownTemplate {
            try invalidInvocation(command: command, message: "The resource template is unknown.")
        } catch ResourceMutationInputError.typeDoesNotMatchTemplate {
            try invalidInvocation(
                command: command,
                message: "The resource type does not belong to the selected template."
            )
        } catch ResourceMutationInputError.unsupportedDesiredState {
            try invalidInvocation(
                command: command,
                message: "Resource state must be active or disabled."
            )
        } catch ResourceMutationInputError.stateCannotCombineWithConfiguration {
            try invalidInvocation(
                command: command,
                message: "Change resource state separately from template or type options."
            )
        } catch {
            try brokerFailure(command: command)
        }
    }
}

enum ResourceMutationInputError: Error {
    case unknownTemplate
    case typeDoesNotMatchTemplate
    case unsupportedDesiredState
    case stateCannotCombineWithConfiguration
}

struct ResourceAddCommand: AsyncParsableCommand, SSHConfigMutationCommand {
    static let configuration = CommandConfiguration(
        commandName: "add",
        abstract: "Add, verify, and activate a resource through its trusted template workflow."
    )
    @Argument(help: "Logical resource alias to create.") var alias: String
    @Option(
        name: .customLong("from-ssh-config"),
        help: "Logical OpenSSH Host alias; defaults to the resource alias."
    ) var fromSSHConfig: String?
    @Option(
        name: .customLong("type"),
        help: "Host platform: host.linux, host.macos, or host.windows.",
        completion: ResourceCLICompletion.hostTypes
    )
    var importedResourceType: String?
    @Option(
        name: .customLong("template"),
        help:
            "Template: ssh, mysql, postgresql, sqlserver, mongodb, s3, minio, oss, redis, kafka, rabbitmq, elasticsearch, neo4j, or http.",
        completion: ResourceCLICompletion.templates
    )
    var template: String?
    @Flag var json = false

    var resourceType: String? { importedResourceType }
    var desiredState: String? { nil }

    func run() async throws {
        try await runMutation(action: .add, command: "resource.add")
    }
}

struct ResourceEditCommand: AsyncParsableCommand, SSHConfigMutationCommand {
    static let configuration = CommandConfiguration(
        commandName: "edit",
        abstract: "Edit resource configuration or its active/disabled state."
    )
    @Argument(
        help: "Existing logical resource alias.",
        completion: ResourceCLICompletion.resourceAliases
    ) var alias: String
    @Option(
        name: .customLong("from-ssh-config"),
        help: "Logical OpenSSH Host alias; defaults to the resource alias."
    ) var fromSSHConfig: String?
    @Option(
        name: .customLong("type"),
        help: "New host type; omitted preserves the current type.",
        completion: ResourceCLICompletion.hostTypes
    )
    var resourceType: String?
    @Option(
        name: .customLong("template"),
        help: "Existing resource template; SSH is inferred when omitted.",
        completion: ResourceCLICompletion.templates
    )
    var template: String?
    @Option(
        name: .customLong("state"),
        help: "Set resource access state to active or disabled.",
        completion: ResourceCLICompletion.editableResourceStates
    )
    var desiredState: String?
    @Flag var json = false

    func run() async throws {
        try await runMutation(action: .edit, command: "resource.edit")
    }
}

protocol AliasMutationCommand: ResourceDirectoryCommand {
    var alias: String { get }
}

extension AliasMutationCommand {
    func runMutation(action: ResourceMutationActionV1, command: String) async throws {
        do {
            try emitMutation(
                command: command,
                reply: try await XPCBrokerAgentClient().mutateResource(
                    action: action,
                    alias: try ResourceAlias(alias),
                    mutation: nil
                )
            )
        } catch let exit as ExitCode {
            throw exit
        } catch is DomainValidationError {
            try invalidInvocation(command: command, message: "The resource alias is invalid.")
        } catch {
            try brokerFailure(command: command)
        }
    }
}

struct ResourceRemoveCommand: AsyncParsableCommand, AliasMutationCommand {
    static let configuration = CommandConfiguration(
        commandName: "remove",
        abstract: "Remove a resource after macOS user authorization."
    )
    @Argument(
        help: "Logical resource alias to remove.",
        completion: ResourceCLICompletion.resourceAliases
    ) var alias: String
    @Flag var json = false

    func run() async throws {
        try await runMutation(action: .remove, command: "resource.remove")
    }
}
