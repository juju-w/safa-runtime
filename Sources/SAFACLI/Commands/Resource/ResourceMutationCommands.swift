import ArgumentParser
import SAFADomain
import SAFAProtocol

protocol SSHConfigMutationCommand: ResourceDirectoryCommand {
    var alias: String { get }
    var fromSSHConfig: String? { get }
    var resourceType: String? { get }
    var template: String? { get }
}

extension SSHConfigMutationCommand {
    func mutationInput() throws -> (ResourceAlias, ResourceMutationV1) {
        let parsedAlias = try ResourceAlias(alias)
        let sourceAlias = try ResourceAlias(fromSSHConfig ?? alias)
        let templateID = try template.map { try ResourceTemplateIdentifier($0) }
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
                templateID: templateID
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
        } catch {
            try brokerFailure(command: command)
        }
    }
}

enum ResourceMutationInputError: Error {
    case unknownTemplate
    case typeDoesNotMatchTemplate
}

struct ResourceAddCommand: AsyncParsableCommand, SSHConfigMutationCommand {
    static let configuration = CommandConfiguration(
        commandName: "add",
        abstract: "Import a draft resource from a local SSH config alias."
    )
    @Argument(help: "Logical resource alias to create.") var alias: String
    @Option(
        name: .customLong("from-ssh-config"),
        help: "Logical OpenSSH Host alias; defaults to the resource alias."
    ) var fromSSHConfig: String?
    @Option(
        name: .customLong("type"),
        help: "Host type: host.linux, host.macos, host.nas, or host.windows."
    )
    var importedResourceType: String?
    @Option(
        name: .customLong("template"),
        help:
            "Template: ssh, mysql, postgresql, sqlserver, s3, minio, oss, redis, elasticsearch, neo4j, or http."
    )
    var template: String?
    @Flag var json = false

    var resourceType: String? { importedResourceType }

    func run() async throws {
        try await runMutation(action: .add, command: "resource.add")
    }
}

struct ResourceEditCommand: AsyncParsableCommand, SSHConfigMutationCommand {
    static let configuration = CommandConfiguration(
        commandName: "edit",
        abstract: "Refresh a resource from a local SSH config alias."
    )
    @Argument(help: "Existing logical resource alias.") var alias: String
    @Option(
        name: .customLong("from-ssh-config"),
        help: "Logical OpenSSH Host alias; defaults to the resource alias."
    ) var fromSSHConfig: String?
    @Option(
        name: .customLong("type"),
        help: "New host type; omitted preserves the current type."
    )
    var resourceType: String?
    @Option(
        name: .customLong("template"),
        help: "Existing resource template; SSH is inferred when omitted."
    )
    var template: String?
    @Flag var json = false

    func run() async throws {
        try await runMutation(action: .edit, command: "resource.edit")
    }
}

struct ResourceSetupCommand: AsyncParsableCommand, SSHConfigMutationCommand {
    static let configuration = CommandConfiguration(
        commandName: "setup",
        abstract: "Activate a draft through a trusted local OpenSSH setup."
    )
    @Argument(help: "Draft resource alias to set up.") var alias: String
    @Option(
        name: .customLong("from-ssh-config"),
        help: "Logical OpenSSH Host alias; defaults to the resource alias."
    ) var fromSSHConfig: String?
    @Flag var json = false

    var resourceType: String? { nil }
    var template: String? { "ssh" }

    func run() async throws {
        try await runMutation(action: .setup, command: "resource.setup")
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

struct ResourceDisableCommand: AsyncParsableCommand, AliasMutationCommand {
    static let configuration = CommandConfiguration(
        commandName: "disable",
        abstract: "Disable a resource after macOS user authorization."
    )
    @Argument(help: "Logical resource alias to disable.") var alias: String
    @Flag var json = false

    func run() async throws {
        try await runMutation(action: .disable, command: "resource.disable")
    }
}

struct ResourceEnableCommand: AsyncParsableCommand, AliasMutationCommand {
    static let configuration = CommandConfiguration(
        commandName: "enable",
        abstract: "Re-enable a disabled resource after macOS user authorization."
    )
    @Argument(help: "Logical resource alias to enable.") var alias: String
    @Flag var json = false

    func run() async throws {
        try await runMutation(action: .enable, command: "resource.enable")
    }
}

struct ResourceRemoveCommand: AsyncParsableCommand, AliasMutationCommand {
    static let configuration = CommandConfiguration(
        commandName: "remove",
        abstract: "Remove a resource after macOS user authorization."
    )
    @Argument(help: "Logical resource alias to remove.") var alias: String
    @Flag var json = false

    func run() async throws {
        try await runMutation(action: .remove, command: "resource.remove")
    }
}
