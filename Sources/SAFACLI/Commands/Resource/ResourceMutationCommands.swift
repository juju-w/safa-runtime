import ArgumentParser
import SAFADomain
import SAFAProtocol

protocol SSHConfigMutationCommand: ResourceDirectoryCommand {
    var alias: String { get }
    var fromSSHConfig: String? { get }
    var resourceType: String? { get }
}

extension SSHConfigMutationCommand {
    func mutationInput() throws -> (ResourceAlias, ResourceMutationV1) {
        let parsedAlias = try ResourceAlias(alias)
        let sourceAlias = try ResourceAlias(fromSSHConfig ?? alias)
        let parsedType = try resourceType.map { try ResourceTypeIdentifier($0) }
        return (
            parsedAlias,
            ResourceMutationV1(
                sourceSSHConfigAlias: sourceAlias,
                resourceType: parsedType
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
        } catch {
            try brokerFailure(command: command)
        }
    }
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
    @Option(name: .customLong("type"), help: "Host type: host.linux, host.macos, or host.nas.")
    var importedResourceType = "host.linux"
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
