import ArgumentParser
import Foundation
import SAFADomain
import SAFAProtocol

struct ResourceCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "resource",
        subcommands: [
            ResourceListCommand.self,
            ResourceShowCommand.self,
            ResourceInspectCommand.self,
            ResourceAddCommand.self,
            ResourceEditCommand.self,
            ResourceDisableCommand.self,
            ResourceRemoveCommand.self,
        ]
    )
}

private protocol ResourceDirectoryCommand: JSONCommand {}

extension ResourceDirectoryCommand {
    func emitDirectory(command: String, reply: ResourceDirectoryReplyV1) throws {
        let status: CLIStatus
        switch reply.status {
        case .completed: status = .completed
        case .denied: status = .denied
        case .failed: status = .failed
        }
        var data: [String: JSONValue] = [:]
        if !reply.summaries.isEmpty {
            data["resources"] = .array(reply.summaries.map(\.jsonValue))
        }
        if let details = reply.details {
            data["resource"] = details.jsonValue
        }
        if let error = reply.error {
            data["error"] = .object(error.jsonObject)
        }
        let envelope = CLIEnvelope(command: command, status: status, data: data)
        let human: String
        if let error = reply.error {
            human = error.message
        } else if let details = reply.details {
            let endpoint = details.endpoint.map { "\($0.host):\($0.port)" } ?? "no endpoint"
            human = "\(details.alias) [\(details.resourceType)] \(endpoint)"
        } else {
            human = reply.summaries.map {
                "\($0.alias) [\($0.resourceType)] \($0.state)/\($0.health)"
            }.joined(separator: "\n")
        }
        try emit(envelope, humanMessage: human.isEmpty ? "No resources." : human)
        switch reply.status {
        case .completed:
            return
        case .denied:
            throw ExitCode(SAFAProcessExit.securityFailure.rawValue)
        case .failed:
            let exit: SAFAProcessExit =
                reply.error?.code == "resource_not_found"
                ? .notFound : .runtimeFailure
            throw ExitCode(exit.rawValue)
        }
    }
}

struct ResourceListCommand: AsyncParsableCommand, ResourceDirectoryCommand {
    static let configuration = CommandConfiguration(commandName: "list", aliases: ["ls"])
    @Flag var json = false
    @Option var state: String?

    func run() async throws {
        let parsedState: ResourceState?
        if let state {
            guard let value = ResourceState(rawValue: state) else {
                throw ValidationError("Invalid resource state")
            }
            parsedState = value
        } else {
            parsedState = nil
        }
        do {
            try emitDirectory(
                command: "resource.list",
                reply: try await XPCBrokerAgentClient().queryResourceDirectory(
                    action: .list,
                    alias: nil,
                    state: parsedState
                )
            )
        } catch let exit as ExitCode {
            throw exit
        } catch {
            try brokerFailure(command: "resource.list")
        }
    }
}

struct ResourceShowCommand: AsyncParsableCommand, ResourceDirectoryCommand {
    static let configuration = CommandConfiguration(commandName: "show")
    @Argument var alias: String
    @Flag var json = false

    func run() async throws {
        do {
            try emitDirectory(
                command: "resource.show",
                reply: try await XPCBrokerAgentClient().queryResourceDirectory(
                    action: .show,
                    alias: try ResourceAlias(alias),
                    state: nil
                )
            )
        } catch let exit as ExitCode {
            throw exit
        } catch {
            try brokerFailure(command: "resource.show")
        }
    }
}

struct ResourceInspectCommand: AsyncParsableCommand, ResourceDirectoryCommand {
    static let configuration = CommandConfiguration(
        commandName: "inspect",
        abstract: "Inspect protected resource details after macOS user authorization."
    )
    @Argument var alias: String
    @Flag var json = false

    func run() async throws {
        do {
            try emitDirectory(
                command: "resource.inspect",
                reply: try await XPCBrokerAgentClient().queryResourceDirectory(
                    action: .inspect,
                    alias: try ResourceAlias(alias),
                    state: nil
                )
            )
        } catch let exit as ExitCode {
            throw exit
        } catch {
            try brokerFailure(command: "resource.inspect")
        }
    }
}

private protocol SSHConfigMutationCommand: ResourceDirectoryCommand {
    var alias: String { get }
    var fromSSHConfig: String? { get }
    var resourceType: String? { get }
    var displayName: String? { get }
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
                resourceType: parsedType,
                displayName: displayName
            )
        )
    }

    func runMutation(action: ResourceDirectoryActionV1, command: String) async throws {
        do {
            let (parsedAlias, mutation) = try mutationInput()
            try emitDirectory(
                command: command,
                reply: try await XPCBrokerAgentClient().queryResourceDirectory(
                    action: action,
                    alias: parsedAlias,
                    state: nil,
                    mutation: mutation
                )
            )
        } catch let exit as ExitCode {
            throw exit
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
    @Option(name: .customLong("display-name"), help: "Optional human-readable label.")
    var displayName: String?
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
    @Option(name: .customLong("display-name"), help: "New human-readable label.")
    var displayName: String?
    @Flag var json = false

    func run() async throws {
        try await runMutation(action: .edit, command: "resource.edit")
    }
}

private protocol AliasMutationCommand: ResourceDirectoryCommand {
    var alias: String { get }
}

extension AliasMutationCommand {
    func runMutation(action: ResourceDirectoryActionV1, command: String) async throws {
        do {
            try emitDirectory(
                command: command,
                reply: try await XPCBrokerAgentClient().queryResourceDirectory(
                    action: action,
                    alias: try ResourceAlias(alias),
                    state: nil,
                    mutation: nil
                )
            )
        } catch let exit as ExitCode {
            throw exit
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

private extension ResourceSummaryV1 {
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

private extension ResourceDetailsV1 {
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

private extension ResourceMetadataValueV1 {
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
