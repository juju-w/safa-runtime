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
