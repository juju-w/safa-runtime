import ArgumentParser
import SAFADomain
import SAFAProtocol

struct ResourceListCommand: AsyncParsableCommand, ResourceDirectoryCommand {
    static let configuration = CommandConfiguration(commandName: "list", aliases: ["ls"])
    @Option(completion: ResourceCLICompletion.resourceStates) var state: String?
    @Option(help: "Maximum number of rows to return (1...500).") var limit: Int = 100
    @Option(help: "Comma-separated safe fields; alias is required.") var fields: String?

    func requestedState() throws -> ResourceState? {
        guard let state else { return nil }
        guard let value = ResourceState(rawValue: state), value != .deleted else {
            throw ResourceListInputError.invalidState
        }
        return value
    }

    func requestedLimit() throws -> Int {
        guard (1...500).contains(limit) else { throw ResourceListInputError.invalidLimit }
        return limit
    }

    func requestedFields() throws -> [AgentResourceListFieldV2] {
        guard let fields else { return AgentResourceListFieldV2.defaultFields }
        let values = fields.split(separator: ",", omittingEmptySubsequences: false).map(String.init)
        guard !values.contains(where: \.isEmpty) else {
            throw ResourceListInputError.invalidFields
        }
        let parsed = values.compactMap(AgentResourceListFieldV2.init(rawValue:))
        guard parsed.count == values.count,
            Set(parsed.map(\.rawValue)).count == parsed.count,
            parsed.contains(.alias)
        else {
            throw ResourceListInputError.invalidFields
        }
        return parsed
    }

    func run() async throws {
        do {
            let limit = try requestedLimit()
            let fields = try requestedFields()
            try finishDirectory(
                command: "resource.list",
                reply: try await XPCBrokerAgentClient().queryResourceDirectory(
                    action: .list,
                    alias: nil,
                    state: try requestedState()
                ),
                limit: limit,
                fields: fields
            )
        } catch let exit as ExitCode {
            throw exit
        } catch ResourceListInputError.invalidState {
            try invalidInvocation(
                command: "resource.list",
                message: "Resource state must be draft, active, or disabled."
            )
        } catch ResourceListInputError.invalidLimit {
            try invalidInvocation(
                command: "resource.list",
                message: "Resource list limit must be between 1 and 500."
            )
        } catch ResourceListInputError.invalidFields {
            try invalidInvocation(
                command: "resource.list",
                message:
                    "Resource fields must be unique reviewed names and include alias: "
                    + AgentResourceListFieldV2.allCases.map(\.rawValue).joined(separator: ", ")
            )
        } catch {
            try brokerFailure(command: "resource.list")
        }
    }
}

enum ResourceListInputError: Error {
    case invalidState
    case invalidLimit
    case invalidFields
}

struct ResourceShowCommand: AsyncParsableCommand, ResourceDirectoryCommand {
    static let configuration = CommandConfiguration(
        commandName: "show",
        abstract: "Show a safe summary; pass --details for authorized inventory."
    )
    @Argument(completion: ResourceCLICompletion.resourceAliases) var alias: String
    @Flag(
        name: .customLong("details"),
        help: "Show protected connection and probed inventory after macOS authorization."
    ) var details = false

    func run() async throws {
        do {
            try finishDirectory(
                command: "resource.show",
                reply: try await XPCBrokerAgentClient().queryResourceDirectory(
                    action: details ? .inspect : .show,
                    alias: try ResourceAlias(alias),
                    state: nil
                )
            )
        } catch let exit as ExitCode {
            throw exit
        } catch is DomainValidationError {
            try invalidInvocation(
                command: "resource.show", message: "The resource alias is invalid.")
        } catch {
            try brokerFailure(command: "resource.show")
        }
    }
}
