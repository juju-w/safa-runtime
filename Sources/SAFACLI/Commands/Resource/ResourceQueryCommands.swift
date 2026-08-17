import ArgumentParser
import SAFADomain

struct ResourceListCommand: AsyncParsableCommand, ResourceDirectoryCommand {
    static let configuration = CommandConfiguration(commandName: "list", aliases: ["ls"])
    @Flag var json = false
    @Option(completion: ResourceCLICompletion.resourceStates) var state: String?

    func requestedState() throws -> ResourceState? {
        guard let state else { return nil }
        guard let value = ResourceState(rawValue: state), value != .deleted else {
            throw ResourceListInputError.invalidState
        }
        return value
    }

    func run() async throws {
        do {
            try emitDirectory(
                command: "resource.list",
                reply: try await XPCBrokerAgentClient().queryResourceDirectory(
                    action: .list,
                    alias: nil,
                    state: try requestedState()
                )
            )
        } catch let exit as ExitCode {
            throw exit
        } catch ResourceListInputError.invalidState {
            try invalidInvocation(
                command: "resource.list",
                message: "Resource state must be draft, active, or disabled."
            )
        } catch {
            try brokerFailure(command: "resource.list")
        }
    }
}

enum ResourceListInputError: Error {
    case invalidState
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
    @Flag var json = false

    func run() async throws {
        do {
            try emitDirectory(
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
