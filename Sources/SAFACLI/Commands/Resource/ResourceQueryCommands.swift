import ArgumentParser
import SAFADomain

struct ResourceListCommand: AsyncParsableCommand, ResourceDirectoryCommand {
    static let configuration = CommandConfiguration(commandName: "list", aliases: ["ls"])
    @Flag var json = false
    @Option var state: String?

    func run() async throws {
        let parsedState: ResourceState?
        if let state {
            guard let value = ResourceState(rawValue: state) else {
                try invalidInvocation(
                    command: "resource.list",
                    message: "The resource state is invalid."
                )
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
    static let configuration = CommandConfiguration(
        commandName: "show",
        abstract: "Show a safe summary; pass --details for authorized inventory."
    )
    @Argument var alias: String
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

struct ResourceInspectCommand: AsyncParsableCommand, ResourceDirectoryCommand {
    static let configuration = CommandConfiguration(
        commandName: "inspect",
        abstract: "Compatibility alias for resource show --details.",
        shouldDisplay: false
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
        } catch is DomainValidationError {
            try invalidInvocation(
                command: "resource.inspect",
                message: "The resource alias is invalid."
            )
        } catch {
            try brokerFailure(command: "resource.inspect")
        }
    }
}
