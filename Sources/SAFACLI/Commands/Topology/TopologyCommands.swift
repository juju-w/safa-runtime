import ArgumentParser
import Foundation
import SAFADomain
import SAFAProtocol

struct TopologyCommand: AsyncParsableCommand, AgentCommand {
    static let configuration = CommandConfiguration(
        commandName: "topology",
        abstract: "Ask simple questions about registered resource relationships.",
        subcommands: [
            TopologyShowCommand.self,
            TopologyPathCommand.self,
            TopologyImpactCommand.self,
            TopologyLinkCommand.self,
            TopologyUnlinkCommand.self,
        ]
    )

    mutating func run() async throws {
        do {
            let reply = try await XPCBrokerAgentClient().queryTopology(
                task: .inventory,
                source: nil,
                target: nil,
                relation: nil,
                bounds: TopologyQueryBoundsV1()
            )
            try finishTopology(command: "topology.show", reply: reply)
        } catch let exitCode as ExitCode {
            throw exitCode
        } catch {
            try brokerFailure(command: "topology.show")
        }
    }
}

protocol TopologyQueryCommand: AgentCommand {}

extension TopologyQueryCommand {
    func runQuery(
        command: String,
        request: TopologyQueryRequestV1,
        nodeFields: [AgentTopologyNodeFieldV2] = AgentTopologyNodeFieldV2.defaultFields
    ) async throws {
        do {
            let reply = try await XPCBrokerAgentClient().queryTopology(
                task: request.task,
                source: request.source,
                target: request.target,
                relation: request.relation,
                bounds: request.bounds
            )
            try finishTopology(command: command, reply: reply, nodeFields: nodeFields)
        } catch let exit as ExitCode {
            throw exit
        } catch {
            try brokerFailure(command: command)
        }
    }
}

struct TopologyShowCommand: AsyncParsableCommand, TopologyQueryCommand {
    static let configuration = CommandConfiguration(
        commandName: "show",
        abstract: "Show the safe topology inventory or the neighborhood of one alias."
    )
    @Argument(
        help: "Optional registered alias.",
        completion: ResourceCLICompletion.resourceAliases
    ) var alias: String?
    @Option(help: "Maximum number of topology nodes to return (1...64).") var limit: Int = 64
    @Option(help: "Comma-separated safe node fields; alias is required.") var fields: String?

    func requestedFields() throws -> [AgentTopologyNodeFieldV2] {
        guard let fields else { return AgentTopologyNodeFieldV2.defaultFields }
        let values = fields.split(separator: ",", omittingEmptySubsequences: false).map(String.init)
        let parsed = values.compactMap(AgentTopologyNodeFieldV2.init(rawValue:))
        guard !values.contains(where: \.isEmpty),
            parsed.count == values.count,
            Set(parsed.map(\.rawValue)).count == parsed.count,
            parsed.contains(.alias)
        else {
            throw TopologyCLIInputError.invalidFields
        }
        return parsed
    }

    func query(now: Date = Date()) throws -> TopologyQueryRequestV1 {
        let limit = try validatedTopologyLimit(limit)
        return TopologyQueryRequestV1(
            header: IPCHeader(sentAt: now, deadline: now.addingTimeInterval(30)),
            task: alias == nil ? .inventory : .placement,
            source: try alias.map(ResourceAlias.init),
            bounds: TopologyQueryBoundsV1(
                maximumHops: 6,
                maximumNodes: limit,
                maximumEdges: min(128, limit * 2)
            )
        )
    }

    func run() async throws {
        do {
            let fields = try requestedFields()
            try await runQuery(command: "topology.show", request: try query(), nodeFields: fields)
        } catch is DomainValidationError {
            try invalidInvocation(
                command: "topology.show", message: "The resource alias is invalid.")
        } catch TopologyCLIInputError.invalidLimit {
            try invalidInvocation(
                command: "topology.show", message: "Topology limit must be between 1 and 64.")
        } catch TopologyCLIInputError.invalidFields {
            try invalidInvocation(
                command: "topology.show",
                message: "Topology fields must be unique reviewed names and include alias."
            )
        }
    }
}

struct TopologyPathCommand: AsyncParsableCommand, TopologyQueryCommand {
    static let configuration = CommandConfiguration(
        commandName: "path",
        abstract: "Ask whether a Broker-verified route exists between two aliases."
    )
    @Argument(completion: ResourceCLICompletion.resourceAliases) var source: String
    @Argument(completion: ResourceCLICompletion.resourceAliases) var target: String
    @Option(help: "Maximum number of topology nodes to return (1...64).") var limit: Int = 64

    func query(now: Date = Date()) throws -> TopologyQueryRequestV1 {
        let limit = try validatedTopologyLimit(limit)
        return TopologyQueryRequestV1(
            header: IPCHeader(sentAt: now, deadline: now.addingTimeInterval(30)),
            task: .reachability,
            source: try ResourceAlias(source),
            target: try ResourceAlias(target),
            bounds: TopologyQueryBoundsV1(
                maximumHops: 6,
                maximumNodes: limit,
                maximumEdges: min(128, limit * 2)
            )
        )
    }

    func run() async throws {
        do {
            try await runQuery(command: "topology.path", request: try query())
        } catch is DomainValidationError {
            try invalidInvocation(command: "topology.path", message: "A resource alias is invalid.")
        } catch TopologyCLIInputError.invalidLimit {
            try invalidInvocation(
                command: "topology.path", message: "Topology limit must be between 1 and 64.")
        }
    }
}

struct TopologyImpactCommand: AsyncParsableCommand, TopologyQueryCommand {
    static let configuration = CommandConfiguration(
        commandName: "impact",
        abstract: "Show resources that transitively depend on an alias."
    )
    @Argument(completion: ResourceCLICompletion.resourceAliases) var alias: String
    @Option(help: "Maximum number of topology nodes to return (1...64).") var limit: Int = 64

    func query(now: Date = Date()) throws -> TopologyQueryRequestV1 {
        let limit = try validatedTopologyLimit(limit)
        return TopologyQueryRequestV1(
            header: IPCHeader(sentAt: now, deadline: now.addingTimeInterval(30)),
            task: .dependencyImpact,
            target: try ResourceAlias(alias),
            bounds: TopologyQueryBoundsV1(
                maximumHops: 6,
                maximumNodes: limit,
                maximumEdges: min(128, limit * 2)
            )
        )
    }

    func run() async throws {
        do {
            try await runQuery(command: "topology.impact", request: try query())
        } catch is DomainValidationError {
            try invalidInvocation(
                command: "topology.impact", message: "The resource alias is invalid.")
        } catch TopologyCLIInputError.invalidLimit {
            try invalidInvocation(
                command: "topology.impact", message: "Topology limit must be between 1 and 64.")
        }
    }
}

protocol TopologyMutationCommand: AgentCommand {
    var source: String { get }
    var relation: String { get }
    var target: String { get }
    var action: TopologyMutationActionV1 { get }
}

extension TopologyMutationCommand {
    func mutation(now: Date = Date()) throws -> TopologyMutationRequestV1 {
        guard let parsedRelation = TopologyRelation(rawValue: relation) else {
            throw TopologyCLIInputError.invalidRelation
        }
        return TopologyMutationRequestV1(
            header: IPCHeader(sentAt: now, deadline: now.addingTimeInterval(30)),
            action: action,
            source: try ResourceAlias(source),
            relation: parsedRelation,
            target: try ResourceAlias(target)
        )
    }

    func runMutation(command: String) async throws {
        do {
            let request = try mutation()
            let reply = try await XPCBrokerAgentClient().mutateTopology(
                action: request.action,
                source: request.source,
                relation: request.relation,
                target: request.target
            )
            try finishTopology(command: command, reply: reply)
        } catch let exit as ExitCode {
            throw exit
        } catch is DomainValidationError {
            try invalidInvocation(command: command, message: "A resource alias is invalid.")
        } catch TopologyCLIInputError.invalidRelation {
            try invalidInvocation(
                command: command,
                message: "Unknown topology relation. Use located-in, member-of, runs-on, "
                    + "depends-on, backed-by, replicates-to, routed-via, or can-reach."
            )
        } catch {
            try brokerFailure(command: command)
        }
    }
}

struct TopologyLinkCommand: AsyncParsableCommand, TopologyMutationCommand {
    static let configuration = CommandConfiguration(
        commandName: "link",
        abstract: "Propose a desired relationship after macOS authorization."
    )
    @Argument(completion: ResourceCLICompletion.resourceAliases) var source: String
    @Argument(completion: TopologyCLICompletion.relations) var relation: String
    @Argument(completion: ResourceCLICompletion.resourceAliases) var target: String
    var action: TopologyMutationActionV1 { .link }

    func run() async throws {
        try await runMutation(command: "topology.link")
    }
}

struct TopologyUnlinkCommand: AsyncParsableCommand, TopologyMutationCommand {
    static let configuration = CommandConfiguration(
        commandName: "unlink",
        abstract: "Remove a desired relationship after macOS authorization."
    )
    @Argument(completion: ResourceCLICompletion.resourceAliases) var source: String
    @Argument(completion: TopologyCLICompletion.relations) var relation: String
    @Argument(completion: ResourceCLICompletion.resourceAliases) var target: String
    var action: TopologyMutationActionV1 { .unlink }

    func run() async throws {
        try await runMutation(command: "topology.unlink")
    }
}

enum TopologyCLIInputError: Error {
    case invalidRelation
    case invalidLimit
    case invalidFields
}

private func validatedTopologyLimit(_ limit: Int) throws -> Int {
    guard (1...64).contains(limit) else { throw TopologyCLIInputError.invalidLimit }
    return limit
}

private enum TopologyCLICompletion {
    static let relations = CompletionKind.list(TopologyRelation.allCases.map(\.rawValue).sorted())
}
