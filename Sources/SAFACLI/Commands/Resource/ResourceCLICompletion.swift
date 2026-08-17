import ArgumentParser
import SAFAProtocol

enum ResourceCLICompletion {
    static let resourceStates = CompletionKind.list([
        "draft", "active", "disabled",
    ])

    static let editableResourceStates = CompletionKind.list([
        "active", "disabled",
    ])

    static let hostTypes = CompletionKind.list([
        "host.linux", "host.macos", "host.windows",
    ])

    static let templates = CompletionKind.list([
        "ssh", "mysql", "postgresql", "sqlserver", "mongodb", "s3", "minio", "oss", "redis",
        "kafka", "rabbitmq", "elasticsearch", "neo4j", "http",
    ])

    static let resourceAliases = CompletionKind.custom(completeResourceAliases)

    static func filterAliases(_ aliases: [String], prefix: String) -> [String] {
        Set(aliases)
            .filter { prefix.isEmpty || $0.hasPrefix(prefix) }
            .sorted()
    }

    private static func completeResourceAliases(
        _: [String],
        _: Int,
        prefix: String
    ) async -> [String] {
        guard
            let reply = try? await XPCBrokerAgentClient()
                .queryResourceDirectoryForCompletion(),
            reply.status == .completed
        else {
            return []
        }
        return filterAliases(reply.summaries.map(\.alias), prefix: prefix)
    }
}
