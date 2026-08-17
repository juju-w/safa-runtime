import ArgumentParser
import SAFAProtocol

extension JSONCommand {
    func emitTopology(command: String, reply: TopologyQueryReplyV1) throws {
        let status: CLIStatus = reply.status == .completed ? .completed : .failed
        var data: [String: JSONValue] = [:]
        if let projection = reply.projection { data["topology"] = projection.jsonValue }
        if let error = reply.error { data["error"] = .object(error.jsonObject) }
        let human = reply.error?.message ?? reply.projection?.humanSummary ?? "No topology result."
        try emit(CLIEnvelope(command: command, status: status, data: data), humanMessage: human)
        if reply.status == .failed {
            throw ExitCode(SAFAProcessExit.map(errorCode: reply.error?.code).rawValue)
        }
    }

    func emitTopology(command: String, reply: TopologyMutationReplyV1) throws {
        let status: CLIStatus
        switch reply.status {
        case .completed: status = .completed
        case .denied: status = .denied
        case .failed: status = .failed
        }
        var data: [String: JSONValue] = [:]
        if let revision = reply.graphRevision {
            data["graph_revision"] = .integer(Int64(clamping: revision))
        }
        if let edge = reply.edge { data["edge"] = edge.jsonValue }
        if let error = reply.error { data["error"] = .object(error.jsonObject) }
        let human =
            reply.error?.message
            ?? reply.edge.map { "\($0.from) \($0.relation) \($0.to)" }
            ?? "Topology changed."
        try emit(CLIEnvelope(command: command, status: status, data: data), humanMessage: human)
        switch reply.status {
        case .completed: return
        case .denied: throw ExitCode(SAFAProcessExit.denied.rawValue)
        case .failed:
            throw ExitCode(SAFAProcessExit.map(errorCode: reply.error?.code).rawValue)
        }
    }
}

private extension TopologyProjectionV1 {
    var jsonValue: JSONValue {
        var object: [String: JSONValue] = [
            "schema": .string(schema),
            "graph_revision": .integer(Int64(clamping: graphRevision)),
            "task": .string(task.rawValue),
            "ordering": .string(ordering.rawValue),
            "roots": .array(roots.map(JSONValue.string)),
            "nodes": .array(nodes.map(\.jsonValue)),
            "edges": .array(edges.map(\.jsonValue)),
            "answer": answer.jsonValue,
            "truncated": .boolean(truncated),
        ]
        object["matrix"] = matrix.map(\.jsonValue) ?? .null
        return .object(object)
    }

    var humanSummary: String {
        switch answer.outcome {
        case .confirmed:
            return "\(answer.source ?? "source") can reach \(answer.target ?? "target")."
        case .notFound:
            return "No verified path from \(answer.source ?? "source") to "
                + "\(answer.target ?? "target")."
        case .indeterminate:
            return "Topology bounds prevented a conclusive answer."
        case .found where task == .dependencyImpact:
            return answer.affectedAliases.isEmpty
                ? "No registered dependent resources."
                : answer.affectedAliases.joined(separator: "\n")
        case .found, .listed:
            return nodes.isEmpty ? "No topology nodes." : nodes.map(\.alias).joined(separator: "\n")
        }
    }
}

private extension TopologyNodeV1 {
    var jsonValue: JSONValue {
        .object([
            "alias": .string(alias),
            "kind": .string(kind),
            "resource_kind": resourceKind.map(JSONValue.string) ?? .null,
        ])
    }
}

private extension TopologyEdgeV1 {
    var jsonValue: JSONValue {
        .object([
            "id": .string(id),
            "from": .string(from),
            "relation": .string(relation),
            "to": .string(to),
            "layer": .string(layer),
            "verification": .string(verification),
            "freshness": .string(freshness),
        ])
    }
}

private extension TopologyAnswerV1 {
    var jsonValue: JSONValue {
        .object([
            "outcome": .string(outcome.rawValue),
            "source": source.map(JSONValue.string) ?? .null,
            "target": target.map(JSONValue.string) ?? .null,
            "affected_aliases": .array(affectedAliases.map(JSONValue.string)),
            "proof_edge_ids": .array(proofEdgeIDs.map(JSONValue.string)),
        ])
    }
}

private extension TopologyMatrixV1 {
    var jsonValue: JSONValue {
        .object([
            "aliases": .array(aliases.map(JSONValue.string)),
            "values": .array(
                values.map { row in .array(row.map(JSONValue.boolean)) }
            ),
        ])
    }
}
