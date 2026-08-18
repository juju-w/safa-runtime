import SAFAProtocol

extension AgentTopologyPayloadV2: AgentCLIToonPayload {
    func toonFields() -> [TOONField] {
        [
            TOONField(key: "graph_revision", value: .integer(Int64(clamping: graphRevision))),
            TOONField(key: "task", value: .string(task)),
            TOONField(key: "ordering", value: .string(ordering)),
            TOONField(key: "answer", value: answer.toonValue),
            TOONField(
                key: "count",
                value: .object([
                    TOONField(key: "nodes", value: .integer(Int64(clamping: nodes.count))),
                    TOONField(key: "edges", value: .integer(Int64(clamping: edges.count))),
                    TOONField(key: "truncated", value: .boolean(truncated)),
                ])
            ),
            TOONField(key: "roots", value: .array(roots.map(TOONValue.string))),
            TOONField(
                key: "nodes",
                value: .array(nodes.map { $0.toonValue(fields: nodeFields) })
            ),
            TOONField(key: "edges", value: .array(edges.map(\.toonValue))),
            TOONField(key: "matrix", value: matrix?.toonValue ?? .null),
        ]
    }
}

extension AgentTopologyMutationPayloadV2: AgentCLIToonPayload {
    func toonFields() -> [TOONField] {
        [
            TOONField(
                key: "graph_revision",
                value: graphRevision.map { .integer(Int64(clamping: $0)) } ?? .null
            ),
            TOONField(key: "edge", value: edge?.toonValue ?? .null),
        ]
    }
}

private extension AgentTopologyNodeV2 {
    func toonValue(fields: [AgentTopologyNodeFieldV2]) -> TOONValue {
        .object(
            fields.map { field in
                switch field {
                case .alias: TOONField(key: field.rawValue, value: .string(alias))
                case .kind: TOONField(key: field.rawValue, value: .string(kind))
                case .resourceKind:
                    TOONField(
                        key: field.rawValue,
                        value: resourceKind.map(TOONValue.string) ?? .null
                    )
                }
            }
        )
    }
}

private extension AgentTopologyEdgeV2 {
    var toonValue: TOONValue {
        .object([
            TOONField(key: "id", value: .string(id)),
            TOONField(key: "from", value: .string(from)),
            TOONField(key: "relation", value: .string(relation)),
            TOONField(key: "to", value: .string(to)),
        ])
    }
}

private extension AgentTopologyAnswerV2 {
    var toonValue: TOONValue {
        .object([
            TOONField(key: "outcome", value: .string(outcome)),
            TOONField(key: "source", value: source.map(TOONValue.string) ?? .null),
            TOONField(key: "target", value: target.map(TOONValue.string) ?? .null),
            TOONField(
                key: "affected_aliases",
                value: .array(affectedAliases.map(TOONValue.string))
            ),
            TOONField(
                key: "proof_edge_ids",
                value: .array(proofEdgeIDs.map(TOONValue.string))
            ),
        ])
    }
}

private extension AgentTopologyMatrixV2 {
    var toonValue: TOONValue {
        .object([
            TOONField(key: "aliases", value: .array(aliases.map(TOONValue.string))),
            TOONField(
                key: "values",
                value: .array(
                    values.map { row in .array(row.map(TOONValue.boolean)) }
                )
            ),
        ])
    }
}
