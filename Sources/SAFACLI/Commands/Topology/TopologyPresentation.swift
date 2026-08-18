import SAFAProtocol

extension AgentCommand {
    func finishTopology(
        command: String,
        reply: TopologyQueryReplyV1,
        nodeFields: [AgentTopologyNodeFieldV2] = AgentTopologyNodeFieldV2.defaultFields
    ) throws {
        if let projection = reply.projection {
            try finish(
                AgentCLIResponseV2(
                    command: command,
                    status: reply.status == .completed ? .completed : .failed,
                    payload: projection.agentPayload(nodeFields: nodeFields),
                    error: reply.error?.agentError
                )
            )
            return
        }
        try finish(
            AgentCLIResponseV2(
                command: command,
                status: .failed,
                payload: AgentNoPayloadV2(),
                error: reply.error?.agentError
            )
        )
    }

    func finishTopology(command: String, reply: TopologyMutationReplyV1) throws {
        let status: AgentCLIStatusV2
        switch reply.status {
        case .completed: status = .completed
        case .denied: status = .denied
        case .failed: status = .failed
        }
        try finish(
            AgentCLIResponseV2(
                command: command,
                status: status,
                payload: AgentTopologyMutationPayloadV2(
                    graphRevision: reply.graphRevision,
                    edge: reply.edge?.agentEdge
                ),
                error: reply.error?.agentError
            )
        )
    }
}

private extension TopologyProjectionV1 {
    func agentPayload(nodeFields: [AgentTopologyNodeFieldV2]) -> AgentTopologyPayloadV2 {
        AgentTopologyPayloadV2(
            graphRevision: graphRevision,
            task: task.rawValue,
            ordering: ordering.rawValue,
            roots: roots,
            nodes: nodes.map {
                AgentTopologyNodeV2(
                    alias: $0.alias,
                    kind: $0.kind,
                    resourceKind: $0.resourceKind
                )
            },
            edges: edges.map(\.agentEdge),
            answer: AgentTopologyAnswerV2(
                outcome: answer.outcome.rawValue,
                source: answer.source,
                target: answer.target,
                affectedAliases: answer.affectedAliases,
                proofEdgeIDs: answer.proofEdgeIDs
            ),
            matrix: matrix.map {
                AgentTopologyMatrixV2(aliases: $0.aliases, values: $0.values)
            },
            truncated: truncated,
            nodeFields: nodeFields
        )
    }
}

private extension TopologyEdgeV1 {
    var agentEdge: AgentTopologyEdgeV2 {
        AgentTopologyEdgeV2(id: id, from: from, relation: relation, to: to)
    }
}
