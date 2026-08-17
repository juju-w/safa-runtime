import Foundation

public enum TopologyProjectionTask: String, Codable, Sendable {
    case inventory
    case placement
    case reachability
    case dependencyImpact = "dependency-impact"
    case denseComparison = "dense-comparison"
}

public enum TopologyProjectionOrdering: String, Codable, Sendable {
    case aliasAscending = "alias-ascending"
    case sourceRootedBreadthFirst = "source-rooted-breadth-first"
    case targetRootedReverseBreadthFirst = "target-rooted-reverse-breadth-first"
}

public enum TopologyAnswerOutcome: String, Codable, Sendable {
    case listed
    case found
    case confirmed
    case notFound = "not-found"
    case indeterminate
}

public enum TopologyQueryError: Error, Equatable, Sendable {
    case invalidBounds
    case aliasNotFound(String)
    case invalidShape
}

public struct TopologyQueryBounds: Codable, Equatable, Sendable {
    public let maximumHops: Int
    public let maximumNodes: Int
    public let maximumEdges: Int

    public init(maximumHops: Int = 6, maximumNodes: Int = 64, maximumEdges: Int = 128) throws {
        guard (1...16).contains(maximumHops),
            (1...256).contains(maximumNodes),
            (1...1_024).contains(maximumEdges)
        else {
            throw TopologyQueryError.invalidBounds
        }
        self.maximumHops = maximumHops
        self.maximumNodes = maximumNodes
        self.maximumEdges = maximumEdges
    }

    public static let `default` = try! Self()
}

public struct TopologyQuery: Equatable, Sendable {
    public let task: TopologyProjectionTask
    public let source: ResourceAlias?
    public let target: ResourceAlias?
    public let relation: TopologyRelation?
    public let bounds: TopologyQueryBounds

    private init(
        task: TopologyProjectionTask,
        source: ResourceAlias? = nil,
        target: ResourceAlias? = nil,
        relation: TopologyRelation? = nil,
        bounds: TopologyQueryBounds
    ) {
        self.task = task
        self.source = source
        self.target = target
        self.relation = relation
        self.bounds = bounds
    }

    public static func inventory(bounds: TopologyQueryBounds = .default) -> Self {
        Self(task: .inventory, bounds: bounds)
    }

    public static func placement(
        of alias: ResourceAlias,
        bounds: TopologyQueryBounds = .default
    ) -> Self {
        Self(task: .placement, source: alias, bounds: bounds)
    }

    public static func reachability(
        from source: ResourceAlias,
        to target: ResourceAlias,
        bounds: TopologyQueryBounds = .default
    ) -> Self {
        Self(task: .reachability, source: source, target: target, bounds: bounds)
    }

    public static func dependencyImpact(
        of alias: ResourceAlias,
        bounds: TopologyQueryBounds = .default
    ) -> Self {
        Self(task: .dependencyImpact, target: alias, bounds: bounds)
    }

    public static func denseComparison(
        relation: TopologyRelation,
        bounds: TopologyQueryBounds = .default
    ) -> Self {
        Self(task: .denseComparison, relation: relation, bounds: bounds)
    }
}

public struct ProjectedTopologyNode: Equatable, Sendable {
    public let alias: ResourceAlias
    public let kind: TopologyNodeKind
    public let resourceKind: ResourceKindIdentifier?
}

public struct ProjectedTopologyEdge: Equatable, Sendable {
    public let id: UUID
    public let from: ResourceAlias
    public let relation: TopologyRelation
    public let to: ResourceAlias
    public let layer: TopologyLayer
    public let verification: TopologyVerification
    public let freshness: TopologyFreshness
}

public struct TopologyQueryAnswer: Equatable, Sendable {
    public let outcome: TopologyAnswerOutcome
    public let source: ResourceAlias?
    public let target: ResourceAlias?
    public let affectedAliases: [ResourceAlias]
    public let proofEdgeIDs: [UUID]
}

public struct TopologyRelationMatrix: Equatable, Sendable {
    public let aliases: [ResourceAlias]
    public let values: [[Bool]]
}

public struct TopologyQueryResult: Equatable, Sendable {
    public let graphRevision: UInt64
    public let task: TopologyProjectionTask
    public let ordering: TopologyProjectionOrdering
    public let roots: [ResourceAlias]
    public let nodes: [ProjectedTopologyNode]
    public let edges: [ProjectedTopologyEdge]
    public let answer: TopologyQueryAnswer
    public let matrix: TopologyRelationMatrix?
    public let truncated: Bool
}

public enum TopologyQueryEngine {
    public static func query(
        graph: TopologyGraph,
        query: TopologyQuery,
        now: Date = Date()
    ) throws -> TopologyQueryResult {
        let view = AgentGraphView(graph: graph, now: now)
        switch query.task {
        case .inventory:
            return inventory(view: view, graphRevision: graph.revision, query: query)
        case .placement:
            return try placement(view: view, graphRevision: graph.revision, query: query)
        case .reachability:
            return try reachability(view: view, graphRevision: graph.revision, query: query)
        case .dependencyImpact:
            return try impact(view: view, graphRevision: graph.revision, query: query)
        case .denseComparison:
            return dense(view: view, graphRevision: graph.revision, query: query)
        }
    }

    /// Exact cycle detection for dependency-like relations. Storage order cannot affect the result.
    public static func hasCycle(
        graph: TopologyGraph,
        relations: Set<TopologyRelation>,
        now: Date = Date()
    ) -> Bool {
        let view = AgentGraphView(graph: graph, now: now)
        let adjacency = Dictionary(
            grouping: view.edges.filter {
                relations.contains($0.edge.relation) && $0.freshness != .failed
            }, by: { $0.edge.fromNodeID })
        var complete = Set<UUID>()
        var active = Set<UUID>()

        func visit(_ nodeID: UUID) -> Bool {
            if active.contains(nodeID) { return true }
            if complete.contains(nodeID) { return false }
            active.insert(nodeID)
            let neighbors = (adjacency[nodeID] ?? []).map { $0.edge.toNodeID }.sorted {
                $0.uuidString.lowercased() < $1.uuidString.lowercased()
            }
            for neighbor in neighbors where visit(neighbor) { return true }
            active.remove(nodeID)
            complete.insert(nodeID)
            return false
        }

        return view.nodes.map(\.id).contains(where: visit)
    }

    private static func inventory(
        view: AgentGraphView,
        graphRevision: UInt64,
        query: TopologyQuery
    ) -> TopologyQueryResult {
        let selectedNodes = Array(view.nodes.prefix(query.bounds.maximumNodes))
        let selectedIDs = Set(selectedNodes.map(\.id))
        let selectedEdges = Array(
            view.edges.filter {
                selectedIDs.contains($0.edge.fromNodeID) && selectedIDs.contains($0.edge.toNodeID)
            }.prefix(query.bounds.maximumEdges)
        )
        return result(
            revision: graphRevision,
            query: query,
            ordering: .aliasAscending,
            roots: [],
            nodes: selectedNodes,
            edges: selectedEdges,
            outcome: .listed,
            affected: [],
            proof: [],
            matrix: nil,
            truncated: selectedNodes.count < view.nodes.count
                || selectedEdges.count < view.edges.count
        )
    }

    private static func placement(
        view: AgentGraphView,
        graphRevision: UInt64,
        query: TopologyQuery
    ) throws -> TopologyQueryResult {
        guard let source = query.source else { throw TopologyQueryError.invalidShape }
        let root = try view.node(alias: source)
        let walk = view.walk(
            rootID: root.id,
            reverse: false,
            undirected: true,
            allowedRelations: [.locatedIn, .memberOf, .runsOn, .routedVia],
            requireFreshProof: false,
            bounds: query.bounds
        )
        return result(
            revision: graphRevision,
            query: query,
            ordering: .sourceRootedBreadthFirst,
            roots: [source],
            nodes: walk.nodes,
            edges: walk.edges,
            outcome: .found,
            affected: [],
            proof: [],
            matrix: nil,
            truncated: walk.truncated
        )
    }

    private static func reachability(
        view: AgentGraphView,
        graphRevision: UInt64,
        query: TopologyQuery
    ) throws -> TopologyQueryResult {
        guard let source = query.source, let target = query.target else {
            throw TopologyQueryError.invalidShape
        }
        let sourceNode = try view.node(alias: source)
        let targetNode = try view.node(alias: target)
        let path = view.shortestPath(
            from: sourceNode.id,
            to: targetNode.id,
            allowedRelations: [.canReach, .routedVia],
            bounds: query.bounds
        )
        let neighborhood = view.walk(
            rootID: sourceNode.id,
            reverse: false,
            undirected: false,
            allowedRelations: [.canReach, .routedVia],
            requireFreshProof: false,
            bounds: query.bounds
        )
        var projectedNodes = neighborhood.nodes
        if !projectedNodes.contains(where: { $0.id == targetNode.id }),
            projectedNodes.count < query.bounds.maximumNodes
        {
            projectedNodes.append(targetNode)
        }
        let outcome: TopologyAnswerOutcome =
            path.edgeIDs != nil
            ? .confirmed
            : (path.truncated ? .indeterminate : .notFound)
        return result(
            revision: graphRevision,
            query: query,
            ordering: .sourceRootedBreadthFirst,
            roots: [source, target],
            nodes: projectedNodes,
            edges: neighborhood.edges,
            outcome: outcome,
            affected: [],
            proof: path.edgeIDs ?? [],
            matrix: nil,
            truncated: path.truncated || neighborhood.truncated
        )
    }

    private static func impact(
        view: AgentGraphView,
        graphRevision: UInt64,
        query: TopologyQuery
    ) throws -> TopologyQueryResult {
        guard let target = query.target else { throw TopologyQueryError.invalidShape }
        let root = try view.node(alias: target)
        let walk = view.walk(
            rootID: root.id,
            reverse: true,
            undirected: false,
            allowedRelations: [.dependsOn, .runsOn, .backedBy],
            requireFreshProof: false,
            bounds: query.bounds
        )
        let affected = walk.nodes.map(\.alias).filter { $0 != target }.sorted(by: aliasLess)
        return result(
            revision: graphRevision,
            query: query,
            ordering: .targetRootedReverseBreadthFirst,
            roots: [target],
            nodes: walk.nodes,
            edges: walk.edges,
            outcome: .found,
            affected: affected,
            proof: [],
            matrix: nil,
            truncated: walk.truncated
        )
    }

    private static func dense(
        view: AgentGraphView,
        graphRevision: UInt64,
        query: TopologyQuery
    ) -> TopologyQueryResult {
        let relation = query.relation
        let nodes = Array(view.nodes.prefix(query.bounds.maximumNodes))
        let aliases = nodes.map(\.alias)
        let index = Dictionary(uniqueKeysWithValues: nodes.enumerated().map { ($1.id, $0) })
        var values = Array(
            repeating: Array(repeating: false, count: aliases.count),
            count: aliases.count
        )
        let edges = Array(
            view.edges.filter { item in
                item.edge.relation == relation && index[item.edge.fromNodeID] != nil
                    && index[item.edge.toNodeID] != nil
            }.prefix(query.bounds.maximumEdges)
        )
        for item in edges {
            if let row = index[item.edge.fromNodeID], let column = index[item.edge.toNodeID] {
                values[row][column] = true
            }
        }
        return result(
            revision: graphRevision,
            query: query,
            ordering: .aliasAscending,
            roots: [],
            nodes: nodes,
            edges: edges,
            outcome: .listed,
            affected: [],
            proof: [],
            matrix: TopologyRelationMatrix(aliases: aliases, values: values),
            truncated: nodes.count < view.nodes.count || edges.count < view.edges.count
        )
    }

    private static func result(
        revision: UInt64,
        query: TopologyQuery,
        ordering: TopologyProjectionOrdering,
        roots: [ResourceAlias],
        nodes: [TopologyNode],
        edges: [AgentGraphView.VisibleEdge],
        outcome: TopologyAnswerOutcome,
        affected: [ResourceAlias],
        proof: [UUID],
        matrix: TopologyRelationMatrix?,
        truncated: Bool
    ) -> TopologyQueryResult {
        TopologyQueryResult(
            graphRevision: revision,
            task: query.task,
            ordering: ordering,
            roots: roots,
            nodes: nodes.map {
                ProjectedTopologyNode(alias: $0.alias, kind: $0.kind, resourceKind: $0.resourceKind)
            },
            edges: edges.map {
                ProjectedTopologyEdge(
                    id: $0.edge.id,
                    from: $0.from.alias,
                    relation: $0.edge.relation,
                    to: $0.to.alias,
                    layer: $0.edge.layer,
                    verification: $0.edge.verification,
                    freshness: $0.freshness
                )
            },
            answer: TopologyQueryAnswer(
                outcome: outcome,
                source: query.source,
                target: query.target,
                affectedAliases: affected,
                proofEdgeIDs: proof
            ),
            matrix: matrix,
            truncated: truncated
        )
    }

    private static func aliasLess(_ lhs: ResourceAlias, _ rhs: ResourceAlias) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

private struct AgentGraphView {
    struct VisibleEdge: Equatable {
        let edge: TopologyEdge
        let from: TopologyNode
        let to: TopologyNode
        let freshness: TopologyFreshness
    }

    struct Walk {
        let nodes: [TopologyNode]
        let edges: [VisibleEdge]
        let truncated: Bool
    }

    struct Path {
        let edgeIDs: [UUID]?
        let truncated: Bool
    }

    let nodes: [TopologyNode]
    let edges: [VisibleEdge]
    private let nodesByAlias: [ResourceAlias: TopologyNode]

    init(graph: TopologyGraph, now: Date) {
        nodes = graph.nodes.filter { $0.visibility == .agent }.sorted { lhs, rhs in
            lhs.alias.rawValue < rhs.alias.rawValue
        }
        let byID = Dictionary(uniqueKeysWithValues: nodes.map { ($0.id, $0) })
        nodesByAlias = Dictionary(uniqueKeysWithValues: nodes.map { ($0.alias, $0) })
        edges = graph.edges.compactMap { edge in
            guard edge.visibility == .agent,
                let from = byID[edge.fromNodeID],
                let to = byID[edge.toNodeID]
            else { return nil }
            return VisibleEdge(edge: edge, from: from, to: to, freshness: edge.freshness(at: now))
        }.sorted(by: Self.edgeLess)
    }

    func node(alias: ResourceAlias) throws -> TopologyNode {
        guard let node = nodesByAlias[alias] else {
            throw TopologyQueryError.aliasNotFound(alias.rawValue)
        }
        return node
    }

    func walk(
        rootID: UUID,
        reverse: Bool,
        undirected: Bool,
        allowedRelations: Set<TopologyRelation>,
        requireFreshProof: Bool,
        bounds: TopologyQueryBounds
    ) -> Walk {
        var visited: Set<UUID> = [rootID]
        var orderedIDs: [UUID] = [rootID]
        var selectedEdges: [VisibleEdge] = []
        var queue: [(UUID, Int)] = [(rootID, 0)]
        var truncated = false
        while !queue.isEmpty {
            let (current, depth) = queue.removeFirst()
            guard depth < bounds.maximumHops else {
                if adjacent(
                    to: current, reverse: reverse, undirected: undirected,
                    allowed: allowedRelations, freshOnly: requireFreshProof
                ).isEmpty == false {
                    truncated = true
                }
                continue
            }
            for candidate in adjacent(
                to: current,
                reverse: reverse,
                undirected: undirected,
                allowed: allowedRelations,
                freshOnly: requireFreshProof
            ) {
                let next = candidate.next
                guard !visited.contains(next) else { continue }
                guard orderedIDs.count < bounds.maximumNodes,
                    selectedEdges.count < bounds.maximumEdges
                else {
                    truncated = true
                    continue
                }
                visited.insert(next)
                orderedIDs.append(next)
                selectedEdges.append(candidate.edge)
                queue.append((next, depth + 1))
            }
        }
        let byID = Dictionary(uniqueKeysWithValues: nodes.map { ($0.id, $0) })
        return Walk(
            nodes: orderedIDs.compactMap { byID[$0] },
            edges: selectedEdges,
            truncated: truncated
        )
    }

    func shortestPath(
        from source: UUID,
        to target: UUID,
        allowedRelations: Set<TopologyRelation>,
        bounds: TopologyQueryBounds
    ) -> Path {
        if source == target { return Path(edgeIDs: [], truncated: false) }
        var visited: Set<UUID> = [source]
        var queue: [(UUID, Int)] = [(source, 0)]
        var predecessor: [UUID: (UUID, UUID)] = [:]
        var traversedEdges = 0
        var truncated = false
        while !queue.isEmpty {
            let (current, depth) = queue.removeFirst()
            guard depth < bounds.maximumHops else {
                if adjacent(
                    to: current, reverse: false, undirected: false,
                    allowed: allowedRelations, freshOnly: true
                ).isEmpty == false {
                    truncated = true
                }
                continue
            }
            for candidate in adjacent(
                to: current,
                reverse: false,
                undirected: false,
                allowed: allowedRelations,
                freshOnly: true
            ) {
                guard traversedEdges < bounds.maximumEdges, visited.count < bounds.maximumNodes
                else {
                    truncated = true
                    continue
                }
                traversedEdges += 1
                guard visited.insert(candidate.next).inserted else { continue }
                predecessor[candidate.next] = (current, candidate.edge.edge.id)
                if candidate.next == target {
                    var cursor = target
                    var path: [UUID] = []
                    while cursor != source, let step = predecessor[cursor] {
                        path.append(step.1)
                        cursor = step.0
                    }
                    return Path(edgeIDs: path.reversed(), truncated: truncated)
                }
                queue.append((candidate.next, depth + 1))
            }
        }
        return Path(edgeIDs: nil, truncated: truncated)
    }

    private func adjacent(
        to nodeID: UUID,
        reverse: Bool,
        undirected: Bool,
        allowed: Set<TopologyRelation>,
        freshOnly: Bool
    ) -> [(edge: VisibleEdge, next: UUID)] {
        edges.compactMap { item in
            guard allowed.contains(item.edge.relation), item.freshness != .failed else {
                return nil
            }
            if freshOnly, item.freshness != .fresh { return nil }
            if !reverse, item.edge.fromNodeID == nodeID {
                return (item, item.edge.toNodeID)
            }
            if reverse, item.edge.toNodeID == nodeID {
                return (item, item.edge.fromNodeID)
            }
            if undirected, item.edge.toNodeID == nodeID {
                return (item, item.edge.fromNodeID)
            }
            return nil
        }.sorted { lhs, rhs in
            let leftAlias = nodes.first(where: { $0.id == lhs.next })?.alias.rawValue ?? ""
            let rightAlias = nodes.first(where: { $0.id == rhs.next })?.alias.rawValue ?? ""
            if leftAlias != rightAlias { return leftAlias < rightAlias }
            return Self.edgeLess(lhs.edge, rhs.edge)
        }
    }

    private static func edgeLess(_ lhs: VisibleEdge, _ rhs: VisibleEdge) -> Bool {
        let left = (
            lhs.from.alias.rawValue,
            lhs.edge.relation.rawValue,
            lhs.to.alias.rawValue,
            lhs.edge.id.uuidString.lowercased()
        )
        let right = (
            rhs.from.alias.rawValue,
            rhs.edge.relation.rawValue,
            rhs.to.alias.rawValue,
            rhs.edge.id.uuidString.lowercased()
        )
        if left.0 != right.0 { return left.0 < right.0 }
        if left.1 != right.1 { return left.1 < right.1 }
        if left.2 != right.2 { return left.2 < right.2 }
        return left.3 < right.3
    }
}
