# Topology Projection v1 (Runtime Mirror)

**Status**: Implemented and covered by domain, contract, integration, and leakage tests.

The canonical public contract is
`juju-w/safa/contracts/topology-projection-v1.md`. This Runtime mirror records the implementation
requirements used by the current Spec Kit plan.

## Domain

Topology is a directed, typed, attributed multigraph, never a rendered diagram or prose document.
It contains:

- context or resource nodes of kind `resource`, `site`, `security-domain`, `network-segment`,
  `runtime`, or `route`;
- explicit directed edges including `located-in`, `member-of`, `runs-on`, `depends-on`,
  `backed-by`, `replicates-to`, `routed-via`, and `can-reach`;
- `desired`, `observed`, and `derived` trust layers;
- `asserted`, `verified`, `stale`, and `failed` verification states;
- immutable IDs, revisions, visibility, provenance, evidence freshness, and Broker-only evidence
  references.

Agent proposals create only desired/asserted claims. Only a trusted adapter or Broker computation
may create verified observed/derived edges. A verified path is evidence, not approval or credential
authority.

## Projection

The Agent receives a bounded `dev.safa.topology/v1` JSON projection containing:

```text
schema
graph_revision
task
ordering
roots[]
nodes[{alias, kind, allowlisted attributes}]
edges[{id, from, relation, to, layer, verification, freshness}]
answer{outcome, source, target, affected_aliases[], proof_edge_ids[]}
matrix?
truncated
```

No Agent projection contains an IP, CIDR, DNS endpoint, port, username, credential role or locator,
host identity, raw probe output, policy internals, or physical route coordinates. Context and
resource aliases and abstract relationships are visible only when a trusted local flow marks them
Agent-safe.

Persistence order is irrelevant. Canonical normalization uses stable identity; task projections
declare their ordering:

| Task | Projection |
|---|---|
| inventory/placement | node table and typed edge list ordered by kind and alias |
| reachability/routes | adjacency list and Broker proof ordered source-rooted breadth-first |
| dependency impact | reverse adjacency list and computed affected set |
| small homogeneous dense comparison | bounded relation matrix with stable alias legend |
| human overview | derived diagram plus the same textual projection |

Queries require explicit roots, relation allowlists, direction, and hop/node/edge limits. The Broker
computes exact graph results and returns supporting edge IDs. MVP subgraph selection is deterministic;
semantic retrieval may find candidate roots later but never proves connectivity.

Visual diagrams are optional derived artifacts. Layout, color, proximity, and arrow routing carry no
authority, and a multimodal interpretation can never create a verified edge.

## Agent CLI

The Runtime exposes only five semantic verbs: `topology show`, `topology path`, `topology impact`,
`topology link`, and `topology unlink`. Queries are safe, bounded projections. Mutations require
macOS user presence and can change desired/asserted edges only. Dense comparison and cycle checks
remain internal Broker capabilities so simpler Agents do not need to choose graph algorithms.
`link` may create a missing context node only from a constrained one-segment `site.*`, `domain.*`,
`network.*`, `runtime.*`, or `route.*` semantic alias; IP/CIDR/DNS-shaped context is rejected.
