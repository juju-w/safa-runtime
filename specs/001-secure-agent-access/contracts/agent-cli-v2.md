# Agent CLI v2 Runtime Binding

The product repository owns the normative
[`dev.safa.cli/v2` contract](https://github.com/juju-w/safa/blob/main/contracts/cli-v2.md). This
Runtime implements that TOON-only AXI surface from explicit DTOs in `Sources/SAFAProtocol/Agent/`
and the final presentation adapter in `Sources/SAFACLI/Presentation/`.

Runtime conformance is pinned to TOON 4.1.1:

- specification commit: `62f16b369408180f1faf1cba7da1b46d1f336f12`;
- reference implementation commit: `f06ddca16c8a4ccd091f33d7216c543e10a9c681`;
- product fixture mirror: `conformance/toon-v4.1/agent-cli-v2/`.

Broker IPC, vault persistence, resource projections, and topology projections retain their own
private versioning. They never become alternate Agent-facing encodings. Apart from the bare SemVer
fast path, each CLI invocation writes exactly one canonical TOON document and uses only process exits
0, 1, or 2.
