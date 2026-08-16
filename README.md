# SAFA

Secure Access for Agents on macOS.

SAFA is a Skill-first, local security boundary that lets an AI Agent discover and operate registered
SSH servers or NAS devices without receiving infrastructure credentials. Arbitrary commands remain
available through resource-scoped policy, trusted macOS approval, expiry, revocation, and audit.

The repository now contains the first M0 foundation: a Swift 6 package graph, versioned CLI/XPC data
contracts, domain state machines, deterministic request fingerprints, a data-protection Keychain
abstraction, and an AES-GCM vault with tamper/copy/rollback tests. The native signed app, broker XPC
listener, approval UI, and SSH execution path are not implemented yet. The packaged development
Skill therefore still returns `runtime_missing` without accessing any server.

Start with:

- [Project constitution](.specify/memory/constitution.md)
- [Feature specification](specs/001-secure-agent-access/spec.md)
- [Implementation plan](specs/001-secure-agent-access/plan.md)
- [Task breakdown](specs/001-secure-agent-access/tasks.md)
- [CLI contract](specs/001-secure-agent-access/contracts/cli-v1.md)

Local foundation checks:

```bash
swift test
swift run safa version --json
swift run safa doctor --json  # deliberately exits 22 until the signed broker exists
```

Licensed under the MIT License.
