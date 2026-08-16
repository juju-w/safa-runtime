# SAFA

Secure Access for Agents on macOS.

SAFA is a Skill-first, local security boundary that lets an AI Agent discover and operate registered
SSH servers or NAS devices without receiving infrastructure credentials. Arbitrary commands remain
available through resource-scoped policy, trusted macOS approval, expiry, revocation, and audit.

The repository is currently in specification and initialization stage. The companion runtime is not
implemented and the development Skill intentionally returns `runtime_missing` without accessing any
server.

Start with:

- [Project constitution](.specify/memory/constitution.md)
- [Feature specification](specs/001-secure-agent-access/spec.md)
- [Implementation plan](specs/001-secure-agent-access/plan.md)
- [Task breakdown](specs/001-secure-agent-access/tasks.md)
- [CLI contract](specs/001-secure-agent-access/contracts/cli-v1.md)

Licensed under the MIT License.
