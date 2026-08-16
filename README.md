# SAFA

Secure Access for Agents on macOS.

SAFA is a Skill-first, local security boundary that lets an AI Agent discover and inspect registered
SSH servers or NAS devices without receiving infrastructure credentials.

The first diagnostic MVP is implemented. It includes the four native macOS targets, signed-peer XPC
boundaries, encrypted inventory, Keychain passwords, strict pinned-host SSH configuration, one-shot
child-bound askpass, bounded process execution, private resource onboarding, safe resource
projections, read-only CLI execution and sanitized audit emission. Synthetic tests never contact a
real server.

This is not yet a production release. User-presence approval for arbitrary/sudo commands, persistent
tamper-evident audit storage, recovery, notarized packaging and the final Skill artifact remain later
Spec Kit phases. The MVP intentionally denies commands outside its read-only allowlist.

Start with:

- [Project constitution](.specify/memory/constitution.md)
- [Feature specification](specs/001-secure-agent-access/spec.md)
- [Implementation plan](specs/001-secure-agent-access/plan.md)
- [Task breakdown](specs/001-secure-agent-access/tasks.md)
- [CLI contract](specs/001-secure-agent-access/contracts/cli-v1.md)

Local MVP checks:

```bash
swift test
swift run safa version --json
xcodebuild -quiet -project Apps/SAFA/SAFA.xcodeproj -scheme SAFA \
  -configuration Debug CODE_SIGNING_ALLOWED=NO build
```

The unsigned build validates assembly only. XPC, Keychain and ServiceManagement require all four
runtime components to be signed by the same configured Developer Team.

Licensed under the MIT License.
