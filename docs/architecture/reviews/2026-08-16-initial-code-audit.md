# Initial Code Architecture Audit — 2026-08-16

Scope: the merged diagnostic MVP at `2668cbf`, compared with the existing local `ssh-hosts` Skill.

## Executive verdict

The process-level security direction is sound, but the implementation is not ready to grow directly
into authorization, sudo, and service credentials. The project has good boundaries at the package
and executable level, while several files and wire contracts have already become too broad. More
importantly, the current automatic diagnostic allowlist can expose remote process or container
secrets even though the SSH login password itself is redacted.

The next engineering work is therefore architecture remediation plus SSH parity, not persistent
audit storage.

## What is already strong

- Separate signed app, Agent CLI, per-user broker, and one-shot AskPass process roles.
- Peer signing, Team ID, effective-user, and audit-session checks at XPC acceptance.
- Data Protection Keychain with `WhenUnlockedThisDeviceOnly` and a separately encrypted vault.
- Strict per-request SSH configuration and pinned host keys instead of ambient user SSH settings.
- Child-PID-bound, expiring, single-use password delivery to `/usr/bin/ssh`.
- Bounded stdout/stderr, preserved exit status, timeout/cancellation behavior, and strict Swift 6
  concurrency checks.
- Synthetic contract, integration, and security tests that do not touch real infrastructure.

## Findings

### P0 — automatic diagnostic policy can return unrelated secrets

`MVPBrokerHandler.isMVPReadOnly` permits command names with insufficient argument validation:

- `ps eww` can expose process environments;
- `docker inspect` commonly returns container environment variables and mounted secrets;
- `systemctl show` may return unit environment and command-line values;
- `docker stats` streams until timeout unless `--no-stream` is enforced.

Only the registered SSH password is exactly redacted. Arbitrary remote secrets are not known to the
broker and cannot be reliably removed afterward. Automatic policy must constrain arguments and
fields before these commands are advertised as safe.

### P0 — advertised capability and implementation disagree

`SafeResourceProjection` advertises `shell` for every resource, while the MVP handler rejects shell
mode. CLI resource edit/disable/remove commands currently open the setup app; they are not complete
lifecycle actions. README claims need executable evidence before being presented as implemented.

### P0 — no parity path for existing SSH keys and jump routes

The app currently requires a login password plus manually entered host-key algorithm, base64 key,
and fingerprint. The existing workflow uses verified OpenSSH aliases, `BatchMode=yes`, macOS
OpenSSH/Keychain identities, and Core Tunnel routes. SAFA has Secure Enclave primitives but no
complete SSH-agent socket integration, so public-key authentication is not yet operational.

### P1 — wire contracts are too dynamic

`AgentClientOperation` and `TrustedAppOperation` rely on synthesized `Codable` enum layouts, while
`BrokerReply` and `CLIEnvelope` expose `[String: JSONValue]`. This forces CLI code to search nested
dictionaries and makes schema changes hard to review. Versioned IPC/CLI operations need explicit
discriminators and typed payload DTOs.

### P1 — files are already losing cohesion

Current largest files:

- `SAFADomain/Models.swift`: 728 lines;
- `SAFABroker/BrokerService.swift`: 473 lines;
- `SAFABroker/MVPBrokerHandler.swift`: 384 lines;
- `SAFACLI/SAFACommand.swift`: 376 lines.

They mix unrelated models, XPC adapters, listeners, runtime composition, resource projection,
execution, command families, and presentation. These should be split before adding sudo, service
profiles, or approval UI.

### P1 — onboarding is secure in intent but not humane

The user must know base64 host-key material and a fingerprint before registration. There is no SSH
config import, tunnel status, connectivity preflight, public-key selection, sudo enrollment, or
actionable per-field error. The app should guide the user through discovery and verification while
keeping private values outside the Agent surface.

### P1 — macOS primitives exist but are not complete product flows

- Secure Enclave key generation exists, but the constrained in-memory signer is not exposed through
  a real OpenSSH agent socket.
- `SMAppService` registration exists, but runtime health/remediation is a single message string.
- Keychain secret storage exists, but high-privilege user-presence access control and separate sudo
  enrollment are not implemented.
- Vault writes are atomic and encrypted, but final file-mode verification is not explicit.

### P2 — public package surface is broader than necessary

The package vends most internal library targets as products. Some are required by the Xcode app, but
the final manifest should expose only products intentionally consumed by another package or Xcode
target. This is cleanup after functional boundaries are stabilized.

## Swift CLI conformance assessment

Good:

- `AsyncParsableCommand` is used for async command trees;
- `--` protects the remote argument vector;
- JSON output is centralized and versioned;
- CLI has no Keychain access or direct SSH launch.

Needs correction:

- split command families into files and use `@OptionGroup` for common flags;
- add help text, examples, and typed `ExpressibleByArgument` values;
- replace client-side resource filtering and dynamic JSON traversal with typed broker operations;
- centralize stable error/exit mapping;
- source version data from build metadata instead of repeated `0.1.0` literals;
- add parser/help contract tests, not only response-envelope tests.

## Required remediation sequence

1. Tighten diagnostic commands and correct capability/README claims.
2. Split domain, broker XPC/runtime, broker use case, and CLI command monoliths without behavior
   changes.
3. Introduce typed DTOs for runtime status, resource list/show, and execution response, then expand
   operation-by-operation.
4. Implement trusted SSH config import, Core Tunnel preflight, host-key confirmation, and existing
   public-key execution.
5. Add separate sudo onboarding and user-presence-gated broker execution.
6. Add typed service credential profiles and constrained client adapters.
7. Return to persistent chained audit and review UI after core operations are demonstrably useful.

