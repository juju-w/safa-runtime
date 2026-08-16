# Implementation Plan: Secure Agent Access

> Repository split: Skill/resolver/manifest ownership moved to `juju-w/safa`. Runtime source,
> platform security, packaging inputs, and native validation remain in this repository.

**Branch**: `001-secure-agent-access` | **Date**: 2026-08-16 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/001-secure-agent-access/spec.md`

## Summary

Build SAFA as a macOS-only Agent Skill backed by a signed native CLI and companion runtime. The runtime
keeps the encrypted resource registry and credentials outside the Agent process, evaluates scoped
execution policy, obtains trusted local approval for elevated operations, invokes the system SSH
client, and returns a compact versioned JSON envelope. Arbitrary command and shell execution remain
a target capability for M2; the current diagnostic MVP exposes only bounded non-sudo argument
execution.

The MVP supports one local macOS user and SSH-accessible servers/NAS devices. The underlying resource
directory is adapter-independent so later database, object-storage, cache, and service profiles do
not fork the security architecture. Delivery first covers
SSH-config import, tunnel preflight, public-key execution, strict host identity, read-only
diagnostics, Keychain-backed sudo migration, encrypted inventory, and compact CLI contracts.
Arbitrary mutation, general execution authorization/audit, team vaults, non-SSH execution adapters,
and custom GUI are deferred until parity and security gates are complete. A narrowly scoped macOS
user-presence gate for protected resource inspection is included.

## Technical Context

**Language/Version**: Swift 6.3 language mode; shell only for deterministic build/package launchers

**Primary Dependencies**: Foundation, Security/SecItem, CryptoKit, LocalAuthentication, XPC,
ServiceManagement, OSLog, Swift Argument Parser, and `/usr/bin/ssh`

**Storage**: AES-GCM encrypted Codable document for structured inventory/policy/grants; data
encryption key and credential values in the non-synchronizing macOS data-protection Keychain;
device-generated P-256 keys in Secure Enclave where supported; hash-chained JSONL audit files

**Testing**: Swift Testing for unit/property tests, XCTest for XPC and signed integration
tests, shell contract tests for packaged Skill/CLI, and synthetic SSH fixtures only

**Target Platform**: macOS 14.4 or newer; universal arm64/x86_64 release; Secure Enclave preferred
on Apple silicon or supported T2/Touch ID Macs with an explicit Keychain fallback where unavailable

**Project Type**: Native macOS CLI + per-user broker/launch agent + one-shot AskPass helper + Agent
Skill package; no custom GUI target in the current product phase

**Performance Goals**: `resource list` and policy decisions under 100 ms p95 after unlock; broker
cold activation under 2 s; under 100 MB steady-state broker memory; stream command output without
holding more than the configured 1 MiB bounded capture in memory

**Constraints**: Offline-capable after installation; no public listener; no secret in Agent-visible
I/O, argv, environment, or audit; fail closed on signature, host identity, policy, vault integrity,
or approval-binding failure; no real infrastructure in automated tests

**Scale/Scope**: One local user, up to 500 resources, 10 concurrent requests, 10,000 active audit
events before rotation, and at most 100 active/pending grants in the MVP

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-checked after Phase 1 design.*

| Principle | Pre-design gate | Post-design evidence |
|---|---|---|
| Secrets never cross the Agent boundary | PASS | Agent contracts expose opaque references only; broker owns Keychain and SSH credential injection |
| Useful command execution with scoped authority | PASS | Both argument-based `exec` and explicit `shell` are defined; approval grants bind caller/resource/scope/privilege/expiry |
| macOS-native trust boundary | PASS | Signed broker, CLI and AskPass components use peer-validated XPC; Keychain, Secure Enclave and LocalAuthentication are first-class |
| Open design, encrypted user state | PASS | Per-install AES-GCM vault, non-synchronizing Keychain keys, synthetic fixtures, MIT-compatible dependencies |
| Deterministic contracts and auditability | PASS | Versioned JSON/IPC contracts, bounded outputs, explicit states, hash-linked sanitized audit events |

No constitution exception is required. The design intentionally rejects a same-process vault,
Agent-readable secret command, unsigned bootstrap, shared credential default, and unrestricted
permanent full-access mode.

## Project Structure

### Documentation (this feature)

```text
specs/001-secure-agent-access/
├── spec.md
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   ├── cli-v1.md
│   ├── broker-ipc-v1.md
│   └── skill-runtime-v1.md
├── checklists/
│   └── requirements.md
└── tasks.md
```

### Source Code (repository root)

```text
Package.swift
Sources/
├── SAFAProtocol/              # Codable CLI/XPC types, schema versions, exit mapping
├── SAFADomain/                # resource, request, grant, audit and policy entities
├── SAFACrypto/                # encrypted vault envelope and Keychain abstractions
├── SAFAPolicy/                # deterministic classifier and scope matcher
├── SAFATransport/             # transport protocol, process runner and bounded streams
├── SAFASSH/                   # OpenSSH adapter, host verification, askpass and sudo injection
├── SAFABroker/                # per-user Mach/XPC service and orchestration
├── SAFACLI/                   # `safa` Agent-facing executable
└── SAFAAskPass/               # signed one-shot SSH credential helper
Apps/
└── SAFA/
    ├── SAFA.xcodeproj/
    ├── Targets/               # broker, CLI and one-shot AskPass executable roots
    ├── BrokerLaunchAgent/     # launchd plist and broker packaging
    └── Config/                # entitlements, Info.plist and signing settings
Skills/
└── safa/
    ├── SKILL.md
    ├── agents/openai.yaml
    ├── scripts/safa           # thin runtime resolver; never handles secrets
    ├── references/cli.md
    └── assets/                # release assembly inserts signed runtime components here
Scripts/
├── build-release.sh
├── package-skill.sh
├── verify-package.sh
└── scan-secrets.sh
Tests/
├── Unit/
├── Contract/
├── Integration/
├── Security/
└── Fixtures/                  # synthetic identities, hosts, transcripts and corrupt vaults
```

**Structure Decision**: Keep security-sensitive logic in small SwiftPM library targets with one-way
dependencies, then assemble them into signed broker, AskPass, and CLI runtime components. The
published Skill remains minimal and calls the embedded signed runtime through a thin launcher. This
allows most policy, cryptography-envelope, state-machine, and contract tests to run without a GUI
while reserving Keychain, signing, XPC, and user-presence tests for signed integration targets.

## Security Boundaries

1. **Agent/Skill boundary**: sees resource aliases, request IDs, sanitized command metadata, policy
   decisions, approval states, bounded remote output, and audit summaries; never sees endpoints or
   credential values.
2. **CLI boundary**: parses Agent input and communicates only with the broker. It has no Keychain
   entitlement and cannot approve requests.
3. **Broker boundary**: owns vault decryption, policy, request/grant state, credential injection,
   transport processes, redaction, and audit. Incoming XPC peers must satisfy code-signing and user
   session requirements.
4. **Trusted local-interaction boundary (future M2)**: a separately signed, system-authenticated
   process may present the immutable request and prove local user presence. No such custom UI ships
   in the current phase, and it cannot alter the target or command fingerprint.
5. **Remote boundary**: is untrusted even after authentication. Output is data, host identity is
   pinned, commands are bounded, and remote compromise confers no credential for another host.

## Delivery Phases

- **M0 foundation**: protocol/domain packages, deterministic mock broker, Skill skeleton, contract
  fixtures, threat-model tests.
- **M1 diagnostic MVP**: signed per-user broker, encrypted resource registry, trusted no-GUI
  registration, managed Secure Enclave key or password SSH, strict host identity, read-only
  execution and audit. Existing direct OpenSSH identity/agent registration is implemented in the
  current preview; managed Secure Enclave/password enrollment and proxy-route setup remain open.
- **M2 command authority**: arbitrary `exec`/`shell`, policy classifier, trusted approval, sudo,
  scoped grants, revocation, bounded streaming and redaction.
- **M3 distribution hardening**: universal signed/notarized runtime, Skill packaging, package verification,
  recovery workflow, adversarial suite and independent Skill forward-test.

## Complexity Tracking

No constitution violations require justification. Multiple executable targets are security
boundaries rather than organizational layering: collapsing the broker into the Agent-facing process
would allow it to access secrets or manufacture approval.
