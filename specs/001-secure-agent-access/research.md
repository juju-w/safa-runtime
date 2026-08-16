# Research: Secure Agent Access

## 1. Native implementation language

**Decision**: Use Swift 6.3 language mode for all trusted runtime components. Use shell only for
small deterministic build, verification, and Skill launcher scripts.

**Rationale**: SAFA's security boundary depends directly on Keychain, Secure Enclave,
LocalAuthentication, ServiceManagement, code signing, and XPC. Swift provides typed native access
without placing a C FFI wrapper between security policy and the operating system. Swift's strict
concurrency checking also helps isolate mutable request/grant state.

**Alternatives considered**:

- **Rust**: strong memory-safety and CLI tooling, but the macOS trust surface would still require
  Objective-C/C bridges and a separately maintained native approval app.
- **Go**: good static CLI distribution, but cgo and native UI/XPC integration add a second security
  implementation layer.
- **Python**: excellent for prototypes but inappropriate as the trusted long-lived broker and signed
  companion runtime due to interpreter/dependency surface and weaker packaging identity.

**Sources**:

- [Swift documentation and Swift Package Manager](https://www.swift.org/documentation/)
- [Apple Security framework](https://developer.apple.com/documentation/security/)

## 2. Supported platform baseline

**Decision**: Target macOS 14.4 or newer and build universal arm64/x86_64 release artifacts. Prefer
Secure Enclave on Apple silicon and supported T2/Touch ID Macs; provide an explicit Keychain-backed
fallback when hardware key generation is unavailable.

**Rationale**: The target includes modern XPC peer code-signing requirements, ServiceManagement
launch-agent registration, data-protection Keychain behavior, and LocalAuthentication. Supporting
older macOS versions would require weaker or parallel IPC verification paths in the most sensitive
part of the system.

**Alternatives considered**:

- **Latest macOS only**: simplest, but unnecessarily excludes still-supported Macs.
- **macOS 12/13**: wider coverage, but creates security-sensitive compatibility paths and weakens the
  minimum IPC/runtime assumptions.

## 3. Process and trust-boundary architecture

**Decision**: Split the product into four signed components:

1. `safa` CLI, which has no credential entitlements;
2. a per-user `SAFABroker` launch agent, which owns protected state and execution;
3. `SAFA.app`, which owns onboarding, approval presentation, revocation, and audit UI;
4. a one-shot signed askpass helper used only as a child of an approved broker execution.

**Delivery update**: Component 3 is deferred during the CLI-first parity phase. Do not add new
SwiftUI, menu-bar, dashboard, or custom approval work. Preserve its distinct identity as a future
trusted interaction host while system Keychain and LocalAuthentication prompts enforce the native
human-presence checks that are currently implementable without product GUI.

Use named XPC/Mach services rather than TCP. Require the expected signing identifier, team identity,
entitlement, effective user, and audit session on both CLI-to-broker and app-to-broker connections.
Register the broker as a per-user launch agent embedded in the app.

**Rationale**: The Agent-facing CLI must remain incapable of reading Keychain items or approving its
own request. XPC supplies peer process identity and code-signature requirement APIs; a per-user agent
avoids a privileged system daemon and public listener.

**Alternatives considered**:

- **Single CLI process**: rejected because any Agent command that can launch the CLI would enter the
  same process that handles secrets and approval.
- **Loopback HTTP service**: rejected because bearer-token authentication and a listening port add a
  new replay and cross-process attack surface.
- **Unix socket without peer signing**: file permissions identify a user, not an approved binary;
  same-user malware could impersonate the CLI or approval UI.
- **Root daemon**: unnecessary for remote SSH and increases blast radius.

**Sources**:

- [XPC peer code-signing requirements](https://developer.apple.com/documentation/xpc/xpc-connections)
- [NSXPC listener code-signing requirement](https://developer.apple.com/documentation/foundation/nsxpclistener/setconnectioncodesigningrequirement(_:))
- [SMAppService launch agents](https://developer.apple.com/documentation/servicemanagement/smappservice/agent(plistname:))
- [Apple code-signing requirements](https://developer.apple.com/documentation/technotes/tn3127-inside-code-signing-requirements)

## 4. Inventory and credential storage

**Decision**: Store the structured resource registry, policies, grant state, and vault manifest in a
single versioned AES-GCM encrypted document. Generate a random data-encryption key per installation
and store it in the non-synchronizing data-protection Keychain with
`WhenUnlockedThisDeviceOnly` accessibility and broker-only access. Store credential values as opaque
Keychain records keyed by random identifiers; keep their descriptive metadata inside the encrypted
document.

Do not use Keychain item names that reveal resource aliases or endpoints. Use atomic write-rename,
authenticated schema/version metadata, monotonic revision values, and a last-known revision marker in
Keychain to detect corrupted or rolled-back vault files.

**Rationale**: Keychain is intended for small secret values; a separately encrypted Codable document
supports transactional structured state without leaking searchable infrastructure metadata. AES-GCM
provides confidentiality and tamper detection. `ThisDeviceOnly` prevents migration through ordinary
backups.

**Alternatives considered**:

- **Plain SQLite with Keychain credentials**: leaks topology, usernames, policies, and credential
  relationships.
- **Every field as a Keychain item**: makes transactional state and schema migration difficult and
  may leak descriptive Keychain attributes.
- **SQLCipher**: capable but adds a substantial native dependency and migration surface for a small
  single-user dataset.
- **Password-derived vault key for routine use**: portable but forces repeated password handling and
  is weaker than device-bound storage. It remains appropriate only for an explicitly exported,
  separately encrypted recovery package.

**Sources**:

- [Apple guidance to use the SecItem data-protection Keychain](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains)
- [`kSecUseDataProtectionKeychain`](https://developer.apple.com/documentation/security/ksecusedataprotectionkeychain)
- [`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`](https://developer.apple.com/documentation/security/ksecattraccessiblewhenunlockedthisdeviceonly)

## 5. SSH credentials and remote authentication

**Decision**: Support two MVP authentication modes:

- **Managed device-bound key**: generate a P-256 key in Secure Enclave when available, enroll only
  its public key on the remote host, and expose signing to a broker-controlled, per-execution SSH
  agent channel.
- **Password**: store the password in Keychain and deliver it only through a signed one-shot askpass
  helper bound to the immutable execution request and child process.

Do not import existing private keys into Secure Enclave because the hardware does not support it.
Importing exportable private keys is deferred. Existing external SSH agents may be referenced only in
a later feature after their authorization boundary is specified.

Invoke `/usr/bin/ssh` with an isolated configuration, explicit destination and jump route from the
encrypted resource, strict host checking, a dedicated known-hosts file, no inherited user config,
bounded connection timeouts, and no TTY unless explicitly approved.

**Rationale**: Reusing the operating-system SSH client avoids implementing the SSH protocol while the
broker retains control over destination selection, host identity, and credential release. A managed
Secure Enclave key is not exportable; Apple documents that only the enclave can perform operations
with it.

**Alternatives considered**:

- **Bundled SSH library**: adds a large protocol and cryptography maintenance burden.
- **`sshpass`**: frequently exposes sensitive process and terminal behavior and is not a native
  dependency.
- **Password on command line/environment**: explicitly prohibited by the constitution.
- **One shared managed key for all hosts**: makes remote compromise and revocation unnecessarily
  broad.

**Source**:

- [Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)

## 6. Approval and capability model

**Decision**: Make execution asynchronous at the protocol level. The broker creates an immutable
request, computes its fingerprint, evaluates deterministic policy, and either executes it or returns
`approval_required`. The app displays the exact target alias, sanitized command, privilege, reasons,
intent, expected effect, rollback, and proposed scope. LocalAuthentication proves user presence.

After approval, issue a random capability with only a stored hash and bind it to:

- caller signing identity and audit session;
- resource ID and current resource revision;
- command fingerprint, normalized prefix scope, or explicit full-access scope;
- privilege ceiling;
- issuance time, monotonic deadline, wall-clock expiry, and use count;
- approval proof and policy version.

The Agent never receives an approval credential. It receives the request ID and may poll or wait for
the request; the broker associates the approved capability internally. Exact approvals are one-shot.
Session and full-access grants are visible and revocable.

**Rationale**: A CLI command such as `safa approve` could be invoked by the same Agent and therefore
cannot prove human approval. A native authentication prompt and separate signed app establish an
independent user-presence channel. Binding the grant to immutable request properties prevents replay
and target/command substitution.

**Alternatives considered**:

- **Agent self-approval**: useful as risk commentary, not as authority under prompt injection.
- **Reading `yes` from stdin or TTY**: the Agent controls stdin and may control a pseudo-terminal.
- **Permanent host-wide full access**: too broad; temporary full access remains available.

**Sources**:

- [LAContext](https://developer.apple.com/documentation/localauthentication/lacontext)
- [Device owner authentication on macOS](https://developer.apple.com/documentation/localauthentication/lapolicy/deviceownerauthentication)
- [Codex sandbox and approval model](https://openai.com/index/running-codex-safely/)

## 7. Command representation and policy

**Decision**: Provide two explicit command modes:

- `exec`: an argument vector that SAFA renders with a tested POSIX remote-shell quoting function;
- `shell`: an opaque shell program whose full text is shown and whose default risk is elevated.

Do not pretend arbitrary shell can be perfectly understood. Deterministic policy produces findings
from the resource, privilege, executable, arguments, shell metacharacters, redirects, interpreters,
encoded payloads, destructive patterns, and requested scope. A model-provided review is stored as
advisory evidence. Unknown or ambiguous behavior escalates.

Sudo execution is explicit. The broker owns remote stdin and writes a Keychain-protected sudo
password directly to `sudo -S` only after authorization; it never includes that password in the
command string. A future remote constrained helper may reduce sudo password handling but is not
required for the local MVP.

**Rationale**: Argument mode makes common commands easier to fingerprint while shell mode honestly
represents pipelines and scripts. Conservative classification plus scoped approval is more robust
than an incomplete command allowlist.

## 8. Output, redaction, and audit

**Decision**: Stream output through the broker, cap Agent-visible stdout and stderr independently,
include truncation metadata, and keep the final remote exit code in the JSON result. Apply exact
redaction using all credentials involved in the request plus conservative detectors for supported
secret formats. Never claim that heuristic redaction can identify every transformed secret.

Write append-only JSONL audit events with a per-file random genesis value and chained HMAC covering
the previous event digest, sequence, and canonical event. Rotate by size/count and anchor the latest
digest and sequence in Keychain. A local administrator can still delete logs; the MVP detects gaps or
rollback but does not claim remote immutability.

**Alternatives considered**:

- **Store full raw output in audit**: increases leak and retention risk.
- **Rely only on regex redaction**: misses exact secrets with unusual formats.
- **Claim tamper-proof local logs**: false under complete local administrator compromise.

## 9. Skill-first packaging

**Decision**: Publish a minimal `safa` Skill containing `SKILL.md`, UI metadata, a thin launcher,
concise CLI reference, and a pinned signed/notarized universal `SAFA.app` release payload. The
launcher verifies platform, version, bundle identifier, Developer ID/team identity, code signature,
and package manifest before first activation. It does not contain credentials and does not download
or execute an unverified installer.

If a Skill platform enforces artifact-size limits, publish the app as a version-pinned release asset
and have the bundled bootstrap download it over TLS, verify a committed SHA-256 manifest and Apple
code signature, then activate it. `latest` URLs and `curl | sh` are prohibited.

**Rationale**: Skill installation is the intended user journey. The Skill must remain token-efficient
while the native runtime provides the actual security boundary.

## 10. Validation strategy

**Decision**: Use layered tests:

- pure unit/property tests for canonicalization, fingerprints, scope matching, state machines,
  redaction and encrypted-envelope tamper detection;
- protocol snapshots and JSON Schema fixtures for CLI/XPC compatibility;
- signed integration tests for Keychain access groups, peer signing requirements,
  LocalAuthentication cancellation, broker activation and askpass binding;
- synthetic SSH servers for password/key, host mismatch, jump failure, timeout, sudo, output bounds,
  binary output and remote nonzero exits;
- package tests for universal architectures, signature/notarization metadata, manifest hashes,
  absence of secrets and clean Skill installation;
- adversarial tests for prompt injection in remote output, request mutation, replay, expiry, clock
  changes, concurrent requests, vault rollback and copied vault state.

**Rationale**: Most security behavior can be deterministic and fast, while tests that require
macOS signing or user interaction are separated and explicitly gated in CI/release validation.

## 11. Migration baseline from the local `ssh-hosts` Skill

**Decision**: Preserve the existing Skill's useful interaction model while replacing its Python
credential boundary. The legacy implementation remains a reference during development, not a
runtime dependency and not a source of real host fixtures.

Behaviors to preserve:

- logical aliases instead of asking an Agent to repeatedly handle host coordinates;
- refusal of unknown aliases and non-interactive SSH defaults such as `BatchMode`;
- local hidden credential entry rather than chat or command-line password entry;
- sudo password delivery on remote stdin followed by `/dev/null` for the privileged child's stdin;
- explicit separation between connection checks, ordinary commands, and sudo commands.

Behaviors to replace:

- hard-coded real host inventory in Skill source;
- a Python process that can directly read Keychain values;
- environment-variable secret injection into child commands;
- unsigned same-process policy, credential access, transport, and output handling;
- free-form text output without a versioned, bounded, redacted contract;
- execution without immutable request fingerprints, trusted approval, expiry, revocation, or audit.

The migration rule is behavioral compatibility, not code compatibility: no production alias,
endpoint, username, Keychain account, or credential is copied into this repository or its tests.
