# Research: Secure Agent Access

> Repository split: product-level Skill and distribution decisions are canonical in `juju-w/safa`;
> this file remains supporting history for the native macOS Runtime.

## 1. Native implementation language

**Decision**: Use Swift 6.3 language mode for all trusted runtime components. Use shell only for
small deterministic build, verification, and Skill launcher scripts.

**Rationale**: SAFA's security boundary depends directly on Keychain, Secure Enclave,
LocalAuthentication, ServiceManagement, code signing, and XPC. Swift provides typed native access
without placing a C FFI wrapper between security policy and the operating system. Swift's strict
concurrency checking also helps isolate mutable request/grant state.

**Alternatives considered**:

- **Rust**: strong memory-safety and CLI tooling, but the macOS trust surface would still require
  Objective-C/C bridges and a separately maintained native interaction component.
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

**Decision**: Split the current runtime into four signed components:

1. `safa` CLI, which has no credential entitlements;
2. a per-user `SAFABroker` launch agent, which owns protected state and execution;
3. a one-shot signed askpass helper used only as a child of an approved broker execution.
4. a no-custom-GUI trusted setup helper that collects protected fields with terminal echo disabled
   after LocalAuthentication and sends one typed, caller-bound XPC transaction to the Broker.

**Delivery update**: The CLI-first parity phase has no custom GUI target. Resource enrollment ships
as the separately signed `dev.safa.trusted-local` helper; it accepts no protected flags or
Agent-controlled stdin and emits no protected values. System Keychain and LocalAuthentication
prompts enforce native human presence. A future arbitrary-command approval presentation remains a
separate M2 specification.

Use named XPC/Mach services rather than TCP. Require the expected signing identifier, team identity,
effective user, and audit session on every broker connection. Broker activation remains
an explicit delivery task and must not rely on an undeclared application bundle.

**Rationale**: The Agent-facing CLI must remain incapable of reading Keychain items or approving its
own request. XPC supplies peer process identity and code-signature requirement APIs; a per-user agent
avoids a privileged system daemon and public listener.

**Alternatives considered**:

- **Single CLI process**: rejected because any Agent command that can launch the CLI would enter the
  same process that handles secrets and approval.
- **Loopback HTTP service**: rejected because bearer-token authentication and a listening port add a
  new replay and cross-process attack surface.
- **Unix socket without peer signing**: file permissions identify a user, not an approved binary;
  same-user malware could impersonate the CLI or trusted local peer.
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
`approval_required`. A future separately signed local workflow presents the exact target alias,
sanitized command, privilege, reasons, intent, expected effect, rollback, and proposed scope.
LocalAuthentication proves user presence; the current diagnostic preview does not expose this flow.

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
cannot prove human approval. A native authentication prompt and separately signed trusted process
establish an independent user-presence channel. Binding the grant to immutable request properties
prevents replay and target/command substitution.

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

**Foundation implemented**: `CommandCanonicalizer` now produces a versioned, length-prefixed
SHA-256 identity over every execution-affecting command field and independently POSIX-quotes every
`exec` argument. `PolicyEngine` emits sorted stable findings and enforces the fixed precedence
`hard deny / deny rule > approval signal / approval rule > automatic diagnostic / automatic rule`.
Agent review remains bounded advisory text. The existing runtime still executes only the diagnostic
allowlist until request state, trusted approval, grant binding, and sudo isolation are implemented;
the classifier alone does not grant new authority.

## 8. Output, redaction, and audit

**Decision**: Stream output through the broker, cap Agent-visible stdout and stderr independently,
include truncation metadata, and keep the final remote exit code in the typed result. The migration
replaces the pre-release JSON envelope with the Agent-only `dev.safa.cli/v2` contract:
one canonical TOON 4.1 document on stdout for success, empty/no-op, and error outcomes. Keep Swift
DTOs, XPC payloads, vault persistence, and Broker internals private and typed; TOON belongs only at
the Agent output boundary.

The v2 boundary follows the [AXI](https://axi.md/) profile and its
[official Skill](https://github.com/kunchenguid/axi/blob/408a6536625e5b05e5c56e6c4a04fe83e1f510a5/.agents/skills/axi/SKILL.md),
pinned at commit `408a6536625e5b05e5c56e6c4a04fe83e1f510a5`: bounded
three-to-four-field default rows, explicit counts and empty states, structured errors with exit
codes `0/1/2`, opt-in safe ambient context, content-first no-argument behavior, contextual next
commands, and fast help/version paths. There is no table/human renderer and no `--json`/`--toon`
format switch. `--full` only raises a soft presentation limit; it cannot bypass Broker redaction,
binary-output policy, or hard caps.

Apply exact redaction using all credentials involved in the request plus conservative detectors for
supported secret formats. Never claim that heuristic redaction can identify every transformed
secret.

Write append-only JSONL audit events with a per-file random genesis value and chained HMAC covering
the previous event digest, sequence, and canonical event. Rotate by size/count and anchor the latest
digest and sequence in Keychain. A local administrator can still delete logs; the MVP detects gaps or
rollback but does not claim remote immutability.

**Alternatives considered**:

- **Expose JSON and TOON as permanent parallel modes**: creates two contracts and lets clients drift.
- **Serialize XPC and vault data as TOON**: adds migration risk without improving the Agent boundary.
- **Adopt a Swift TOON package by name alone**: insufficient until it passes the official TOON 4.1
  conformance fixtures; the currently reviewed `toon-swift` repository documents an older format
  revision than the current [TOON 4.1 specification](https://toonformat.dev/reference/spec.html).
- **Store full raw output in audit**: increases leak and retention risk.
- **Rely only on regex redaction**: misses exact secrets with unusual formats.
- **Claim tamper-proof local logs**: false under complete local administrator compromise.

### 8.1 TOON encoder ownership and pin

**Decision**: Keep a narrow deterministic TOON encoder inside `SAFACLI/Presentation` for the v2
migration. It accepts only an ordered, typed presentation value produced from explicit public DTOs,
supports the JSON data shapes that SAFA can emit, and has no decoder, persistence, IPC, credential,
or policy role. Do not create a separate general-purpose TOON package or fork at this stage.

Pin conformance evidence to TOON specification 4.1 at commit
`62f16b369408180f1faf1cba7da1b46d1f336f12`. The specification is still a Working Draft, so this
pin is an intentional reviewed compatibility boundary rather than an assumption that the format can
never change. A later specification revision requires an explicit contract review and refreshed
fixtures; it does not silently change shipped output.

The official ecosystem lists a stable Swift implementation, but the reviewed release `0.4.0` still
declares TOON specification 3.0. TOON 4.0/4.1 added mandatory keyed tabular objects, nested field
groups, canonical empty-array output, and changed list-item layout. Depending on that package today
would therefore make SAFA's 4.1 claim unverifiable. Re-evaluate it when an exact release declares
4.1 and passes the pinned fixtures; the internal presentation seam keeps that replacement local.

**Maintenance bound**:

- implement encoding only, not a general decoder or validator;
- expose no public format options beyond the canonical comma delimiter and two-space indentation;
- preserve field encounter order and reject duplicate ordered keys;
- fail closed on unsupported/oversized presentation values;
- verify exact canonical output locally and strict cross-decode it with the pinned official
  reference implementation in CI;
- keep the normative fixture source and license provenance beside the tests.

Do not fork or independently extend the AXI guidance itself. SAFA owns only its narrower public CLI
contract and encoder adapter. The pinned AXI commit is design input; the pinned TOON specification
and conformance fixtures are the serialization oracle. Upgrading either pin requires a reviewed
compatibility change rather than an automatic dependency update.

## 9. Skill-first packaging

**Decision**: Publish a minimal `safa` Skill containing `SKILL.md`, display metadata, a thin launcher,
concise CLI reference, and a pinned signed/notarized universal runtime payload. The launcher verifies
platform, version, per-component identifiers, Developer ID/team identity, code signatures, and the
package manifest before first activation. It does not contain credentials and does not download or
execute an unverified installer.

If a Skill platform enforces artifact-size limits, publish the runtime as a version-pinned release
asset and have the bundled bootstrap download it over TLS, verify a committed SHA-256 manifest and
all Apple code identities, then activate it. `latest` URLs and `curl | sh` are prohibited.

**Rationale**: Skill installation is the intended user journey. The Skill must remain token-efficient
while the native runtime provides the actual security boundary.

## 10. Validation strategy

**Decision**: Use layered tests:

- pure unit/property tests for canonicalization, fingerprints, scope matching, state machines,
  redaction and encrypted-envelope tamper detection;
- TOON 4.1 conformance fixtures and golden snapshots for the Agent CLI boundary, plus independent
  typed protocol snapshots for XPC compatibility;
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

## 12. Infrastructure topology representation for Agents

**Decision**: Store topology as a directed, typed, attributed multigraph and generate a bounded,
task-specific textual projection for the Agent. Do not choose a tree, Mermaid diagram, screenshot,
or one fixed serialization as the universal representation.

The product repository owns the
[canonical bibliography and influence map](https://github.com/juju-w/safa/blob/main/docs/references.md).
The links below remain beside the Runtime decision record so its evidence is reviewable in place.

The evidence does not support a universal best graph encoding:

- [Talk like a Graph](https://arxiv.org/abs/2310.04560) finds that results vary materially with the
  encoder, graph task, and graph structure.
- [Can Graph Descriptive Order Affect Solving Graph Problems with LLMs?](https://aclanthology.org/2025.acl-long.321/)
  finds that ordering changes performance and that the effect is task-dependent.
- [GraCoRe](https://aclanthology.org/2025.coling-main.531/) also reports effects from semantic
  enrichment and node ordering, while a longer context alone does not guarantee better graph
  understanding.
- [G-Retriever](https://proceedings.neurips.cc/paper_files/paper/2024/hash/efaf1c9726648c8ba363a5c927440529-Abstract-Conference.html)
  retrieves a connected question-relevant subgraph and returns its supporting nodes and edges,
  avoiding whole-graph flattening and reducing hallucination.
- [GITA](https://proceedings.neurips.cc/paper_files/paper/2024/hash/00295cede6e1600d344b5cd6d9fd4640-Abstract-Conference.html)
  shows benefits from combined visual and textual graph input in a purpose-trained multimodal
  framework. Conversely, [Visual Graph Arena](https://openreview.net/forum?id=BCJPAmlfxv) reports
  severe layout sensitivity in current vision and multimodal models.

**Projection policy**:

- inventory and placement use a node table plus typed edge list;
- reachability and path questions use source-rooted adjacency plus Broker-computed proof paths;
- dependency impact uses reverse adjacency plus a computed affected set;
- a small, homogeneous dense relation may use a bounded matrix with a stable alias legend;
- visual diagrams are generated for people or as auxiliary multimodal context only and always ship
  beside the canonical textual projection and Broker proof.

The Runtime canonicalizes stored node/edge identity before projection and declares the task and
ordering in every projection. Large graphs are reduced with explicit hop/node/edge limits. MVP uses
deterministic graph traversal instead of embedding retrieval so exact connectivity remains
reproducible and auditable.

**Trust decision**: Split logical maintenance from operational truth. A user or Agent may propose a
desired/asserted logical edge. Only signed adapters and Broker probes create observed evidence, and
only the Broker graph engine creates derived paths. No Agent claim, diagram, or natural-language
interpretation can mark an edge verified, select a credential, or authorize execution.
