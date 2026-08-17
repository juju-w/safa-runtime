# SAFA Runtime Architecture

Status: **Accepted for pre-release development**  
Last reviewed: **2026-08-16**

This document is the implementation guide for SAFA's native runtimes. It defines the trust
boundaries, module responsibilities, source organization, CLI conventions, and delivery order.
Feature specifications describe behavior; this document decides where runtime behavior belongs and
which component is trusted to perform it.

## 0. Product/runtime boundary

The canonical Agent Skill, public CLI/JSON/resource contracts, release manifests, and product-level
architecture live in [`juju-w/safa`](https://github.com/juju-w/safa). This repository owns native
runtime implementations and their platform-specific security adapters.

```mermaid
flowchart TB
    Product["safa product repository\nSkill · contracts · manifests"]
    Product --> Mac["Swift macOS runtime\ncurrent implementation"]
    Mac --> Contract["Shared conformance fixtures"]
    Product -. future .-> Other["Additional native runtimes\nimplemented only when needed"]
    Other -.-> Contract
```

All runtimes must implement the same external contract. Their private implementation is expected to
differ: XPC/Keychain/SMAppService on macOS, Unix sockets with peer credentials and an OS keyring on
Linux, and Named Pipes with DPAPI/Credential Manager on Windows. Internal IPC is never exposed as an
Agent-facing compatibility surface.

Each platform produces one installable Runtime package. The package keeps multiple trust roles:
the Agent-facing CLI parses and presents but has no vault authority; the Broker/daemon owns policy,
credentials, and transport; a narrowly scoped helper may deliver a child-bound credential. Package
unity simplifies installation, while process separation prevents a modified frontend from inheriting
Broker authority.

Source availability is part of the threat model. Security depends on native publisher identity,
Broker-side policy, OS-protected keys, user authorization, and least-privilege resource accounts—not
on implementation secrecy or binary obfuscation.

The Swift package remains at the repository root while the macOS implementation is stabilizing.
Moving it into a deeper directory would be a large mechanical change with no security benefit.
Another platform directory is introduced only when its Runtime implementation starts; an empty
cross-platform scaffold is not an architecture boundary.

Cross-platform Runtime selection belongs to the product repository's script resolver. This
repository does not provide another universal launcher binary. Swift remains the macOS Runtime.

## 1. macOS runtime goal and current priority

The current SAFA macOS runtime is a native security boundary that lets an Agent discover and operate
registered resources without receiving reusable credentials. Its core is a generic encrypted resource
directory; SSH hosts are the first executable profile, not the limit of the model. Database,
object-storage, cache, and service adapters can reuse the same alias, metadata, relationship,
credential-reference, authorization, and policy boundaries.

The immediate goal is functional parity with the existing local `ssh-hosts` workflow while moving
its sensitive operations behind native macOS controls. Persistent tamper-evident audit history is
useful, but it is deliberately later than:

1. importing and resolving existing SSH hosts and jump routes;
2. reliable public-key SSH and Core Tunnel preflight;
3. Keychain-backed sudo and service credentials;
4. broker-owned execution with human-friendly system approval;
5. safe operational workflows such as scoped sudo and atomic user creation.

Delivery is CLI-first and the current product has no custom GUI target. System-provided Touch ID,
Keychain, LocalAuthentication, and Authorization Services prompts are security controls rather than
product UI. If a safe operation cannot yet be completed through those controls, SAFA returns
`user_action_required` instead of accepting a secret or approval through the Agent-facing CLI.

Release and Skill-package publication remain frozen until the repository owner explicitly enables
them.

## 2. macOS architecture principles

1. **The CLI is a parser and presenter, not a security boundary.** It has no Keychain entitlement,
   cannot approve requests, and never launches credential-bearing processes.
2. **The broker owns authority.** It resolves encrypted resource metadata, enforces policy, obtains
   credentials, launches transports, and returns bounded results.
3. **macOS owns human presence.** During the CLI-first phase, privileged credential use and human
   confirmation rely on system-provided Keychain and LocalAuthentication interaction. That
   authority never moves into the Agent-facing CLI.
4. **Use macOS primitives directly.** Prefer Data Protection Keychain, Secure Enclave,
   LocalAuthentication, signed XPC peers, and `SMAppService` over a custom password store or daemon
   installer.
5. **Use a functional core and imperative shell.** Domain validation, canonicalization, scope
   matching, and policy are deterministic. Keychain, XPC, files, clocks, processes, and UI are
   adapters behind narrow protocols.
6. **Typed boundaries over dictionaries.** Public CLI JSON and XPC payloads use versioned DTOs with
   explicit coding keys. Domain persistence models are not wire contracts.
7. **Fail closed without becoming hostile.** A rejection must contain a stable code and a safe next
   action; it must not silently fall back to raw SSH, password prompts, mutable SSH config, or weaker
   host verification.
8. **Claims follow evidence.** README capability claims require an executable contract or
   integration test.
9. **Profiles extend the directory; they do not fork it.** Resource kinds, access methods,
   credential roles, and metadata keys are validated namespaced identifiers. New adapters do not
   add arbitrary JSON to the vault or put credentials in metadata.

## 3. System context and trust boundaries

```mermaid
flowchart LR
    Agent["Agent or terminal user"] -->|argv / JSON only| CLI["Signed safa CLI\nno secret entitlement"]
    CLI -->|Agent XPC\nsigned peer check| Broker["Per-user SAFA broker\nauthority boundary"]
    Human["Local human"] -->|Touch ID / system prompt| Native["macOS Security UI\nno custom product GUI"]
    Native -->|user presence result| Broker
    Broker --> Policy["Deterministic policy\nand use cases"]
    Broker --> Vault["Encrypted resource vault"]
    Broker --> Keychain["Data Protection Keychain"]
    Broker --> Enclave["Secure Enclave keys"]
    Broker --> Adapters["Typed resource adapters\nSSH first; DB/S3/cache/service later"]
    Adapters --> SSH["Isolated OpenSSH adapter"]
    SSH --> Remote["Untrusted SSH host"]
    SSH --> AskPass["One-shot signed AskPass helper"]
    AskPass -->|child-bound XPC| Broker
```

### Boundary rules

- Agent/CLI data may choose a resource alias and command, but cannot provide an endpoint,
  credential reference, approval decision, or trusted identity. `resource inspect` is the one
  read-only disclosure path: after a macOS-owned user-presence prompt, it may return non-secret
  connection and inventory metadata. It never returns a credential reference, Keychain locator,
  private/public key material, host fingerprint, password, or token.
- XPC listeners require the expected signing identifier, Developer Team, effective user, and audit
  session. The broker derives peer identity from the connection, not message fields.
- The Agent-facing CLI cannot submit a secret or approval. A system-authenticated local workflow may
  confirm a broker-computed request but cannot rewrite its target, command, or policy result.
- A future trusted local-interaction process, if specified, must retain a separate signing identity
  and XPC contract. No such product UI ships in the current phase.
- The broker writes a per-request SSH config and pinned `known_hosts`, disables ambient forwarding,
  and does not inherit the user's mutable SSH configuration during execution.
- Remote output is untrusted data. It is bounded before returning to the Agent and must never be
  interpreted as new instructions by the Skill.

## 4. Module map and dependency direction

The current SwiftPM target split is appropriate because several modules coincide with real trust or
test seams. The targets must remain one-way dependencies; not every target needs to be an externally
vended library product.

| Module | Owns | Must not own |
|---|---|---|
| `SAFADomain` | Generic resource directory, typed metadata, value types, invariants, state transitions | Keychain, XPC, files, process launch, CLI formatting |
| `SAFAProtocol` | Explicit versioned CLI/XPC DTOs and stable error codes | Vault models, policy logic, Security-framework helpers |
| `SAFACrypto` | Keychain, encrypted vault, Secure Enclave adapters | Resource workflows, SSH command construction |
| `SAFAPolicy` | Pure command classification and grant matching | UI, clocks without injection, credential access |
| `SAFATransport` | Bounded subprocess lifecycle and cancellation | SSH policy or credentials |
| `SAFASSH` | OpenSSH config, host identity, SSH-agent/AskPass and sudo transport adapters | Keychain lookup, approvals, resource persistence |
| `SAFABroker` | Application use cases, XPC adapters, orchestration/composition root | CLI parsing, product presentation |
| `SAFACLI` | ArgumentParser commands, typed request mapping, JSON/human presentation | Secrets, policy, direct SSH, approval |
| `SAFAAskPass` | One-shot child-bound credential response | Resource lookup or general Keychain queries |

The intended dependency shape is:

```text
SAFACLI ───────────────► SAFAProtocol
SAFABroker ────────────► SAFAProtocol + SAFADomain + SAFAPolicy + SAFACrypto + SAFASSH
SAFASSH ───────────────► SAFADomain + SAFATransport
SAFACrypto ────────────► SAFADomain
SAFAPolicy ────────────► SAFADomain
SAFATransport ─────────► SAFADomain
```

`SAFAProtocol` must gradually stop importing persistence-oriented domain aggregates. Map explicit
wire DTOs to domain types at the broker edge. This prevents a domain refactor from silently changing
the XPC or CLI schema.

## 5. Source organization

Organize files by responsibility inside each target. Do not return to target-wide `Models.swift`,
`SAFACommand.swift`, or `BrokerService.swift` monoliths.

```text
Sources/
├── SAFADomain/
│   ├── Resources/
│   ├── Execution/
│   ├── Credentials/
│   └── Authorization/
├── SAFAProtocol/
│   ├── Agent/
│   ├── TrustedLocal/
│   ├── AskPass/
│   └── CLI/
├── SAFABroker/
│   ├── UseCases/
│   ├── XPC/
│   ├── Resources/
│   └── Runtime/
├── SAFACLI/
│   ├── Commands/Resource/
│   ├── Commands/Exec/
│   ├── Commands/Credential/
│   └── Presentation/
└── SAFASSH/
    ├── Configuration/
    ├── Authentication/
    ├── Tunnel/
    └── Sudo/
```

Guidelines:

- Prefer one primary type per file. A file over roughly 300 lines should have an explicit cohesion
  reason; otherwise split it before adding behavior.
- Command types parse arguments and call an injected client/use case. They do not scan dynamic JSON
  dictionaries or implement resource business rules.
- Broker XPC exports adapt bytes to typed operations. Use cases remain testable without an XPC
  connection.
- Mutable security state is actor-isolated. `@unchecked Sendable` is limited to small Foundation/XPC
  bridges with their synchronization visible in the same file.
- Composition happens only in executable runtime roots. Do not create global service
  locators or singletons for credentials.

## 6. Swift CLI conventions

SAFA uses Apple's `swift-argument-parser` and follows these rules:

- The root and every asynchronous subtree use `AsyncParsableCommand`.
- Each command family is a separate file/directory with `CommandConfiguration`, `abstract`, argument
  help, and examples where the operation is non-obvious.
- Shared flags such as `--json`, timeouts, and output limits use `@OptionGroup`.
- Validated scalar arguments such as resource alias and state conform to
  `ExpressibleByArgument`; cross-field constraints use `validate()`.
- `run()` performs only: parse/validate → create typed request → call client → present response.
- Machine mode writes exactly one versioned JSON object to stdout. Human diagnostics go to stderr
  only when they cannot be represented safely in that object.
- Exit-code mapping is centralized and keyed by a stable error-code enum, not duplicated string
  switches.
- Version information comes from generated build metadata, never a literal repeated across CLI and
  Xcode settings.
- `--` remains the boundary before a remote argument vector. Shell programs are explicit and never
  inferred by concatenating arguments.

## 7. Human-friendly CLI-first flows

### Discover and inspect a resource

1. `safa resource list --json` and `resource show ALIAS --json` return a safe summary: canonical
   alias, resource type, state, health, capabilities, and only source-code-allowlisted metadata.
2. Unknown or newly imported metadata keys fail closed as private. A configuration file cannot mark
   its own field public.
3. `safa resource inspect ALIAS --json` asks macOS to verify the local user with Touch ID or login
   credentials. Denial and prompt-rate-limiting return no detail object.
4. An approved inspection may return alternate aliases, access methods, endpoint, username,
   security domain, non-secret typed metadata, relationships by alias, and identity status. It never
   returns secrets or credential/key locators.
5. Canonical and alternate aliases occupy one collision namespace and resolve to the same stable
   resource identity for inspection and execution.

### Manage resource lifecycle from the CLI

1. `safa resource add ALIAS --from-ssh-config SSH_ALIAS` and `resource edit` carry only logical
   aliases and one of the supported host resource types across the mutation XPC method.
2. The broker asks macOS for device-owner authentication, then runs bounded `ssh -G SSH_ALIAS`
   locally and persists the resolved endpoint and username inside the encrypted vault. Private
   connection values never become CLI arguments or mutation DTO fields.
3. Imports are `draft/needs_setup`: discovery alone does not create a credential or trusted host
   identity. `resource setup` separately authenticates the local user, imports a previously trusted
   `known_hosts` identity and an available existing OpenSSH identity/agent route, then verifies
   `hostname` and the exact remote username before committing `active`.
4. Setup currently accepts direct routes, including a local Core Tunnel listener expressed as the
   resolved endpoint. `ProxyJump` and `ProxyCommand` fail with `user_action_required` until SAFA can
   review and snapshot their complete route rather than inherit mutable SSH configuration.
5. Refreshing a draft is allowed. Retargeting a resource that already has a credential or trusted
   identity is rejected so a mutable SSH config cannot silently redirect trusted access.
6. `resource disable`, `resource enable`, and `resource remove` also require macOS user presence.
   Enable accepts only a disabled resource and preserves its trusted route. All resource writes pass
   through one serialized broker transaction gate. Removal preserves relationship integrity and
   deletes an unshared credential reference through the same transaction.

### Resource directory extension model

- Types are open validated identifiers such as `host.linux`, `host.nas`, `database.mysql`,
  `database.postgresql`, `object-storage.s3`, `cache.redis`, and `service.http`.
- Access methods are independent identifiers such as `ssh`, `database.mysql`, `object-storage.s3`,
  `cache.redis`, and `http`. Supporting an identifier in storage does not claim its adapter is
  implemented.
- Metadata is an ordered set of typed key/value entries (`text`, `integer`, `boolean`, `byte_count`,
  or `text_list`). Passwords, API tokens, private keys, access keys, and Keychain locators are never
  metadata.
- Resource relationships such as `hosted-on`, `depends-on`, and `backed-by` form the later service
  topology without copying endpoints into dependent records.
- Credential kinds and roles are also extensible identifiers, while secret material stays in
  Keychain/Secure Enclave and the encrypted directory keeps only opaque references.
- Built-in templates currently cover SSH (including Windows OpenSSH), MySQL, PostgreSQL,
  SQL Server, S3, MinIO, OSS, Redis, Elasticsearch, Neo4j, and HTTP. Their protected setup payload
  enters only through the separately signed trusted-local XPC role. Shipping that role's local
  no-GUI client remains a separate delivery gate; the Agent-facing CLI cannot substitute for it.
- A stored service connection is `needs_verification`, not `ready`. Only its typed broker adapter
  may record revision-bound verification evidence. Changing endpoint, username, access method, or
  credential clears the evidence before the edited revision is returned.

The normative schema and initial host keys are defined in
`specs/001-secure-agent-access/contracts/resource-directory-v1.md`.

### Import an existing SSH host

1. A local human adds an explicitly declared OpenSSH `Host` alias. The broker resolves it through a
   bounded read-only `ssh -G <alias>` adapter without importing private-key or password bytes.
2. A separate `resource setup` authorization imports an existing entry from the user's configured
   `known_hosts` files. Absence is not silently accepted: the command returns
   `host_identity_setup_required`.
3. Setup references only existing readable identity-file paths or an existing SSH-agent socket. The
   path/socket locator remains encrypted in the broker vault and is never returned by list, show, or
   inspect. Private-key bytes do not enter SAFA storage.
4. The broker constructs an isolated, pinned OpenSSH configuration and runs non-destructive
   `hostname` and `id -un` checks. Authentication as a username other than the imported username
   fails setup.
5. Only after successful verification does a revision-checked transaction add the OpenSSH
   credential reference and mark the resource active.

Execution snapshots the direct endpoint, remote username, trusted host key, and approved local
OpenSSH credential locator. Later retargeting through `~/.ssh/config` is rejected. Managed Secure
Enclave onboarding, password entry, first-use host confirmation, and `ProxyJump`/`ProxyCommand`
snapshotting remain later work.

### Add sudo capability

1. The Agent-facing CLI never requests or accepts a sudo password.
2. The CLI-first parity slice may import an existing per-host sudo credential from the current local
   Keychain only inside a broker-owned, system-authenticated migration flow.
3. New sudo-password enrollment remains unavailable until a safe local secret-entry path exists; it
   must not be improvised through argv, environment variables, chat, or Agent-controlled stdin.
4. The broker stores sudo as a separate `ThisDeviceOnly` Keychain item and verifies it with a
   read-only `sudo -v` operation.
5. Sudo remains independently removable and high-privilege use requires system user presence.

### Agent execution

```text
safa host list --json
safa host check app.prod --json
safa exec app.prod --json -- systemctl status docker
```

The Agent sees aliases, capabilities, health, stable errors, and bounded output. If Core Tunnel is
down, the response directs the user to start it instead of asking for an IP or password.

## 8. `ssh-hosts` parity plan

| Existing workflow capability | Current SAFA state | Native target state | Priority |
|---|---|---|---|
| Business-name/alias resolution | Canonical and alternate alias resolution implemented | Search and import UX over the encrypted directory | P0 |
| `ssh -G` route inspection | Explicit-host import implemented for direct routes | Reviewed `ProxyJump`/`ProxyCommand` snapshot | P0 |
| Core Tunnel listener preflight | Direct local-listener routes execute; dedicated health check missing | Route-health adapter and actionable `tunnel_unavailable` result | P0 |
| Public-key `BatchMode=yes` SSH | Existing identity-file/agent route wired end-to-end | Managed Secure Enclave identity | P0 |
| Strict host-key checking | Existing `known_hosts` import and pinned execution implemented | First-use confirmation and rotation flow | P0 |
| Read-only diagnosis | Narrow allowlist exists | Argument-aware policy that excludes secret-dumping forms | P0 |
| Per-host sudo in Keychain | Model only | Separate credential, system approval, protected stdin | P1 |
| One scoped sudo command | Missing | Broker-owned sudo adapter and exact approval | P1 |
| Atomic user creation | Missing | Reviewed operational recipe over scoped sudo | P1 |
| Service credential status/injection | Typed templates, protected Broker commit, and verification evidence implemented; local setup client and protocol adapters missing | Least-privilege client adapters with credential injection and health probes | P2 |
| Credential discovery/import | External Python tooling | Explicit local migration assistant; never background scanning | P2 |
| Core Tunnel inventory refresh | External Python tooling | Read-only optional import adapter | P2 |
| Persistent tamper-evident audit UI | In-memory event sketch | Deferred until core operations are useful and safe | Later |

## 9. macOS security controls

- **Keychain:** use the Data Protection Keychain and the most restrictive accessibility compatible
  with broker operation. Device-bound values use a `ThisDeviceOnly` class.
- **User presence:** privileged credentials and authorization decisions use
  `SecAccessControl`/LocalAuthentication. A CLI flag or stdin confirmation is never approval.
- **Secure Enclave:** private key material is generated and used on-device. Do not claim managed
  Secure Enclave SSH until the constrained SSH-agent socket protocol is implemented and tested
  end-to-end.
- **XPC:** both sides set peer code-signing requirements; the listener also validates user and audit
  session. Agent, broker, AskPass, and any future trusted local-interaction process use role-specific
  signing identifiers.
- **Service lifecycle:** register the per-user broker through `SMAppService`; show registration state
  and a direct System Settings remediation path.
- **Files:** application-support directories are `0700`; vault/config/known-host files are `0600`;
  temporary request directories are removed after execution.

## 10. Delivery gates

No new authorization or audit feature starts until the architecture remediation gate is green:

1. split the four current monolith files by feature/responsibility;
2. replace dynamic broker reply maps for touched operations with typed DTOs;
3. correct advertised capabilities and README claims;
4. remove secret-dumping command forms from the automatic diagnostic policy;
5. add SSH-config import, tunnel preflight, and public-key execution contract tests;
6. validate the signed broker/CLI/AskPass boundaries without adding GUI work or publishing
   artifacts.

After every slice: format, build, test, unsigned Xcode assembly, Draft PR, CI, squash merge. No tag,
GitHub Release, notarized artifact, or Skill package is created while the publication hold is active.

## References

- [Swift Package Manager: Introducing Packages](https://docs.swift.org/swiftpm/documentation/packagemanagerdocs/introducingpackages/)
- [Apple Swift Argument Parser](https://github.com/apple/swift-argument-parser)
- [Apple Keychain Services](https://developer.apple.com/documentation/security/keychain-services)
- [Accessing Keychain items with Touch ID](https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id)
- [Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
- [SMAppService](https://developer.apple.com/documentation/servicemanagement/smappservice)
- [XPC peer requirements](https://developer.apple.com/documentation/xpc/xpcpeerrequirement)
