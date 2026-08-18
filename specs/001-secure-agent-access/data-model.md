# Data Model: Secure Agent Access

All persisted domain records use UUID identifiers, explicit schema versions, UTC wall-clock times,
and monotonic deadlines where expiration decisions are security-sensitive. Human-readable aliases
are unique per local vault. Sensitive records live only inside the authenticated encrypted vault
unless stated otherwise.

## Resource

Represents any logical resource. SSH hosts are the first executable profile; NAS is a host role,
not a platform or a separate host type.
databases, object storage, caches, and services reuse the same aggregate as adapters are added.

| Field | Type | Rules |
|---|---|---|
| `id` | UUID | Stable, never reused |
| `alias` | String | 1-64 chars; lowercase letters, digits, dots and hyphens; unique |
| `alternateAliases` | String list | Shares the canonical collision namespace; encrypted |
| `kind` | Namespaced identifier | `host`, `database`, `object-storage`, `cache`, `messaging`, `search`, `graph`, or `service` |
| `template` | ID + version | Immutable adapter/configuration schema binding such as `ssh@1` or `mysql@1` |
| `hostPlatform` | Enum? | Hosts only: `linux`, `macos`, or `windows` |
| `roles` | Identifier list | Orthogonal purposes such as `nas`, `gpu`, or `jump-server` |
| `resourceType` | Namespaced identifier | Additive CLI v1 compatibility projection; not an internal template key |
| `displayName` | String? | Protected detail; encrypted and not in the default summary |
| `accessMethods` | Identifier list | Stored profile; an adapter must still implement execution |
| `transport` | Enum? | Legacy/MVP compatibility value: `ssh`; non-SSH profiles leave it absent |
| `endpoint` | Scheme + host + port + path | Encrypted; disclosed only by authorized detailed show |
| `username` | String | Encrypted; disclosed only by authorized detailed show |
| `metadata` | Typed entry list | Non-secret profile data; unknown keys default private |
| `relationships` | Kind + target ID + origin list | Canonical encrypted resource relationships; exposed by target alias only after authorization |
| `credentialBindings` | Role + CredentialReference ID list | Encrypted; never Agent-visible |
| `jumpRoute` | Resource ID list | Acyclic; each item must be an SSH resource |
| `securityDomain` | String | Used to detect credential reuse/blast radius |
| `hostIdentity` | Host-key record | Required before normal execution |
| `authRef` | CredentialReference ID | Must be healthy and authorized for this resource |
| `sudoRef` | CredentialReference ID? | Separate from login credential when possible |
| `policyRef` | Policy ID | Required |
| `revision` | UInt64 | Increment on security-relevant modification |
| `state` | Enum | `draft`, `active`, `disabled`, `deleted` |
| `createdAt` / `updatedAt` | Timestamp | UTC |

### State transitions

```text
draft -> active       after endpoint, identity, credential and policy validation
active -> disabled    explicit user action or security failure
disabled -> active    trusted user revalidation
draft/active/disabled -> deleted
```

Deleting a resource immediately invalidates its pending requests and grants. Alias reuse requires a
new UUID and cannot reactivate old grants.

### Metadata disclosure

Metadata values are explicitly typed as text, integer, boolean, byte count, or text list. The
non-interactive summary uses a source-code allowlist; configuration and imported plugins cannot
declare their own keys public. The initial safe keys are `host.os.family`,
`host.docker.available`, `database.engine`, `object-storage.provider`, `cache.engine`, and
`service.protocol`. IP addresses, kernel releases, CPU/memory/disk details, Docker versions, routes,
and all unknown keys require `resource show --details` user presence.

Successful initial SSH setup records a bounded read-only inventory snapshot in the same transaction
that activates the resource. It includes platform, architecture, OS/kernel version, CPU model/count,
total memory, root-filesystem capacity/free space, hardware vendor/model, and Docker availability or
version when present. Missing optional values do not block activation; account or platform mismatch
does.

## TopologyGraph

Represents relationships that cannot be faithfully modeled by a tree. The graph is directed, typed,
attributed, and permits parallel edges. It is versioned independently from individual resources.

| Field | Type | Rules |
|---|---|---|
| `revision` | UInt64 | Changes on every graph mutation or verification-state change |
| `nodes` | `TopologyNode` list | Stable identity; storage order is non-semantic |
| `edges` | `TopologyEdge` list | Explicit direction; storage order is non-semantic |

A `TopologyNode` has an immutable ID, kind (`resource`, `site`, `security-domain`,
`network-segment`, `runtime`, or `route`), optional Resource ID, stable semantic alias, visibility,
and bounded typed attributes. Resource aliases reuse the directory selector; context aliases occupy
reviewed namespaces. Agent-proposed context aliases are limited to one semantic segment beneath
`site`, `domain`, `network`, `runtime`, or `route`; raw network coordinates never become
Agent-visible node attributes.

A `TopologyEdge` has an immutable ID, source/target IDs, relation, layer (`desired`, `observed`, or
`derived`), verification (`asserted`, `verified`, `stale`, or `failed`), origin, visibility,
observation/expiry timestamps, Broker-only evidence reference, and revision. Initial relations are
`located-in`, `member-of`, `runs-on`, `depends-on`, `backed-by`, `replicates-to`, `routed-via`, and
`can-reach`.

Agent proposals may create or update only desired/asserted logical edges. A signed adapter or probe
owns observed evidence; deterministic Broker graph operations own derived edges and proof paths.
Credential bindings are not graph nodes or Agent-visible edge properties.

For resource pairs, `hosted-on`, `depends-on`, and `backed-by` are canonical in
`Resource.relationships` and materialize as deterministic `runs-on`, `depends-on`, and `backed-by`
desired edges. A successful bounded SSH setup or execution refreshes a single observed/verified
`runtime.local can-reach <resource>` edge for five minutes; OpenSSH exit `255` never creates it.

## TopologyProjection

A transient, bounded Agent DTO derived from one graph revision. It contains an answer-first outcome,
safe semantic aliases, a node table, typed directed edge table, task, declared ordering, roots,
Broker-computed proof edge IDs, and a truncation flag. Inventory, reachability, dependency-impact, and dense-comparison tasks select
different views; there is deliberately no universal serialization. Visual diagrams are derived
artifacts and cannot be read back as trusted graph state.

## CredentialReference

Opaque metadata pointing to protected material held by Keychain or Secure Enclave.

| Field | Type | Rules |
|---|---|---|
| `id` | UUID | Random; also used as opaque Keychain account identifier |
| `kind` | Validated identifier | SSH kinds today; DB passwords, object-store keys and API tokens can be added without a vault shape change |
| `storageLocator` | Opaque bytes/string | Encrypted; never an endpoint or human label |
| `publicMaterial` | String? | Public SSH key only; safe for explicit human export |
| `securityDomains` | Set<String> | Used for reuse warnings |
| `accessClass` | Enum | `automaticWithinPolicy`, `userPresenceRequired` |
| `health` | Enum | `pending`, `ready`, `locked`, `invalid`, `reenrollRequired` |
| `createdAt` / `lastUsedAt` | Timestamp | `lastUsedAt` optional |

Secret values are not fields in the domain model. Device-bound private keys have no export
transition. Removing a reference deletes or invalidates its Keychain material after dependent
resources are disabled.

## HostIdentity

Pins the authenticated identity of an SSH destination.

| Field | Type | Rules |
|---|---|---|
| `algorithm` | String | Supported OpenSSH host-key algorithm |
| `publicKey` | Bytes/String | Encrypted as infrastructure metadata |
| `fingerprint` | String | Displayable only in trusted setup/repair UI |
| `verifiedAt` | Timestamp | Required |
| `verificationMethod` | Enum | `manual`, `trustedImport`, `rotationApproval` |
| `status` | Enum | `trusted`, `changed`, `revoked` |

A changed key never overwrites a trusted identity automatically.

## CommandSpec

Immutable representation used to calculate an execution fingerprint.

| Field | Type | Rules |
|---|---|---|
| `mode` | Enum | `exec` or `shell` |
| `arguments` | Array<String>? | Required for `exec`; first item is executable |
| `shellProgram` | String? | Required for `shell`; preserved byte-for-byte |
| `stdinMode` | Enum | `none`, `brokerControlled`, `boundedAgentData` |
| `tty` | Boolean | Defaults false; true elevates risk |
| `workingDirectory` | String? | Remote path; included in fingerprint |
| `timeoutSeconds` | UInt | Bounded by policy |
| `outputLimitBytes` | UInt | Bounded by policy |

Exactly one of `arguments` and `shellProgram` is present. Environment injection is excluded from the
MVP Agent contract to avoid a second secret and policy channel.

`dev.safa.command/v1` canonicalization length-prefixes every UTF-8 value and binds mode, ordered
arguments or exact shell source, stdin mode, TTY, working directory, timeout, and output limit into
one SHA-256 command fingerprint. `exec` rendering quotes each argument independently for a POSIX
remote shell; empty values, quotes, whitespace, newlines, metacharacters, and command-substitution
text therefore remain inert argument data. NUL values and vectors above the reviewed byte/count
limits fail before policy or transport work.

## ExecutionRequest

| Field | Type | Rules |
|---|---|---|
| `id` | UUID | Public request handle |
| `caller` | CallerIdentity | Captured from authenticated IPC peer |
| `resourceID` | UUID | Bound to current resource revision |
| `resourceRevision` | UInt64 | Prevents use after resource mutation |
| `command` | CommandSpec | Immutable after creation |
| `privilege` | Enum | `user`, `sudo` |
| `intent` | String | Required, bounded and sanitized |
| `expectedEffect` | String? | Required for state-changing requests |
| `rollback` | String? | Required when a practical rollback exists |
| `fingerprint` | Digest | Canonical caller/resource/command/privilege digest |
| `riskAssessmentID` | UUID | Required before execution |
| `state` | Enum | See transitions below |
| `createdAt` / `deadline` | Timestamp/monotonic | Bounded lifetime |
| `executionResult` | ExecutionResult? | Present after terminal execution state |

### State transitions

```text
created -> evaluating
evaluating -> approved_by_policy -> running
evaluating -> awaiting_approval
evaluating -> denied
awaiting_approval -> approved_by_user -> running
awaiting_approval -> denied | cancelled | expired
approved_by_policy/approved_by_user -> running | cancelled | expired
running -> completed | failed | timed_out | cancelled
```

Terminal requests are immutable. Retrying creates a new request linked by `retryOf`.

## CallerIdentity

| Field | Type | Rules |
|---|---|---|
| `signingIdentifier` | String | Must match configured CLI identity |
| `teamIdentifier` | String | Distribution builds require expected team |
| `effectiveUserID` | UInt32 | Must equal broker user |
| `auditSessionID` | UInt32 | Bound into grants |
| `agentSession` | String? | Opaque optional session supplied by integration |

The caller cannot self-declare signing, user, or audit-session fields.

## RiskAssessment

| Field | Type | Rules |
|---|---|---|
| `id` | UUID | Stable for request |
| `policyVersion` | String | Included in grant binding |
| `level` | Enum | `low`, `medium`, `high`, `critical` |
| `findings` | Array<Finding> | Stable codes plus sanitized details |
| `requiredApproval` | Enum | `none`, `userPresence`, `explicitFullAccess` |
| `agentReview` | AgentReview? | Advisory only, bounded text |
| `evaluatedAt` | Timestamp | UTC |

Critical policy blocks remain denied even if an Agent review says safe. The first release includes
hard blocks for integrity failure, identity mismatch, invalid caller, and unsupported platform.

## ApprovalGrant

| Field | Type | Rules |
|---|---|---|
| `id` | UUID | Human/audit handle; not an Agent bearer token |
| `capabilityHash` | Digest | Hash of random internal capability; raw value never persisted |
| `scope` | ApprovalScope | Exact command, normalized prefix, or explicit full access |
| `callerBinding` | CallerIdentity subset | Signing/audit/optional Agent session |
| `resourceID` / `resourceRevision` | UUID / UInt64 | Exact binding |
| `privilegeCeiling` | Enum | `user` or `sudo` |
| `policyVersion` | String | Re-evaluate on incompatible policy change |
| `maxUses` / `uses` | UInt? / UInt | Exact approval defaults to one |
| `issuedAt` / `expiresAt` | Timestamp | Mandatory expiry |
| `monotonicDeadline` | Duration anchor | Defends wall-clock rollback |
| `approvalProof` | Local approval record | No biometric data stored |
| `state` | Enum | `active`, `consumed`, `expired`, `revoked`, `invalidated` |

Any resource revision, caller mismatch, privilege escalation, scope mismatch, expiry, use exhaustion,
or revocation prevents use.

Grant matching is pure and fail-closed. Exact scope stores the `dev.safa.command/v1` fingerprint and
is valid only as a one-use grant. Prefix scope compares complete `exec` argument boundaries and does
not implicitly cover Agent stdin, TTY, or a selected working directory. Full access may cover shell
mode but remains bound to the same caller, resource revision, privilege ceiling, policy version,
expiry, and use limit. Matching never consumes a grant; the Broker request service must re-check and
increment usage in one serialized transaction before execution.

Both wall-clock and continuous monotonic deadlines must remain valid. Issuance derives them from the
same bounded duration; matching reconstructs the monotonic issue point, rejects a reset/rollback,
and rejects wall-clock elapsed time that falls materially behind monotonic elapsed time. A Broker
restart therefore cannot silently extend a persisted grant by resetting the monotonic clock.

## Policy

| Field | Type | Rules |
|---|---|---|
| `id` | UUID | Required per resource |
| `version` | String | Included in decisions and grants |
| `automaticRules` | Array<Rule> | Permit only bounded low-risk operations |
| `approvalRules` | Array<Rule> | Determine approval level and scope ceiling |
| `denyRules` | Array<Rule> | Integrity/security denials override all permits |
| `limits` | ExecutionLimits | Time, output, concurrency and TTY limits |

Rule evaluation is deterministic and emits every matched finding. Order cannot turn a deny into an
allow. Hard security or execution-limit failures and matching deny rules take precedence over
approval and automatic rules. Shell mode, sudo, stdin, TTY, a selected working directory,
interpreters, encoded payloads, redirects, command substitution, destructive patterns, and
state-changing commands cannot be downgraded by an automatic rule or Agent-authored review.

## ExecutionResult

| Field | Type | Rules |
|---|---|---|
| `startedAt` / `finishedAt` | Timestamp | UTC |
| `remoteExitCode` | Int? | Exact value when remote command started |
| `termination` | Enum | `exit`, `signal`, `timeout`, `cancel`, `transportFailure` |
| `stdout` / `stderr` | BoundedOutput | Sanitized Agent-visible output |
| `transportError` | ErrorCode? | Stable code, no endpoint or secret |
| `redactionCount` | UInt | Count only, not matched secret |

`BoundedOutput` contains bytes/text encoding state, captured byte count, total known byte count when
available, and truncation flag.

## AuditEvent

| Field | Type | Rules |
|---|---|---|
| `sequence` | UInt64 | Strictly increasing within chain |
| `id` | UUID | Unique |
| `kind` | Enum | request, decision, approval, execution, revocation, vault, integrity, package |
| `timestamp` | Timestamp | UTC |
| `requestID` / `grantID` | UUID? | References when applicable |
| `actor` | Sanitized actor | No endpoint or credential |
| `resourceAlias` | String? | Alias only |
| `summary` | Sanitized object | Bounded fields |
| `previousDigest` / `digest` | Digest | Hash/HMAC chain |

Audit retention and rotation preserve a signed/chained continuity record. Deletion by a fully
compromised local administrator is outside the local-only integrity guarantee.

## VaultEnvelope

| Field | Type | Rules |
|---|---|---|
| `formatVersion` | UInt | Clear authenticated header |
| `installationID` | UUID | Authenticated, not secret |
| `revision` | UInt64 | Must not fall below Keychain revision marker |
| `keyID` | Opaque ID | Locates broker-only data key |
| `nonce` | Bytes | Unique per encryption |
| `ciphertext` | Bytes | Encrypted `VaultDocument` |
| `tag` | Bytes | Authentication tag |

The plaintext `VaultDocument` contains resources, credential references, policies, pending requests,
active grants, settings, and schema migration metadata. Credential values and private keys remain
separate Keychain/Secure Enclave items.
