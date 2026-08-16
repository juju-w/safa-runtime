# Data Model: Secure Agent Access

All persisted domain records use UUID identifiers, explicit schema versions, UTC wall-clock times,
and monotonic deadlines where expiration decisions are security-sensitive. Human-readable aliases
are unique per local vault. Sensitive records live only inside the authenticated encrypted vault
unless stated otherwise.

## Resource

Represents a logical server or NAS target.

| Field | Type | Rules |
|---|---|---|
| `id` | UUID | Stable, never reused |
| `alias` | String | 1-64 chars; lowercase letters, digits, dots and hyphens; unique |
| `displayName` | String? | Human-only label; encrypted |
| `transport` | Enum | MVP value: `ssh` |
| `endpoint` | Host + port | Encrypted; never Agent-visible |
| `username` | String | Encrypted; never Agent-visible |
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

## CredentialReference

Opaque metadata pointing to protected material held by Keychain or Secure Enclave.

| Field | Type | Rules |
|---|---|---|
| `id` | UUID | Random; also used as opaque Keychain account identifier |
| `kind` | Enum | `sshSecureEnclaveKey`, `sshPassword`, `sudoPassword` |
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
allow.

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
