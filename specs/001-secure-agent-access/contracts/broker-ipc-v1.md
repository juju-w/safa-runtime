# Broker IPC Contract v1

## Boundary

The CLI and separately signed trusted local processes communicate with the per-user broker over
named XPC/Mach services. The broker exposes no TCP listener and no general-purpose secret API. The
current preview ships a separately signed no-custom-GUI resource-setup client; approval UI for
arbitrary execution remains outside this phase.

Before accepting a message, each side validates the peer's code-signing requirement. The broker also
checks effective user and audit session. Distribution builds accept only the expected Developer Team,
signing identifier, and component-specific entitlement. Development acceptance is explicit and cannot
be enabled in a release build.

## Interfaces

### Agent client interface

```text
runtimeStatus() -> RuntimeStatus
listResources(ResourceQuery) -> ResourcePage
queryResourceDirectory(ResourceDirectoryRequestV1) -> ResourceDirectoryReplyV1
mutateResource(ResourceMutationRequestV1) -> ResourceMutationReplyV1
submitExecution(ExecutionSubmission) -> RequestSnapshot
getRequest(RequestID) -> RequestSnapshot
waitRequest(RequestID, deadline) -> RequestSnapshot
cancelRequest(RequestID) -> RequestSnapshot
listGrants(GrantQuery) -> GrantPage
revokeGrant(GrantID) -> GrantSnapshot
listAudit(AuditQuery) -> AuditPage
verifyAudit() -> AuditIntegrityResult
```

`queryResourceDirectory` is the typed v1 path for `list`, `show`, and protected `inspect`. Public
queries return only safe summaries. Inspect is broker-authorized with macOS user presence and never
returns credential references, Keychain locators, passwords, tokens, private/public keys, or host
fingerprints. New resource-directory work must not add fields to the legacy dynamic broker reply.

`mutateResource` is a separate typed method for `add`, `edit`, `setup`, `disable`, and `remove`.
Every mutation requires macOS user presence. The request may carry logical aliases and a supported
resource type, but no endpoint, username, credential locator, key path, host key, or approval value.
This separation prevents a future query-only client from gaining mutations merely by selecting a
different action on the query DTO.

This interface accepts no endpoint, username, password, private key, host key, sudo password,
Keychain identifier, approval decision, or raw grant capability.

### Reserved trusted local interface

```text
beginPrivateSetup(PrivateSetupDraft) -> SetupSession
commitPrivateSetup(SetupSessionID, ProtectedSetupValues) -> ResourceSnapshot
getApprovalPresentation(RequestID) -> ApprovalPresentation
decideApproval(RequestID, Decision, Scope, AuthenticationContextProof) -> RequestSnapshot
listSensitiveResourceDetails(ResourceID) -> TrustedResourceDetails
rotateHostIdentity(ResourceID, HostIdentityDecision, AuthenticationContextProof) -> ResourceSnapshot
exportRecovery(RecoveryOptions, AuthenticationContextProof) -> RecoveryResult
importRecovery(RecoveryPackage, AuthenticationContextProof) -> RecoveryResult
```

The Broker accepts resource setup only from the `dev.safa.trusted-local` peer signed by the same
Developer Team and running as the same user/audit session. Setup sessions bind begin and commit to
that caller, expire within five minutes, and are single-use. The helper accepts only a safe alias and
host type in argv; endpoint, account, fingerprint, and password are read with terminal echo disabled
and sent only in the protected typed XPC payload. The Broker verifies the live host, account,
platform, and inventory before Keychain persistence.

Future approval uses the same separately identified role but may choose only among Broker-proposed
scopes; it cannot replace the command, target, risk findings, or privilege ceiling. The
trusted-local role is not evidence that a custom GUI is part of the current product.

## Message properties

- Every request carries `protocolVersion`, `messageID`, `sentAt`, and a deadline.
- The broker derives caller signing/effective-user/audit-session identity from XPC, not payload.
- All strings and arrays have explicit size limits before decoding into domain objects.
- Unknown message types and unknown required enum values fail closed.
- Replies contain stable error codes and sanitized values equivalent to the CLI envelope.
- Cancellation propagates to pending waits and child processes where applicable.

## Approval binding

An approval decision covers the broker-generated immutable presentation:

```text
request ID
request fingerprint
resource ID and revision
caller identity and audit session
command mode and canonical command fingerprint
privilege
risk findings and policy version
selected scope and expiry
presentation nonce
```

LocalAuthentication proves user presence for the decision. SAFA stores only the fact, policy, domain
state reference where safe, and timestamps; it does not store biometric data or a reusable macOS
authentication credential.

## Request waiting

`waitRequest` is bounded and does not keep an approval capability in the client. A disconnected client
can query the request later if its caller binding matches. A different caller can see only a generic
not-found response.

## Process execution ownership

Only the broker launches SSH and helper processes. The CLI never receives a file descriptor connected
to credential input. The askpass helper accepts a single broker-issued child binding, validates its
parent/request association through XPC, writes one credential response to its inherited SSH pipe, and
exits. It cannot list credentials or ask for an arbitrary credential ID.

## Failure behavior

Peer-validation, vault-integrity, resource-revision, host-identity, approval-fingerprint, or child-
binding failure records a sanitized security audit event and returns a stable failure. It never falls
back to a weaker IPC channel, interactive SSH prompt, user SSH configuration, or Agent-provided
endpoint.
