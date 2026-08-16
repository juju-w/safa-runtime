# Broker IPC Contract v1

## Boundary

The CLI and approval app communicate with the per-user broker over a named XPC/Mach service. The
broker exposes no TCP listener and no general-purpose secret API.

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
submitExecution(ExecutionSubmission) -> RequestSnapshot
getRequest(RequestID) -> RequestSnapshot
waitRequest(RequestID, deadline) -> RequestSnapshot
cancelRequest(RequestID) -> RequestSnapshot
listGrants(GrantQuery) -> GrantPage
revokeGrant(GrantID) -> GrantSnapshot
listAudit(AuditQuery) -> AuditPage
verifyAudit() -> AuditIntegrityResult
openTrustedSetup(SetupIntent) -> UserActionSnapshot
```

`queryResourceDirectory` is the typed v1 path for `list`, `show`, and protected `inspect`. Public
queries return only safe summaries. Inspect is broker-authorized with macOS user presence and never
returns credential references, Keychain locators, passwords, tokens, private/public keys, or host
fingerprints. New resource-directory work must not add fields to the legacy dynamic broker reply.

This interface accepts no endpoint, username, password, private key, host key, sudo password,
Keychain identifier, approval decision, or raw grant capability.

### Trusted app interface

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

The broker accepts approval only from the separately identified app peer. The app may choose among
broker-proposed scopes but cannot replace the command, target, risk findings, or privilege ceiling in
an existing request.

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
