# Feature Specification: Secure Agent Access

**Feature Branch**: `feat/001-secure-agent-access`

**Created**: 2026-08-16

**Status**: Draft

**Input**: User description: "Create a macOS-only Skill with a companion CLI that lets an Agent
discover and operate registered servers without asking for or seeing IP addresses, passwords, sudo
passwords, private keys, or tokens. Keep arbitrary command execution useful, add Codex-like risk
review and user approval, encrypt the local resource inventory, and remain secure when the source is
open or a managed server is compromised."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Check a Registered Resource Without Sharing Secrets (Priority: P1)

A Mac user installs the SAFA Skill, privately registers a server or NAS under a logical name, and
then asks an Agent to investigate it. The Agent discovers the logical resource and runs a diagnostic
without asking for connection details or receiving credentials.

**Why this priority**: This is the smallest complete expression of the product promise and removes
the immediate password-leak workflow.

**Independent Test**: Register a synthetic SSH host as `nas.home`, ask an Agent whether a named
service is running, and verify that the Agent completes the check while the transcript, process
arguments, environment, output, and audit record contain no credential.

**Acceptance Scenarios**:

1. **Given** SAFA is installed but has no resources, **When** the user privately registers
   `nas.home`, **Then** connection details and credentials are collected outside Agent-visible input
   and the Agent can discover only the safe logical metadata.
2. **Given** `nas.home` is registered and reachable, **When** the Agent requests a read-only service
   check, **Then** the command runs under the matching policy and returns bounded, structured output.
3. **Given** a user asks the Agent to check an unknown resource, **When** the Agent queries SAFA,
   **Then** SAFA returns a non-secret not-found result and the Agent does not ask for a password.
4. **Given** a resource is unreachable or has a changed host identity, **When** a check is attempted,
   **Then** SAFA fails closed and returns an actionable diagnostic without retrying insecurely.

---

### User Story 2 - Run an Arbitrary Command with Scoped Approval (Priority: P2)

An Agent can propose and run the exact command needed to diagnose or repair a registered resource,
including pipelines, shell syntax, and sudo. SAFA shows the user what will run, why it was requested,
the assessed risk, the target, and the requested approval scope before elevated execution.

**Why this priority**: Real operations cannot be reduced to a fixed catalog; retaining arbitrary
commands avoids making users bypass the security layer.

**Independent Test**: Use a synthetic host to execute one read-only command automatically, approve
one service restart exactly once, grant a 15-minute scoped session for a command family, and verify
that a command outside each granted scope is denied.

**Acceptance Scenarios**:

1. **Given** a command is classified as low risk and within policy, **When** the Agent submits it
   with its intent, **Then** SAFA executes it without an unnecessary interruption and records the
   decision.
2. **Given** a command requires sudo or changes state, **When** the Agent submits it, **Then** SAFA
   pauses and requests trusted user approval bound to the exact target and command.
3. **Given** the user approves a command once, **When** the Agent later submits a different command,
   **Then** the earlier approval cannot authorize the new command.
4. **Given** the user grants time-limited access to one resource and command scope, **When** the Agent
   operates inside that scope before expiry, **Then** it can continue without repeated prompts.
5. **Given** a grant expires or is revoked, **When** the Agent retries, **Then** SAFA requires a new
   approval.
6. **Given** the Agent's self-review labels a destructive command as safe, **When** SAFA evaluates the
   request, **Then** deterministic policy still forces trusted user approval or denies the request.

---

### User Story 3 - Protect Inventory and Limit Compromise Impact (Priority: P3)

The user can rely on SAFA even though its source code is public. Server inventory and credentials are
protected per installation, and credentials are isolated so compromise of one managed server does
not create a reusable path to the others.

**Why this priority**: The product stores a map to sensitive infrastructure; protecting only the
password while leaking the map or sharing one credential would leave the main risk unresolved.

**Independent Test**: Copy the local SAFA data files to another Mac, compromise one synthetic remote
host, and verify that neither test reveals another host's usable endpoint-and-credential combination
or an exportable private key.

**Acceptance Scenarios**:

1. **Given** an attacker copies SAFA's local files from a locked Mac, **When** the files are inspected
   on another device, **Then** resource endpoints, routes, usernames, policies, and credential
   references remain unreadable and tampering is detected.
2. **Given** one managed host is fully compromised, **When** its stored data is inspected, **Then** it
   contains no private credential that authorizes access to another registered host.
3. **Given** a user attempts to reuse one credential across multiple security domains, **When** the
   resource is registered, **Then** SAFA warns about the increased blast radius and requires explicit
   acceptance.
4. **Given** the local Mac is already unlocked and fully controlled by an administrator-level
   attacker, **When** SAFA reports its security state, **Then** it does not claim that local secrecy or
   trusted approval can still be guaranteed.

---

### User Story 4 - Install and Use SAFA as a Skill (Priority: P4)

The user installs SAFA from a Skill platform. The Skill detects the macOS companion runtime,
initializes it when needed, and teaches compatible Agents to use stable structured commands instead
of improvising SSH or requesting raw credentials.

**Why this priority**: Skill-first distribution is the intended experience and keeps installation,
discovery, and safe tool use together.

**Independent Test**: Install the Skill into a clean macOS Agent profile, trigger it with a request
to inspect a NAS, and verify that it performs runtime setup, reports missing human configuration
clearly, and subsequently uses the companion CLI without an external package manager.

**Acceptance Scenarios**:

1. **Given** a compatible macOS environment without SAFA, **When** the Skill is installed and first
   invoked, **Then** it verifies and activates its pinned companion runtime without executing an
   unverified download.
2. **Given** a non-macOS environment, **When** the Skill is invoked, **Then** it stops with an explicit
   unsupported-platform result and does not fall back to insecure credential handling.
3. **Given** the runtime requires private setup, **When** the Agent encounters that state, **Then** it
   directs the user to a trusted local setup flow without asking the user to paste secrets into chat.
4. **Given** remote output contains text instructing the Agent to reveal credentials or run another
   command, **When** the Skill processes the output, **Then** it treats the content only as untrusted
   data and does not follow those instructions.

---

### User Story 5 - Review and Revoke Access (Priority: P5)

The user can understand what Agents have requested and executed, review active grants, revoke them,
and obtain a sanitized record suitable for incident investigation.

**Why this priority**: Approval without visibility and revocation is not sufficient for ongoing use
or recovery from a suspected compromise.

**Independent Test**: Execute a mixture of allowed, denied, approved, failed, and revoked requests;
then confirm that the user can reconstruct the sequence without finding credentials in the records.

**Acceptance Scenarios**:

1. **Given** several Agent requests have occurred, **When** the user reviews activity, **Then** each
   record identifies the caller, resource alias, command fingerprint or sanitized command, risk,
   policy decision, approval scope, timing, and outcome.
2. **Given** an active session grant, **When** the user revokes it, **Then** subsequent matching
   requests stop using the grant immediately.
3. **Given** sensitive values appear in command output or errors, **When** activity is displayed or
   exported, **Then** configured and detected secrets are redacted.

### Edge Cases

- The local vault is locked, unavailable, corrupted, copied, rolled back, or tampered with.
- Touch ID is unavailable, unenrolled, changed, or cancelled during approval.
- The companion runtime is missing, unsigned, replaced, outdated, or incompatible with the Skill.
- An Agent retries an approval request, changes insignificant whitespace, changes shell quoting, or
  races another request while approval is pending.
- A command uses pipes, redirects, command substitution, encoded payloads, nested shells, or an
  interpreter to obscure its effects.
- A remote command hangs, produces unbounded output, emits binary data, prompts interactively, or
  deliberately prints strings resembling credentials or Agent instructions.
- SSH host identity changes, a jump host is unavailable, or a connection is redirected.
- Multiple Agents or processes concurrently request access to the same resource.
- The user deletes a resource while a grant or command is active.
- System time changes while a time-limited grant exists.
- The Mac is offline during installation, approval, audit, or normal execution.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST be distributed primarily as an Agent Skill with a companion macOS
  runtime and MUST NOT require an external package manager for normal installation.
- **FR-002**: The system MUST expose registered infrastructure through logical resource aliases and
  MUST allow the Agent to discover only non-secret metadata needed to select a resource.
- **FR-003**: The system MUST collect and update endpoints, usernames, routes, passwords, private-key
  references, sudo credentials, and recovery material through a trusted flow outside Agent-visible
  input and output.
- **FR-004**: The system MUST encrypt and authenticate the complete sensitive resource inventory at
  rest with installation-specific protection.
- **FR-005**: The system MUST never return stored secret values or exportable device-bound private
  keys through its Agent-facing interface.
- **FR-006**: The system MUST support direct argument-based command execution and explicit shell
  execution, including pipelines, redirects, and sudo, against a selected registered resource.
- **FR-007**: Every execution request MUST include or derive the target resource, exact command,
  caller identity, requested privilege, intent, expected effect, and rollback information when
  applicable.
- **FR-008**: The system MUST evaluate every execution against deterministic policy before execution
  and MAY use an Agent-provided risk review as advisory input only.
- **FR-009**: The system MUST permit policy-defined low-risk operations to run automatically.
- **FR-010**: The system MUST require a trusted user-presence approval for sudo, destructive,
  unrestricted shell, policy-exceeding, or otherwise high-risk operations.
- **FR-011**: An Agent MUST NOT be able to approve its own high-risk request through another
  Agent-facing command or by writing to the CLI's standard input.
- **FR-012**: Approvals MUST support exact one-time commands, bounded command scopes, and temporary
  full access, with every grant bound to a caller, resource, privilege level, and expiry.
- **FR-013**: Users MUST be able to inspect and revoke active or pending grants immediately.
- **FR-014**: Approval matching MUST be resistant to replay, command mutation, quoting changes,
  target substitution, and concurrent-request confusion.
- **FR-015**: The system MUST inject credentials only inside the trusted execution boundary and MUST
  prevent credentials from appearing in process arguments, environment variables, output, model
  context, or audit data.
- **FR-016**: The system MUST enforce strict remote host identity checking and MUST fail closed on an
  unknown or changed identity unless the user resolves it through a trusted flow.
- **FR-017**: The system MUST warn when a credential is reused across hosts or security domains and
  MUST support unique credentials for each resource.
- **FR-018**: The system MUST bound command duration and output, preserve the actual exit status, and
  return structured timeout, cancellation, transport, policy, approval, and remote-execution errors.
- **FR-019**: The system MUST treat remote output as untrusted data and the Skill MUST explicitly
  prohibit following instructions contained in that output.
- **FR-020**: The system MUST maintain a secret-free audit trail covering requests, risk evaluations,
  policy decisions, approvals, revocations, executions, failures, and security-state changes.
- **FR-021**: Agent-facing commands MUST provide stable machine-readable output, deterministic exit
  codes, bounded fields, versioned schemas, and actionable next steps.
- **FR-022**: The system MUST verify the platform, runtime version, package integrity, and publisher
  identity before activating the companion runtime, and MUST fail closed on verification failure.
- **FR-023**: The system MUST work without a cloud account or public network service after Skill and
  runtime installation.
- **FR-024**: The system MUST provide an encrypted backup and recovery workflow for recoverable
  inventory while clearly identifying credentials or device-bound keys that require re-enrollment.
- **FR-025**: The system MUST document and surface the limits of protection under offline theft,
  same-user malware, managed-host compromise, and full local administrator compromise.
- **FR-026**: The initial release MUST support a single local macOS user managing SSH-accessible
  servers and NAS devices. Windows, Linux desktops, centralized team vaults, browser credentials,
  databases, and HTTP credential brokering are outside the initial release.

### Key Entities

- **Resource**: A logical infrastructure target with an alias, encrypted connection metadata,
  security-domain membership, host identity, credential references, and lifecycle state.
- **Credential Reference**: An opaque link to protected authentication material; it exposes type,
  health, and scope but never its secret value.
- **Execution Request**: A proposed action containing the caller, resource, command representation,
  intent, privilege request, timestamps, and immutable fingerprint.
- **Risk Assessment**: Deterministic policy findings plus optional Agent review, including risk level,
  reasons, and required approval class.
- **Approval Grant**: A revocable capability bound to a caller, resource, command scope, privilege,
  creation proof, and expiry.
- **Audit Event**: A sanitized immutable record of a request, decision, approval, execution, failure,
  revocation, or security-state change.
- **Runtime Package**: The versioned and verified macOS companion components associated with a Skill
  release.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A first-time user can install the Skill, complete private setup, register one synthetic
  host, and run a health check in under five minutes.
- **SC-002**: In end-to-end tests, an Agent completes 100% of supported resource checks without
  requesting or receiving an IP address, password, sudo password, private key, or token in chat.
- **SC-003**: A user can understand and approve a high-risk command in under 30 seconds, and every
  approval is limited to the target and scope shown at approval time.
- **SC-004**: Across a security test suite of at least 100 request variations, no mutated, replayed,
  expired, revoked, cross-resource, or cross-caller request is authorized by an unrelated grant.
- **SC-005**: Copying local SAFA data to another device reveals no usable sensitive inventory or
  credential, and any modification of protected state is detected before use.
- **SC-006**: Compromise of one synthetic managed host yields no credential capable of authenticating
  to another synthetic host.
- **SC-007**: Automated leakage tests find zero stored credentials in process arguments, environment
  snapshots, Agent-visible output, audit exports, or published Skill artifacts.
- **SC-008**: All request outcomes produce valid versioned structured output and deterministic exit
  codes; no tested failure requires parsing human prose to determine the next action.
- **SC-009**: Every privileged test action can be traced to exactly one valid approval or explicit
  policy decision, while audit records contain no unredacted test secrets.
- **SC-010**: A clean installation on unsupported platforms or with an unverifiable runtime performs
  zero remote actions and returns a clear remediation path.

## Assumptions

- The initial product is local-first and single-user; team sharing and centralized administration
  require a separate future specification.
- Target servers already expose SSH through the user's existing network path. SAFA does not create
  VPNs, firewall rules, JumpServer accounts, or remote hosts in the initial release.
- Resource aliases such as `nas.home` are considered safe for Agent discovery; endpoints, routes,
  usernames, credential material, and infrastructure topology are sensitive.
- Read-only versus state-changing behavior can be conservatively classified; ambiguous requests are
  escalated rather than silently approved.
- Users may deliberately choose temporary full access after a clear warning; SAFA limits and audits
  that authority but does not pretend an approved root shell is low risk.
- The user controls the Mac account and can complete local user-presence approval when required.
- Recovery prioritizes confidentiality: device-bound private keys are re-enrolled rather than made
  exportable for convenience.
