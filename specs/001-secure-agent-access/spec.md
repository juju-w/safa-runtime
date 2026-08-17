# Feature Specification: Secure Agent Access

> Repository split: the canonical Agent Skill, public contracts, resolver, and distribution model
> now live in `juju-w/safa`. This document remains the macOS Runtime implementation history.

**Feature Branch**: `feat/001-secure-agent-access`

**Created**: 2026-08-16

**Status**: Draft

**Input**: User description: "Create a macOS-only Skill with a companion CLI that lets an Agent
discover and operate registered servers without asking for or seeing IP addresses, passwords, sudo
passwords, private keys, or tokens. Keep arbitrary command execution useful, add Codex-like risk
review and user approval, encrypt the local resource inventory, and remain secure when the source is
open or a managed server is compromised."

**Delivery sequencing update**: The current phase is CLI-first. Match `ssh-hosts` behavior and prove
the broker/Keychain/XPC/SSH security boundary without a custom product GUI. System Touch ID,
Keychain, LocalAuthentication, and Authorization Services dialogs remain permitted security
controls.

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
5. **Given** a new host is not yet present in OpenSSH configuration, **When** the local user runs one
   add workflow with the SSH template, **Then** that workflow collects configuration, verifies the
   connection, and activates the resource without requiring a separate setup command or placing
   protected values in Agent-visible arguments, input, output, or logs.
6. **Given** a draft resolves to an existing remote username, **When** managed-key setup is chosen,
   **Then** SAFA enrolls a device public key for that exact user, verifies the new key before
   activation, and neither creates a remote user nor silently replaces the bootstrap credential.
7. **Given** the configured remote user may have sudo capability, **When** SSH setup completes,
   **Then** sudo discovery or enrollment remains a separate operation and setup neither requests a
   sudo password nor modifies the user's password or sudo policy.

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
- A second Mac receives synchronized resource configuration before it has a local device credential.
- The user signs out of iCloud, disables iCloud Keychain, resets encrypted CloudKit data, or creates
  conflicting resource edits on two devices while one is offline.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST be distributed primarily as an Agent Skill with a companion macOS
  runtime and MUST NOT require an external package manager for normal installation.
- **FR-002**: The system MUST expose registered infrastructure through logical resource aliases and
  MUST allow the Agent to discover only non-secret metadata needed to select a resource.
- **FR-002a**: The encrypted resource directory MUST support validated, extensible resource types,
  independently versioned templates, host platforms, roles, access methods, typed metadata,
  alternate aliases, relationships, credential kinds, and credential roles without accepting
  arbitrary JSON or embedded secrets. Resource kind, host platform, and role MUST remain separate
  dimensions; NAS is a host role rather than a host platform.
- **FR-002b**: List/default-show MUST expose only source-code-allowlisted summary fields. Protected
  show MUST require macOS device-owner authentication, rate-limit prompts, return no details when
  denied, and never disclose credentials, credential locators, key material, or host fingerprints.
- **FR-002c**: Every resource MUST have an immutable internal identifier and one canonical logical
  alias. Canonical and alternate aliases MUST be unique across the complete local catalog, not only
  within one template or resource type. Alias comparison MUST use a documented canonical form so
  case or Unicode normalization cannot create two visually equivalent selectable resources.
- **FR-002d**: `add` MUST reserve the canonical alias atomically before collecting protected values.
  If that alias or any proposed alternate alias already belongs to an active, disabled, or draft
  resource, the operation MUST return a conflict without overwriting or merging either resource and
  MUST direct the user to `edit` or explicitly remove the existing resource. Concurrent adds MUST
  produce at most one successful resource.
- **FR-003**: The system MUST collect and update endpoints, usernames, routes, passwords, private-key
  references, sudo credentials, and recovery material through a trusted flow outside Agent-visible
  input and output.
- **FR-003a**: The public resource-management surface MUST use the CRUD-oriented commands `list`,
  `show`, `add`, `edit`, and `remove`. Adapter setup, verification, activation, disabling, enabling,
  and protected inspection MUST be expressed as stages or options of those operations rather than
  separate top-level resource commands.
- **FR-003b**: A trusted local configuration flow MUST allow the user to create a resource for a new
  host without first adding an OpenSSH configuration entry. It MUST deliver protected connection
  fields directly to the Broker without echoing them to Agent-visible output or logs.
- **FR-003c**: `add` MUST own template selection, protected configuration collection, credential and
  identity verification, and activation as one user workflow. An interrupted or remediable add MAY
  preserve an internal draft, but the user MUST resume it through `edit` rather than a separate
  setup command.
- **FR-003d**: The SSH setup stage inside `add` or `edit` MUST bind authentication to the existing
  username stored in the draft and MUST verify that the remote session resolves to that username. A
  managed-key mode MAY enroll a device-generated public key for that user, but MUST NOT create a
  remote user, MUST verify the new identity before activation, and MUST preserve the prior bootstrap
  path on failure.
- **FR-003e**: SSH setup and sudo enrollment MUST remain separate capabilities. Setup MUST NOT accept
  or change a sudo password or sudo policy. Passwordless sudo MAY be detected non-interactively;
  any sudo secret MUST be enrolled through a distinct trusted local flow and stored as a separate
  device-protected credential.
- **FR-003f**: `add` and `edit` MUST select a versioned resource template that defines protected and
  public fields, defaults, validation, credential roles, health checks, and the corresponding
  adapter. The template registry MUST be extensible to profiles such as SSH host, SQL Server,
  MySQL, PostgreSQL, S3-compatible object storage, Redis, and HTTP service without adding another
  resource lifecycle.
- **FR-003g**: `edit` MUST own configuration refresh, protected field changes, credential rotation,
  and enabled/disabled state changes. Updates to an active resource MUST verify the proposed target
  and credential before atomically replacing the previous working revision; failure MUST preserve
  the prior active configuration.
- **FR-003h**: `show` MUST return a non-interactive safe summary by default. Its allowlisted summary
  MAY include canonical alias, display label, template and version, safe tags, lifecycle and health
  state, declared capabilities, and last-check time; it MUST exclude endpoints, ports, usernames,
  routes, database or bucket names, topology, credential references, and secrets. A protected-details
  option MAY disclose the configured non-secret connection and inventory fields needed for local
  diagnosis only after macOS device-owner authorization. Denial, cancellation, or prompt rate limits
  MUST return no protected fields. Even after authorization, `show` MUST never disclose a password,
  token, private or public key material, recovery value, Keychain locator, or exportable credential.
  `list` MUST remain a safe summary and MUST NOT trigger user-presence prompts.
- **FR-003i**: Agent-facing `add` and `edit` inputs MUST contain only logical aliases, template names,
  safe state choices, and other non-secret selections. They MUST NOT accept endpoints, ports,
  usernames, passwords, key paths, tokens, or sudo passwords; those values belong to the trusted
  local configuration flow.
- **FR-003j**: Agent access to the default `show` summary MUST be read-only and require no disclosure
  grant. An Agent MAY request protected details only when the user explicitly asks for connection,
  inventory, or topology details; the Broker MUST independently enforce macOS user presence and MUST
  NOT treat Agent intent, an audit string, or a previous execution approval as disclosure authority.
- **FR-003k**: Alias changes through `edit` MUST preserve the immutable resource identifier and its
  credential bindings, and MUST pass the same atomic catalog-wide collision check as `add`. Display
  labels MAY repeat because they are descriptive and MUST NOT be accepted as execution selectors.
- **FR-003l**: Resource-template schemas and adapter bindings MUST be versioned built-ins owned and
  validated by the signed Runtime. The Agent Skill MAY contain only concise template-selection
  guidance and stable template identifiers; it MUST NOT define, inject, override, or transmit a
  template's protected fields, validation rules, adapter, or health check. Adding a template in MVP
  therefore requires reviewed Runtime code, tests, and a Runtime release rather than editing
  `SKILL.md` or loading an arbitrary local template file.
- **FR-003m**: Every template MUST reuse the same small common resource model: generated immutable
  identifier; unique canonical alias; optional non-unique display label and safe tags; immutable
  template identifier and version; lifecycle and health state; protected notes and route; and typed
  template fields. Alias, display label, safe tags, and template selection are Agent-safe. Endpoint,
  route, username, database or bucket names, topology, and inventory are protected. Passwords,
  tokens, access keys, and private keys are secrets and MUST only enter the trusted local flow.
- **FR-003n**: The first built-in `ssh` template MUST collect, in one trusted local add/edit flow,
  endpoint, port with default 22, existing remote username, route mode, authentication mode and
  device-protected credential, and verified host identity. Initial setup MUST verify the declared
  Linux, macOS, or Windows platform and collect a bounded read-only inventory snapshot including
  architecture, OS/kernel, CPU, memory, root storage, hardware model, and Docker availability when
  present. Validated inventory MUST be committed atomically with activation and MUST remain
  protected detail except for explicitly allowlisted summary keys. Sudo capability and
  any sudo credential remain separate from SSH registration. The first `sqlserver` template MUST
  similarly collect endpoint, port with default 1433, optional database, username, password,
  connection route, encryption enabled by default, certificate-verification choice, and connection
  identity verification. Unsupported authentication modes or instance discovery MUST fail with a
  clear limitation rather than exposing additional ad hoc fields.
- **FR-003o**: `resource add [ALIAS] [--template TEMPLATE]` MUST be usable when the Agent supplies
  only a safe alias, or no alias when the trusted local flow is responsible for choosing one. An
  obvious template MAY be selected by the Agent; otherwise the template selector MUST appear in the
  trusted local flow. That single flow MUST collect all remaining fields, verify the target and
  credential, and activate the resource. Normal success MUST NOT require the Agent to understand or
  invoke setup, verification, enable, or credential commands.
- **FR-003p**: `resource edit ALIAS` MUST open the same trusted template form with existing
  non-secret protected values available locally and secret fields represented only as
  configured/missing. The user MUST be able to keep or replace a credential without revealing its
  current value. Edit MUST cover alias and display changes, connection changes, credential rotation,
  and enabled/disabled state. It MUST verify a changed active configuration before atomic commit and
  preserve the prior working revision on cancellation or failure.
- **FR-003q**: The Skill's Agent workflow for resource creation MUST remain deterministic and short:
  list safe aliases; invoke one `resource add` only after an explicit user request; follow only the
  Runtime's structured safe next action; then show the resulting safe summary. The Agent MUST NOT
  ask which protected fields a template contains, collect those values in conversation, or invent a
  secondary setup step. Runtime errors MUST say whether the user should retry `add`, use `edit` for
  an existing alias, or take a trusted local remediation.
- **FR-003r**: Migration from the predecessor local `ssh-hosts` Skill MUST occur through a trusted
  local import into the encrypted resource directory. The importer MAY read logical SSH aliases,
  resolved OpenSSH configuration, non-secret Core Tunnel routing metadata, alternate aliases,
  resource roles, and the existence and privilege role of matching Keychain items. It MUST NOT read
  or copy a Keychain value, private key, password, token, source `.env` value, or recovery secret.
  Real infrastructure inventory and topology MUST NOT be copied into the public Skill, source tree,
  fixtures, logs, command output, or conversation.
- **FR-003s**: SSH migration and the built-in `ssh` template MUST preserve the predecessor workflow's
  useful semantics: direct and loopback-tunnel routes, optional reviewed jump relationships,
  alternate business aliases, expected existing username, strict host-identity verification,
  non-interactive key or agent authentication, host role and caution metadata, execution capability,
  and a separate optional sudo credential role. A route preflight MUST distinguish an unavailable
  local tunnel from an authentication failure and MUST flag wildcard local binds as potentially
  LAN-exposed rather than silently treating them as loopback-only.
- **FR-003t**: Service-resource parity MUST be delivered through typed templates rather than SSH
  notes. Database templates (`mysql`, `sqlserver`, and `postgresql`) share endpoint, port, optional
  database or schema, username, route, TLS policy, credential role, and privilege tier. Object-store
  templates (`s3`, `minio`, and `oss`) share endpoint, region, optional bucket, TLS policy, access-key
  credential, and privilege tier. `redis`, `kafka`, `rabbitmq`, `mongodb`, `elasticsearch`, `neo4j`,
  and `http` templates MUST define only their protocol-specific additions while reusing the common
  route, credential, health, and relationship model.
- **FR-003u**: A service resource MUST be able to reference a host or tunnel resource as its route
  and MAY have multiple separately scoped credential roles such as read-only and administrator.
  Selection MUST default to the least-privileged healthy role sufficient for the requested action;
  an administrator or production-data role requires explicit user intent and policy evaluation.
  SSH usernames and service usernames MUST never be inferred from one another.
- **FR-003v**: The Runtime replacement for predecessor helper scripts MUST provide broker-mediated
  command execution, bounded sudo, direct credential injection into an intended child client,
  tunnel readiness checks, and sanitized credential-health checks without returning credential
  values. User creation, credential discovery from source trees, and bulk credential import remain
  explicit high-risk local workflows and MUST NOT run automatically during ordinary resource add.
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
- **FR-026**: The initial release MUST support a single local macOS user executing operations against
  SSH-accessible servers and NAS devices. Windows/Linux desktop clients, centralized team vaults,
  browser credentials, and database/HTTP/S3/cache execution adapters are outside the initial
  release, but their resource profiles MUST fit the common encrypted directory rather than require a
  second inventory or credential architecture.

### Post-MVP Same-User Device Sync Requirements

- **FR-F01**: Same-user iCloud synchronization MUST be optional. Local resource discovery and
  execution MUST continue to work without an iCloud account or network connection.
- **FR-F02**: Synchronization MUST transfer only an authenticated, encrypted resource catalog such
  as aliases, protected endpoints, ports, usernames, host identities, relationships, and policy.
  It MUST NOT synchronize the live local `vault.json` file, its device rollback marker, or a
  `ThisDeviceOnly` vault key as an opaque shared filesystem artifact.
- **FR-F03**: Secure Enclave keys, device-bound SSH credentials, sudo passwords, and other
  device-protected credentials MUST remain local by default. A resource discovered on another Mac
  MUST be non-executable with local credential health `reenroll_required` until that device enrolls
  and verifies its own credential.
- **FR-F04**: A new Mac signed into the same authorized iCloud account MUST be able to recover the
  resource catalog without re-entering endpoints, ports, usernames, or topology. Device enrollment
  MAY add that Mac's public key to the already configured remote user but MUST NOT create another
  remote user or copy an exportable private key from an existing Mac.
- **FR-F05**: Synchronization MUST define deterministic conflict resolution, authenticated revision
  handling, deletion semantics, offline reconciliation, and fail-closed behavior for iCloud logout,
  keychain reset, encrypted-data reset, or an unavailable synchronization service.
- **FR-F06**: Synchronizable credentials, if ever offered as an explicit convenience mode, MUST be
  separately consented, clearly distinguish their larger multi-device blast radius, and MUST NOT
  weaken the default device-bound credential mode.

### Key Entities

- **Resource**: A logical infrastructure target with an immutable identifier, one catalog-wide unique
  canonical alias, optional catalog-wide unique alternate aliases, an optional non-unique display
  label, an extensible kind, immutable template ID/version, optional host platform, orthogonal roles,
  typed encrypted metadata, access methods, relationships, security-domain
  membership, opaque credential references, and lifecycle state. Host identity applies to SSH
  profiles.
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
- **Device Enrollment**: The local credential and verification state that authorizes one Mac to use
  a synchronized resource. It is distinct from the resource's portable encrypted configuration.
- **Synchronized Resource Catalog**: The optional same-user encrypted representation of resource
  configuration and topology. It excludes device-bound credentials and local rollback state.
- **Resource Template**: A versioned schema and adapter binding that defines how one resource kind
  is configured, validated, authenticated, health-checked, displayed, and edited while reusing the
  common resource lifecycle.

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
- **SC-011**: A user can add and activate a new synthetic host through one `resource add` workflow
  without a separate setup command and without placing its endpoint, username, or credential in
  Agent-visible arguments, standard streams, logs, or conversation.
- **SC-012**: Managed-key setup for a synthetic existing user changes no remote account identity or
  sudo policy, preserves the bootstrap path until verification succeeds, and activates only after
  the device-generated key authenticates as that same user.
- **SC-013**: SSH and SQL Server synthetic templates both complete add, show, edit, state-change,
  and remove journeys through the same five-command resource surface while rejecting fields and
  credential roles that do not belong to the selected template.
- **SC-014**: Exact, case-variant, normalization-equivalent, alternate-alias, and concurrent duplicate
  add tests never overwrite a resource and yield exactly one selectable resource for each alias.
- **SC-015**: Default list/show responses contain zero protected fields without prompting; authorized
  protected show tests return only allowlisted non-secret details, and denied or cancelled prompts
  return no partial protected data or reusable authorization.
- **SC-016**: A basic Agent that knows only `list`, `add`, `show`, `edit`, and `remove` can register
  and later update synthetic SSH and SQL Server resources without learning either template's field
  schema and without requesting a protected value in conversation.
- **SC-017**: One successful add produces an active verified resource; one cancelled or failed add
  produces no ambiguous selectable resource, and one failed edit leaves the previously active
  revision executable and unchanged.
- **SC-018**: Importing a synthetic predecessor inventory recreates every supported alias, alternate
  alias, route relationship, service relationship, and credential role in the encrypted directory
  while leakage tests find zero real endpoint, username, credential locator, or secret in repository
  changes, Agent-visible output, logs, and process arguments.

### Post-MVP Sync Outcomes

- **SC-F01**: A second Mac signed into the authorized iCloud account discovers 100% of synchronized
  resource aliases and protected configuration without re-entry while receiving zero reusable
  credential material from the first Mac.
- **SC-F02**: Before local enrollment, every synchronized resource on the second Mac is
  non-executable and reports credential health `reenroll_required`; after enrollment, execution is
  possible only with that Mac's verified credential.
- **SC-F03**: Concurrent edits, offline recovery, iCloud logout, and encrypted-key reset never
  silently roll back a newer resource revision or fall back to an unauthenticated local copy.

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
