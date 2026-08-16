<!--
Sync Impact Report
- Version change: template -> 1.0.0
- Added principles:
  - I. Secrets Never Cross the Agent Boundary
  - II. Useful Command Execution with Scoped Authority
  - III. macOS-Native Trust Boundary
  - IV. Open Design, Encrypted User State
  - V. Deterministic Contracts and Complete Auditability
- Added sections:
  - Security and Product Constraints
  - Spec-Driven Development Workflow
- Removed sections: none
- Deferred items: none
-->
# SAFA Constitution

## Core Principles

### I. Secrets Never Cross the Agent Boundary
The Agent MUST identify resources and request actions through opaque logical names. SAFA MUST NOT
return passwords, private keys, sudo credentials, API tokens, recovery material, or decrypted vault
contents to an Agent. Secrets MUST be injected only at the final trusted execution boundary and MUST
not appear in command arguments, environment variables, standard output, logs, crash reports, or
model context. No public command may reveal or export a stored secret.

Rationale: the primary product promise is that an Agent can use an authorized capability without
possessing the credential behind it.

### II. Useful Command Execution with Scoped Authority
SAFA MUST support arbitrary remote commands because investigation and repair cannot be reduced to a
fixed command catalog. Every execution MUST nevertheless be bound to an exact resource, caller,
privilege level, command or approved command scope, and expiry. Low-risk requests MAY run
automatically under policy. Higher-risk, sudo, destructive, or unrestricted shell requests MUST
require an approval that the requesting Agent cannot manufacture. Full-access grants MUST be
explicit, time-limited, resource-limited, visible, revocable, and audited.

Rationale: security controls that make the tool operationally useless will be bypassed; useful
capability with enforceable boundaries is safer than an impractical allowlist.

### III. macOS-Native Trust Boundary
The first supported platform MUST be macOS. Credential storage MUST use Keychain access controls;
device-bound private keys SHOULD use Secure Enclave when compatible hardware exists; sensitive
approval MUST use macOS user-presence mechanisms such as Touch ID. The trusted broker MUST be
separated from the Agent-facing CLI, authenticate its client, expose no network listener by default,
and ship as signed, notarized, hardened macOS code. Security-critical behavior MUST fail closed when
platform guarantees or signature verification are unavailable.

Rationale: the operating system, rather than prompt instructions, must enforce the credential and
approval boundary.

### IV. Open Design, Encrypted User State
The source code MUST be releasable under the MIT License and the design MUST assume attackers know
the implementation. No security property may depend on obscurity, a hard-coded key, or a private
algorithm. Resource inventory, endpoints, usernames, routes, policies, and credential references
MUST be encrypted and authenticated at rest. Keys MUST be generated per installation. Published
Skill packages, examples, tests, fixtures, and repository history MUST contain no real infrastructure
metadata or credentials.

Rationale: open review strengthens the implementation while per-installation keys protect each
user's private state.

### V. Deterministic Contracts and Complete Auditability
The companion CLI MUST provide stable machine-readable output, deterministic exit codes, bounded
output, explicit risk and approval states, and actionable error recovery. Every requested action,
policy decision, approval scope, execution outcome, and relevant security event MUST be audited
without recording secrets. Remote output MUST be treated as untrusted data and MUST never be
interpreted as instructions by the Skill. Security-sensitive parsers, redaction, policy matching,
approval binding, and vault state transitions MUST have automated tests before release.

Rationale: Agents require compact predictable interfaces, while users require evidence of what was
requested, approved, and executed.

## Security and Product Constraints

- The product consists of an Agent Skill plus a signed macOS companion runtime. The Skill guides
  tool use; the runtime enforces security.
- Skill installation is the primary distribution path. Homebrew MAY exist for developers but MUST
  NOT be required for normal use.
- Packaged binaries MUST be version-pinned and signature-verified. Bootstrap code MUST NOT execute
  unverified downloads or use `curl | sh` installation patterns.
- SAFA MUST distinguish offline theft, same-user compromise, remote-host compromise, and full local
  administrator compromise in its threat model. It MUST NOT claim to protect an unlocked Mac after
  complete root or kernel compromise.
- Credentials MUST be unique per host or security domain by default. Shared credentials MUST produce
  a visible warning and require explicit acceptance.
- Compromise of one managed host MUST NOT disclose credentials that authorize access to another
  host. Remote systems SHOULD receive public keys or short-lived capabilities, not reusable secrets.
- Arbitrary shell, pipes, redirects, sudo, and destructive commands remain supported but MUST receive
  risk-appropriate review and approval.
- A model-generated self-review MAY inform automatic approval but MUST NOT be the sole authority for
  high-risk actions. Human approval MUST be proven through a trusted local channel.
- No feature may silently weaken encryption, client authentication, code-signature checks,
  destination binding, approval scope, or audit coverage for convenience.

## Spec-Driven Development Workflow

1. Define or amend user-visible behavior in a Spec Kit feature specification before implementation.
2. Record security decisions, alternatives, and threat assumptions in the feature research and plan.
3. Define CLI and broker contracts before implementing either side.
4. Write automated tests for security-critical behavior, including negative and adversarial cases,
   before considering the behavior complete.
5. Validate the Skill independently from the runtime: another Agent must be able to select the Skill,
   recover from errors, and avoid requesting raw credentials.
6. Never use real infrastructure, production credentials, or live destructive operations in automated
   tests. Use synthetic fixtures and isolated test hosts.
7. Review every release for secret leakage, dependency licensing, signing/notarization, reproducible
   packaging metadata, and backward compatibility of the CLI JSON contract.

## Governance

This constitution supersedes conflicting project documentation and implementation convenience.
Every specification, plan, task list, pull request, and release MUST include a constitution check.
Exceptions require a documented threat analysis, explicit maintainer approval, a bounded duration,
and a removal or migration plan.

Amendments MUST update this document and its Sync Impact Report. Versions follow semantic versioning:
MAJOR for incompatible principle removal or redefinition, MINOR for new principles or materially
expanded obligations, and PATCH for clarifications that do not change obligations. Security defects
that violate a principle block release. Maintainers MUST review the threat model and constitution at
least once before every minor or major release.

**Version**: 1.0.0 | **Ratified**: 2026-08-16 | **Last Amended**: 2026-08-16
