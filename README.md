<p align="center">
  <img src="docs/assets/safa-readme-hero.webp" alt="SAFA owl guardian routing an AI agent diagnostic to a registered macOS-managed resource without exposing credentials" width="100%">
</p>

# SAFA

**Secure Access for Agents on macOS.** Let an AI agent discover registered resources by logical name
and run bounded operations while reusable credentials remain inside the local macOS security
boundary. SSH hosts are the first working adapter; the encrypted directory is designed to add
database, object-storage, cache, and service profiles without creating a second secret workflow.

[![CI](https://github.com/juju-w/safa-mac/actions/workflows/ci.yml/badge.svg)](https://github.com/juju-w/safa-mac/actions/workflows/ci.yml)
[![GitHub stars](https://img.shields.io/github/stars/juju-w/safa-mac?style=flat)](https://github.com/juju-w/safa-mac/stargazers)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![macOS 14.4+](https://img.shields.io/badge/macOS-14.4%2B-black)
![Swift 6](https://img.shields.io/badge/Swift-6-F05138?logo=swift&logoColor=white)

> [!IMPORTANT]
> SAFA is currently an early diagnostic MVP, not a production release. The bounded read-only path is
> implemented; arbitrary commands, sudo approval, persistent audit storage, notarized distribution
> and the final globally installable Skill are still roadmap items.

## Stop pasting infrastructure secrets into chat

Imagine a service alert arrives:

> **You:** Find out why `report.prod` is alerting and whether the service is unhealthy.

Without a local access boundary, the conversation often becomes:

> **Agent:** What is the machine's IP and SSH port? Which username and password should I use? This
> check may need sudo—please send the sudo password too.

That puts infrastructure inventory and reusable credentials into chat history, process context, logs
or model-visible tools.

With SAFA, the user first imports `report.prod` through a local, system-authenticated setup flow.
The endpoint, username, pinned host identity and password are stored behind the broker's encrypted
vault and macOS Keychain boundary. The Agent normally receives only the safe alias and invokes the
signed CLI:

```bash
safa exec report.prod --json \
  --intent "Check why the report service is alerting" -- \
  systemctl is-active report-api
```

The Agent can inspect the bounded, redacted result but cannot retrieve the plaintext password.
Protected inventory—including an endpoint—requires an explicit `resource inspect` operation and a
macOS user-presence prompt. If SAFA is unavailable or the host key changes, it fails closed instead
of asking the user for a credential or falling back to raw SSH.

## What SAFA protects

- **Extensible private resource directory** — hosts, databases, object stores, caches, and services
  share typed aliases, metadata, relationships, and opaque credential references. Hosts, ports,
  usernames and routes live in an authenticated encrypted vault rather than in Agent prompts.
- **Two-level discovery** — list/show exposes only source-code-allowlisted summary metadata;
  protected inspect requires a macOS Touch ID/login prompt and still never returns credentials or
  key material.
- **macOS-backed credentials** — passwords use the data-protection Keychain; device-bound P-256 key
  primitives use Secure Enclave where supported.
- **Signed local boundary** — the app, per-user broker, CLI and AskPass helper authenticate peers by
  code signature, Developer Team, effective user and audit session.
- **Strict remote identity** — every SSH execution uses an isolated configuration and a pinned host
  key. Changed identity is a hard failure.
- **One-shot password delivery** — AskPass credentials are bound to the exact launched SSH child PID,
  expire quickly and can be consumed only once.
- **Bounded evidence** — execution has time and output limits, preserves the remote exit code and
  redacts matching credential bytes before returning data to the Agent.
- **Audit events** — the MVP emits sanitized request, decision and execution events. Persistent,
  tamper-evident audit history and review UI are planned for the authorization phase.

## Permissions and blast radius

SAFA is designed to complement server and database permissions, not replace them. A practical
deployment should register separate resource aliases and least-privilege remote accounts for each
security domain—for example, a read-only reporting account must not share credentials with a database
administrator or production deployment account.

The current MVP isolates each resource credential and permits only a small diagnostic allowlist.
Fine-grained command scopes, database-role-aware workflows, Touch ID approval, sudo injection,
time-limited grants and immediate revocation are specified for the next authorization phase.

Development is currently CLI-first. The existing SwiftUI app is a deferred prototype: no new
windows, menu-bar features, dashboards, or custom approval UI will be added until `ssh-hosts` parity
and the native security gates are complete. macOS system Touch ID and Keychain prompts remain part
of the security boundary.

## Current diagnostic MVP

Implemented now:

- private password-backed add/edit resource onboarding in the existing deferred app prototype;
- safe resource discovery by logical alias;
- encrypted inventory and Keychain password storage;
- strict pinned-host SSH configuration;
- argument-constrained diagnostics such as `systemctl is-active`, fixed-field process/container
  metrics, `df`, `free` and `uptime`; secret-dumping variants are rejected;
- child-bound one-shot AskPass, output redaction and sanitized audit emission;
- fail-closed unsigned runtime, peer, host-identity, timeout and unsupported-command behavior;
- 37 synthetic contract, integration and security tests that contact no real server.

Not yet shipped:

- arbitrary shell commands, mutations, sudo and trusted user approval;
- persistent audit verification, recovery and credential-reuse warnings;
- complete Secure Enclave public-key onboarding through the SSH agent channel;
- signed/notarized universal app artifacts and an installable global Skill package.

## Build and validate

The unsigned build validates assembly only. Runtime XPC, Keychain and ServiceManagement behavior
requires all four components to be signed by the same configured Apple Developer Team.

```bash
xcrun swift-format lint --recursive --strict \
  Sources Tests Apps/SAFA/App Apps/SAFA/Targets Package.swift
swift test
swift build -c release
xcodebuild -quiet -project Apps/SAFA/SAFA.xcodeproj -scheme SAFA \
  -configuration Debug CODE_SIGNING_ALLOWED=NO build
```

See the [diagnostic MVP quickstart](specs/001-secure-agent-access/quickstart.md) for the synthetic
journey and signed development setup.

## Distribution roadmap

SAFA follows the open Agent Skills format, with a macOS-native companion runtime providing the
security boundary. Distribution work starts only after signed artifact verification and the Skill
forward-test are complete.

1. **[skills.sh](https://www.skills.sh/)** — first public discovery target, with an exact-version and
   digest-pinned macOS runtime rather than an unverified download.
2. **[OpenAI Plugin Directory](https://help.openai.com/en/articles/20001256-plugins-in-codex)** —
   package the Skill and its companion-runtime setup as a reviewable plugin.
3. **[Claude Code Plugin Marketplace](https://code.claude.com/docs/en/plugin-marketplaces)** — add a
   validated marketplace manifest and versioned plugin release.
4. **[GitHub Copilot Agent Skills](https://docs.github.com/en/copilot/concepts/agents/about-agent-skills)**
   — support personal/global Skill locations without weakening SAFA's local trust boundary.
5. **[SkillHub](https://skillhub.cn/)** — evaluate a China-friendly mirror after release provenance,
   signature and update behavior can be preserved.

## Design and specification

The owl guardian is SAFA's visual shorthand for a local, watchful security boundary. Source-ready
brand assets are available as a [transparent mascot](docs/assets/safa-mascot.webp), a
[square icon master](docs/assets/safa-icon-master.png) and a
[GitHub avatar candidate](docs/assets/safa-github-avatar.png). The same icon is wired into the native
macOS asset catalog and Skill metadata; publishing those packages remains intentionally disabled.

- [Normative architecture and SSH parity plan](ARCHITECTURE.md)
- [Initial code architecture audit](docs/architecture/reviews/2026-08-16-initial-code-audit.md)
- [Project Swift development Skill](.agents/skills/develop-swift/SKILL.md)
- [Project macOS CLI development Skill](.agents/skills/build-macos-cli/SKILL.md)
- [Project constitution](.specify/memory/constitution.md)
- [Feature specification](specs/001-secure-agent-access/spec.md)
- [Implementation plan](specs/001-secure-agent-access/plan.md)
- [Task breakdown](specs/001-secure-agent-access/tasks.md)
- [CLI contract](specs/001-secure-agent-access/contracts/cli-v1.md)

SAFA is licensed under the [MIT License](LICENSE).
