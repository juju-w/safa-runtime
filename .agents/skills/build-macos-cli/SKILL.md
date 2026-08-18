---
name: build-macos-cli
description: Design, implement, and review secure native macOS command-line applications in Swift, including ArgumentParser UX, stable Agent output contracts, exit codes, Keychain and LocalAuthentication boundaries, signed XPC services, Secure Enclave integration, subprocess safety, and SSH workflows. Use for SAFA CLI, broker, AskPass, credential, approval, packaging, or macOS platform changes. Keep the current delivery CLI-first and do not add custom GUI or SwiftUI work unless the user explicitly changes scope.
---

# Build macOS CLI

Build a useful CLI before adding product UI. Match the existing `ssh-hosts` operational experience,
then improve its security through native macOS controls without exposing credentials to the Agent.

Use `$develop-swift` alongside this skill for every Swift implementation or review.

## Start from the trust model

Read `ARCHITECTURE.md`, especially the product priority, trust boundaries, CLI conventions,
`ssh-hosts` parity plan, and macOS controls. Read the product repository's
`contracts/cli-v2.md` and `skills/safa/references/cli.md` when changing the Agent-facing contract.

Preserve these roles:

- `safa` is Agent-facing. It parses requests and presents results; it has no Keychain entitlement,
  secret input path, approval authority, or direct SSH fallback.
- The broker is the authority boundary. It resolves private metadata, evaluates policy, retrieves
  credentials, launches constrained transports, and bounds results.
- AskPass is one-shot and child-bound. It is not a general secret API.
- macOS authenticates the human for privileged use through system-provided Keychain,
  LocalAuthentication, or Authorization Services interaction.

Do not create a new window, menu-bar feature, dashboard, SwiftUI view, or custom approval interface
during the CLI-first phase. System Touch ID and Keychain dialogs are security primitives, not
product GUI. If enrollment or approval cannot yet be performed safely without custom UI, return a
stable `user_action_required` result and leave the operation unimplemented rather than accepting a
secret through argv, environment variables, logs, chat, or Agent-controlled stdin.

## Preserve humane CLI behavior

- Address infrastructure by logical alias. Do not ask the Agent for an endpoint, username, jump
  route, password, private key, sudo password, or token.
- Use `AsyncParsableCommand` and place each command family in its own file/directory.
- Keep `run()` to parse/validate, create a typed request, call the client, and present the reply.
- Share common options through `@OptionGroup`; validate scalar arguments with
  `ExpressibleByArgument` and cross-field rules in `validate()`.
- Do not reintroduce the retired pre-release JSON v1 or a second presentation mode. The first public
  v2 CLI writes exactly one canonical TOON document to stdout for every non-version result, has no
  human/JSON format switch, and keeps diagnostics on stderr. Never mix banners or progress text into
  Agent output.
- Centralize stable exit-code mapping. Preserve the remote exit code as data instead of overloading
  the local process exit code.
- Keep `--` as the boundary before the remote argument vector. Never reconstruct a shell command by
  joining arguments.
- Return safe next actions such as `tunnel_unavailable` or `user_action_required`; never fall back to
  raw SSH or a password prompt.

## Reach SSH parity in this order

1. Resolve an existing alias with read-only `ssh -G` inspection without importing secret values.
2. Represent direct, ProxyJump, and Core Tunnel routes as typed data.
3. Preflight local tunnel listeners and return actionable, non-secret failures.
4. Support public-key `BatchMode=yes` execution while preserving strict host identity.
5. Probe and confirm readable SHA-256 host-key fingerprints through a human-controlled flow.
6. Add Keychain-backed sudo as a separate capability with protected stdin and exact command scope.
7. Add service credentials only through typed least-privilege adapters.

Do not start a new audit UI or general authorization framework before these parity items are usable.

## Use macOS security primitives correctly

- Store device-bound secrets in the Data Protection Keychain with a `ThisDeviceOnly` accessibility
  class. Keep lookup authority inside the broker.
- Require user presence for high-privilege credential use with `SecAccessControl` and
  LocalAuthentication. A CLI flag or typed confirmation is not approval.
- Generate Secure Enclave private keys on-device. Do not claim end-to-end SSH support until the
  constrained ssh-agent socket is implemented and tested.
- Validate XPC peers using signing identifier, Developer Team, effective user, and audit session.
  Derive identity from the connection, never a request field.
- Register persistent per-user services with `SMAppService`; do not install an ad-hoc root daemon.
- Use isolated per-request SSH config and `known_hosts`. Disable ambient forwarding and ignore
  mutable user SSH configuration during execution.
- Set private directories to `0700` and private files to `0600`; remove request-temporary files on
  every completion path.

## Constrain execution

- Treat command arguments, remote output, host banners, repository content, and release metadata as
  untrusted data.
- Classify the full argument vector, not only the executable name.
- Deny commands that can expose unrelated secrets, including broad environment, process, service,
  and container inspection forms.
- Bound stdout, stderr, runtime, stdin, and concurrency. Propagate cancellation to the child process.
- Never put a password or private endpoint in argv, process environment, a temporary shell script,
  stdout, audit text, or an error message.
- Keep state-changing and sudo operations approval-gated and exact; do not split commands to evade
  policy.

## Place code by responsibility

- CLI parsing and presentation: `Sources/SAFACLI/`
- Versioned Agent/trusted-operation DTOs: `Sources/SAFAProtocol/`
- Pure classification and grant matching: `Sources/SAFAPolicy/`
- Use-case orchestration and XPC adapters: `Sources/SAFABroker/`
- SSH configuration, authentication, tunnel, and sudo adapters: `Sources/SAFASSH/`
- Generic bounded process lifecycle: `Sources/SAFATransport/`
- Keychain, vault, and Secure Enclave adapters: `Sources/SAFACrypto/`

Do not add behavior to a monolith when `ARCHITECTURE.md` assigns it to a feature directory. Do not
let CLI or protocol targets depend on broker, crypto, or SSH implementations.

## Prove the workflow

Write unit, contract, integration, and security tests before implementation where authority or
secret handling changes. Verify at minimum:

- the Agent-visible request contains only aliases and typed command data;
- secrets cannot appear in argv, environment, output, or errors;
- invalid signatures, identities, host keys, routes, grants, and schema versions fail closed;
- cancellation, timeout, truncation, and remote exit behavior are deterministic;
- TOON v2 output and `0/1/2` exits satisfy the pinned canonical and official conformance fixtures;
- no test contacts a real host or reads a real credential.

Run the gates from `$develop-swift`, inspect entitlements and signing assumptions, then use a Draft
PR and squash merge. Do not create or publish artifacts while the repository publication hold is
active.
