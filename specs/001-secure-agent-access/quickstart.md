# Quickstart Validation: Diagnostic MVP

Use synthetic data only. Do not register a production host or enter a real password while validating
this feature branch.

## 1. Run the automated MVP gates

```bash
xcrun swift-format lint --recursive --strict \
  Sources Tests Apps/SAFA/Targets Package.swift
swift test
swift build -c release
xcodebuild -quiet -project Apps/SAFA/SAFA.xcodeproj -scheme "SAFA Runtime" \
  -configuration Debug CODE_SIGNING_ALLOWED=NO build
```

The test journey constructs only `nas.home` with documentation-only address `203.0.113.10`; its
transport is an in-memory fake and does not open a network connection. The native Xcode build checks
the broker, CLI, and AskPass assembly without pretending that an unsigned XPC build can run.

## 2. Inspect the stable CLI surface

```bash
swift run safa version --json
swift run safa --help
swift run safa resource --help
swift run safa resource ls --help
swift run safa resource add --help
swift run safa resource edit --help
swift run safa resource disable --help
swift run safa resource enable --help
swift run safa resource remove --help
swift run safa exec --help
```

An unsigned `doctor` must fail closed because it cannot derive a Developer Team identity. It must
not fall back to raw SSH or ask for a credential.

## 3. Inspect the native runtime aggregate

The Xcode project intentionally contains no GUI target. To inspect the broker, CLI, and AskPass
runtime roots with one configured Apple Developer Team, build:

```bash
xcodebuild -project Apps/SAFA/SAFA.xcodeproj -scheme "SAFA Runtime" \
  -configuration Debug SAFA_DEVELOPMENT_TEAM=YOUR_TEAM_ID build
```

This proves native target assembly, not installation. Broker activation and signed runtime packaging
remain an open delivery task. The broker rejects clients whose Developer Team, signing identifier,
effective user, or audit session does not match.

## 4. Validate resource lifecycle through tests

The CLI-first preview has no private registration UI. Its signed runtime exposes
`resource add/edit/setup/disable/enable/remove`; each mutation requires a macOS Touch ID/login
authorization. Add/edit/setup accept only logical aliases and an optional supported host type:

```bash
safa resource add nas.home --from-ssh-config home-nas \
  --type host.nas --json
safa resource edit nas.home --from-ssh-config home-nas --json
safa resource setup nas.home --from-ssh-config home-nas --json
safa resource disable nas.home --json
safa resource enable nas.home --json
safa resource remove nas.home --json
```

The broker resolves endpoint and username locally through `ssh -G`. Add returns
`draft/needs_setup` and imports no password, private-key bytes, or host identity. Setup separately
requires an existing `known_hosts` entry and available OpenSSH identity-file/agent route, verifies
the direct route, and atomically returns `active`. `ProxyJump` and `ProxyCommand` remain unsupported.
The adapter accepts only `host.linux`, `host.macos`, and `host.nas`.
`ResourceLifecycleTests`, `ReadOnlySSHJourneyTests`, and `ResourceOnboardingTests` validate this
boundary using synthetic fixtures and contact no real host.

The safe read surface is:

```bash
swift run safa resource list --json
swift run safa resource ls --json
```

The response may contain alias, resource type, state, capabilities, health, and explicitly
allowlisted summary metadata only. It must not contain host, port, username, host fingerprint,
credential reference or Keychain locator.

Use `resource show nas.home --json` for the same non-interactive safe projection. Use
`resource inspect nas.home --json` only when protected endpoint or inventory metadata is needed;
macOS asks the local user for Touch ID/login authentication. A denial returns no detail object, and
an approval still returns no credential, key material, Keychain locator, or host fingerprint.

## 5. Validate the diagnostic MVP

```bash
swift test --filter ReadOnlySSHJourneyTests
```

The broker permits only its small read-only allowlist, writes a private isolated SSH configuration,
enforces the pinned host identity, issues one child-bound askpass response, bounds time/output,
preserves the remote exit code, redacts a matching credential from output and emits a sanitized audit
event. A changed host identity or unsupported command fails closed.

## MVP boundary

This checkpoint does not yet enable credential/host-identity onboarding for a draft, broker
activation, sudo, shell programs, arbitrary remote mutations, approval grants, recovery, notarized
distribution, or the final packaged Skill. Those remain separate Spec Kit phases; do not bypass the
diagnostic allowlist to simulate them.
