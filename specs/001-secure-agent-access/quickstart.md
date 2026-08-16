# Quickstart Validation: Diagnostic MVP

Use synthetic data only. Do not register a production host or enter a real password while validating
this feature branch.

## 1. Run the automated MVP gates

```bash
xcrun swift-format lint --recursive --strict \
  Sources Tests Apps/SAFA/App Apps/SAFA/Targets Package.swift
swift test
swift build -c release
xcodebuild -quiet -project Apps/SAFA/SAFA.xcodeproj -scheme SAFA \
  -configuration Debug CODE_SIGNING_ALLOWED=NO build
```

The test journey constructs only `nas.home` with documentation-only address `203.0.113.10`; its
transport is an in-memory fake and does not open a network connection. The native Xcode build checks
the app, broker launch agent, CLI and askpass assembly without pretending that an unsigned XPC build
can run.

## 2. Inspect the stable CLI surface

```bash
swift run safa version --json
swift run safa --help
swift run safa exec --help
```

An unsigned `doctor` must fail closed because it cannot derive a Developer Team identity. It must
not fall back to raw SSH or ask for a credential.

## 3. Build a signed development app

Configure one Apple Developer Team for every component, then build:

```bash
xcodebuild -project Apps/SAFA/SAFA.xcodeproj -scheme SAFA \
  -configuration Debug SAFA_DEVELOPMENT_TEAM=YOUR_TEAM_ID build
```

Install the resulting `SAFA.app` in a stable location, open it, and choose **Enable local broker**.
macOS may require approval in **System Settings → General → Login Items**. The broker rejects clients
whose Developer Team, signing identifier, effective user or audit session does not match.

## 4. Register a synthetic fixture privately

From the trusted app's **Resources** tab, add `nas.home`. The endpoint, username, pinned host key and
password are collected only in the signed UI and broker. Verify the host fingerprint through a
separate trusted channel before checking the confirmation box.

Then use the signed bundled CLI:

```bash
/path/to/SAFA.app/Contents/Library/Helpers/safa resource list --json
```

The response may contain alias, transport, state, capabilities and health only. It must not contain
host, port, username, host fingerprint, credential reference or Keychain locator.

## 5. Run the diagnostic MVP

```bash
/path/to/SAFA.app/Contents/Library/Helpers/safa exec nas.home --json \
  --intent "Check the synthetic service state" -- \
  systemctl is-active sample-service
```

The broker permits only its small read-only allowlist, writes a private isolated SSH configuration,
enforces the pinned host identity, issues one child-bound askpass response, bounds time/output,
preserves the remote exit code, redacts a matching credential from output and emits a sanitized audit
event. A changed host identity or unsupported command fails closed.

## MVP boundary

This checkpoint does not yet enable sudo, shell programs, arbitrary mutations, approval grants,
recovery, notarized distribution or the final packaged Skill. Those remain separate Spec Kit phases;
do not bypass the diagnostic allowlist to simulate them.
