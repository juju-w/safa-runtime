# Quickstart Validation: Secure Agent Access

This guide validates the implemented feature with synthetic data only. Do not register a production
server or use a real password while running these scenarios.

## Prerequisites

- macOS 14.4 or newer.
- Xcode with the repository's supported Swift toolchain.
- A development signing identity for signed XPC/Keychain integration tests.
- No real SAFA vault in the test user's application-support directory.

## 1. Validate repository and contracts

```bash
swift test
./Scripts/scan-secrets.sh
./Scripts/verify-package.sh --source-only
```

Expected results:

- Domain, policy, scope, crypto-envelope, redaction, and protocol tests pass.
- Contract fixtures conform to [CLI v1](contracts/cli-v1.md).
- The secret scanner finds no credentials or real infrastructure metadata.

## 2. Build the signed development runtime

```bash
./Scripts/build-release.sh --configuration debug --development-signing
./Scripts/verify-package.sh build/SAFA.app
```

Expected results:

- `SAFA.app`, `safa`, `SAFABroker`, and `SAFAAskPass` have the expected distinct signing identifiers.
- The broker and app have only their documented entitlements; the CLI has no Keychain access group.
- The app contains the per-user launch-agent registration payload.

## 3. Install the local Skill artifact

```bash
./Scripts/package-skill.sh --runtime build/SAFA.app --output build/safa.skill
./Scripts/verify-package.sh build/safa.skill
```

Install `build/safa.skill` through the target Skill platform's local-development flow, then invoke:

```bash
build/safa.skill/scripts/safa doctor --json
```

Expected result: schema `dev.safa.cli/v1`, supported macOS, verified runtime, and either `completed`
or a `user_action_required` next step that opens trusted setup.

## 4. Register a synthetic resource privately

```bash
build/safa.skill/scripts/safa resource add test.nas --json
```

Complete the trusted SAFA app flow using the isolated SSH fixture from `Tests/Fixtures`. Do not enter
the endpoint or credential into the Agent terminal.

Then run:

```bash
build/safa.skill/scripts/safa resource list --json
```

Expected result: the response contains alias `test.nas`, transport, state, capabilities, and health;
it contains no host, port, username, credential identifier, host key, or jump route.

## 5. Run a low-risk diagnostic

```bash
build/safa.skill/scripts/safa exec test.nas --json \
  --intent "Check the synthetic service state" \
  -- systemctl is-active sample-service
```

Expected result: the request is automatically allowed by test policy, completes through the broker,
and returns bounded output plus the exact synthetic remote exit code.

## 6. Exercise approval and scope binding

Submit a state-changing request:

```bash
build/safa.skill/scripts/safa exec test.nas --json \
  --intent "Restart the synthetic service" \
  --expected-effect "The fixture service restarts" \
  --rollback "Start the previous fixture process" \
  --sudo -- systemctl restart sample-service
```

Expected result: exit code 21 and `approval_required`. Approve the exact command in SAFA.app, then
run the returned safe wait command. Confirm successful completion.

Repeat with one argument changed. Expected result: the first approval does not authorize it.

Create a 15-minute scoped grant in the app for `systemctl restart` on `test.nas`; verify matching
commands work, a different executable is denied or requires approval, and revocation takes effect
immediately.

## 7. Exercise explicit shell behavior

```bash
build/safa.skill/scripts/safa shell test.nas --json \
  --intent "Measure synthetic disk usage" \
  --expected-effect "Read-only reporting" \
  --command 'du -sk /fixture/* | sort -n'
```

Expected result: the complete shell program is fingerprinted and shown for approval according to the
test policy. Quoting or program changes do not reuse an exact-command approval.

## 8. Validate compromise boundaries

Run the security suite:

```bash
swift test --filter Security
./Scripts/verify-package.sh --adversarial build/safa.skill
```

The suite must prove:

- copied or modified vault files cannot be opened on a different test installation;
- one fixture host contains no private credential accepted by another fixture host;
- request replay, resource revision, caller change, expiry, revocation and clock rollback fail;
- credentials do not appear in argv, environment snapshots, CLI output, logs or Skill artifacts;
- remote prompt-injection strings remain output data and cause no follow-up action;
- an unsigned/replaced CLI, broker, app, helper, or package is rejected.

## 9. Verify audit and cleanup

```bash
build/safa.skill/scripts/safa audit verify --json
build/safa.skill/scripts/safa audit list --json --limit 100
build/safa.skill/scripts/safa grant revoke-all --json --resource test.nas
```

Expected result: the audit chain verifies, every privileged execution maps to one valid policy
decision or approval, and no synthetic secret appears in the audit export.

Remove the isolated test resource and development runtime through the trusted app. Test cleanup must
not touch a normal user's SAFA state.
