# CLI Contract v1

## Invocation rules

- Binary name: `safa`.
- Agent callers MUST pass `--json`; the Skill always does so.
- Human-readable output is optional and MUST be derived from the same response object.
- Secrets and encrypted infrastructure metadata are never accepted as ordinary command arguments.
- Private setup is not exposed through the Agent-facing CLI and never prompts through stdin. The
  current preview reports the trusted registration flow as unavailable.
- `--` terminates SAFA options before remote argument vectors.

## Command surface

```text
safa version --json
safa doctor --json
safa setup status --json

safa resource list|ls --json [--state active]
safa resource show ALIAS --json
safa resource inspect ALIAS --json

safa exec ALIAS --json \
  --intent TEXT [--expected-effect TEXT] [--rollback TEXT] \
  [--timeout SECONDS] [--output-limit BYTES] -- ARG...
```

This is the complete command surface of the diagnostic preview. Registration/update, shell, sudo,
request, grant, approval, and audit commands are not advertised until their broker workflows exist.
Endpoint, username, password, sudo password, private key, host-key approval, and recovery material
have no Agent-facing flags.

## Response envelope

Every JSON invocation emits exactly one JSON object on stdout. Diagnostics that cannot be represented
in the envelope may be written to stderr only after redaction.

```json
{
  "schema": "dev.safa.cli/v1",
  "command": "exec",
  "status": "completed",
  "request_id": "018f0000-0000-7000-8000-000000000001",
  "timestamp": "2026-08-16T09:30:00Z",
  "data": {},
  "warnings": [],
  "next_action": null
}
```

### Status values

| Status | Meaning |
|---|---|
| `completed` | Requested lifecycle completed; inspect result for remote exit |
| `accepted` | Request created and still evaluating |
| `approval_required` | Trusted human approval is pending |
| `user_action_required` | Private setup or repair is required outside Agent input |
| `denied` | Policy or user denied the request |
| `cancelled` | Caller or user cancelled |
| `expired` | Request or grant expired |
| `failed` | Runtime, vault, transport, integrity, or execution failure |

## Exit codes

The actual remote exit code is always retained in `data.execution.remote_exit_code`; it is not
overloaded as the SAFA process exit code.

| Exit | Meaning |
|---:|---|
| 0 | Completed successfully and remote exit was zero, or non-execution query succeeded |
| 10 | Remote command completed with nonzero exit or signal |
| 20 | Accepted/pending |
| 21 | Approval required |
| 22 | Private user action required |
| 30 | Denied |
| 31 | Cancelled |
| 32 | Expired/revoked |
| 40 | Invalid invocation or contract version |
| 41 | Resource/request/grant not found |
| 42 | Vault locked or unavailable |
| 43 | Policy/integrity/host-identity failure |
| 44 | Transport failure or timeout before remote execution |
| 45 | Runtime/package/platform failure |
| 70 | Unexpected internal failure |

## Resource list response

```json
{
  "schema": "dev.safa.cli/v1",
  "command": "resource.list",
  "status": "completed",
  "timestamp": "2026-08-16T09:30:00Z",
  "data": {
    "resources": [
      {
        "alias": "nas.home",
        "display_name": null,
        "resource_type": "host.nas",
        "state": "active",
        "capabilities": ["exec"],
        "health": "ready",
        "metadata": {
          "host.os.family": "truenas",
          "host.docker.available": false
        }
      }
    ],
    "next_cursor": null
  },
  "warnings": [],
  "next_action": null
}
```

`resource list` and `resource show` never include host, port, username, alternate alias, jump route,
Keychain locator, host fingerprint, or credential identifier. Unknown metadata keys remain private.

`resource inspect ALIAS` is an explicit protected read. It triggers a macOS-owned Touch ID/login
prompt and, only after approval, may return non-secret endpoint and inventory details. A denial or
rate-limit response contains no resource detail object. Inspect never returns a password, token,
private/public key, host fingerprint, credential identifier, or Keychain locator.

## Reserved approval-required response

The schema reserves this response for the M2 authorization phase; the current command surface does
not expose an Agent-callable approval operation.

```json
{
  "schema": "dev.safa.cli/v1",
  "command": "exec",
  "status": "approval_required",
  "request_id": "018f0000-0000-7000-8000-000000000002",
  "timestamp": "2026-08-16T09:30:00Z",
  "data": {
    "resource": "nas.home",
    "risk": {
      "level": "high",
      "finding_codes": ["sudo", "state-changing-service-action"]
    },
    "approval": {
      "state": "pending",
      "trusted_ui_presented": true
    }
  },
  "warnings": [],
  "next_action": {
    "kind": "wait",
    "command": ["safa", "request", "wait", "018f0000-0000-7000-8000-000000000002", "--json"],
    "safe_for_agent": true
  }
}
```

The envelope never includes an approval token or an Agent-callable approval command.

## Completed execution response

```json
{
  "schema": "dev.safa.cli/v1",
  "command": "exec",
  "status": "completed",
  "request_id": "018f0000-0000-7000-8000-000000000002",
  "timestamp": "2026-08-16T09:30:04Z",
  "data": {
    "resource": "nas.home",
    "execution": {
      "termination": "exit",
      "remote_exit_code": 0,
      "duration_ms": 932,
      "stdout": {
        "text": "active\n",
        "encoding": "utf-8",
        "captured_bytes": 7,
        "truncated": false
      },
      "stderr": {
        "text": "",
        "encoding": "utf-8",
        "captured_bytes": 0,
        "truncated": false
      },
      "redaction_count": 0
    }
  },
  "warnings": [],
  "next_action": null
}
```

## Error contract

Failures put a stable object in `data.error`:

```json
{
  "code": "host_identity_changed",
  "message": "The saved identity for this resource no longer matches.",
  "retryable": false,
  "details": {"resource": "nas.home"},
  "remediation": {
    "kind": "complete_local_setup",
    "command": []
  }
}
```

Error details MUST be allowlisted per error code and MUST NOT contain nested process errors, endpoints,
prompts, command environments, raw Keychain statuses, or remote banners without redaction.

## Compatibility

- Additive optional fields are backward compatible within v1.
- Changing meaning, required fields, status values, or command semantics requires v2.
- Skill packages declare the minimum and maximum CLI schema they understand.
- An incompatible Skill/runtime pair returns `runtime_incompatible` without remote action.
