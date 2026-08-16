# Resource Directory v1

The resource directory is SAFA's encrypted, transport-independent inventory. A resource is selected
by logical alias; an adapter later decides which operations are implemented for its type and access
method. Registering a type does not grant access and does not claim its adapter exists.

## Core record

| Field | Visibility | Notes |
|---|---|---|
| canonical alias | public | Lowercase logical name; globally unique in one vault |
| alternate aliases | authorized | Share the canonical alias collision namespace |
| resource type | public | Validated open identifier, for example `database.mysql` |
| display name | authorized | Encrypted; may contain internal context |
| access methods | authorized | Open identifiers; do not imply adapter availability |
| endpoint/user/route | authorized | Encrypted connection metadata |
| typed metadata | allowlist/authorized | Unknown keys always default private |
| relationships | authorized | Returned with target aliases, never raw resource IDs |
| credential bindings | broker only | Opaque IDs only; never in Agent DTOs |
| credential values/locators | Keychain/broker only | Never resource metadata |

## Initial identifiers

Resource types:

```text
host.linux
host.macos
host.nas
database.mysql
database.postgresql
object-storage.s3
cache.redis
service.http
```

Access methods:

```text
ssh
database.mysql
database.postgresql
object-storage.s3
cache.redis
http
```

Credential kinds may be extended independently, including `database.password`,
`object-storage.access-key`, and `service.api-token`. Values remain separate Keychain or Secure
Enclave objects.

## Typed metadata

Each entry has a validated namespaced key, one tagged value, and an optional observation timestamp.
Supported values are `text`, `integer`, `boolean`, `byte_count`, and `text_list`. Arbitrary JSON and
embedded secrets are rejected by design.

Initial host profile keys:

| Key | Value | Default visibility |
|---|---|---|
| `host.os.family` | text | public summary |
| `host.os.version` | text | authorized |
| `host.kernel.release` | text | authorized |
| `host.cpu.model` | text | authorized |
| `host.cpu.logical-count` | integer | authorized |
| `host.memory.total-bytes` | byte count | authorized |
| `host.storage.total-bytes` | byte count | authorized |
| `host.storage.available-bytes` | byte count | authorized |
| `host.docker.available` | boolean | public summary |
| `host.docker.version` | text | authorized |

Initial profile-summary keys also include `database.engine`, `object-storage.provider`,
`cache.engine`, and `service.protocol`. The allowlist lives in trusted source code. An imported
configuration cannot mark an arbitrary field public.

## Query contract

The Agent XPC surface uses the explicit `ResourceDirectoryRequestV1` and
`ResourceDirectoryReplyV1` DTOs instead of the legacy dynamic broker map.

- `list`: safe summaries, optionally filtered by lifecycle state; never prompts.
- `show`: one safe summary by canonical or alternate alias; never prompts.
- `inspect`: resolves the canonical resource, rate-limits prompts, and asks macOS for device-owner
  authentication. Only an approved request receives `ResourceDetailsV1`.

Denied, rate-limited, malformed, and unknown-resource replies contain no protected detail object.
No resource-directory reply includes a credential ID, Keychain locator, password, token, access
key, host fingerprint, or private/public key material.

## Future adapters

Database, object-storage, cache, and service adapters must add typed operations and policies at the
broker boundary. They reuse resource aliases and credential bindings but must not interpret metadata
as executable instructions. Least-privilege accounts remain separate resources or credential roles;
one generic credential must not become a cross-service superuser.
