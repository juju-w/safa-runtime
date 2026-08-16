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
Supported values are `text`, `integer`, `boolean`, `byte_count`, and `text_list`. Arbitrary JSON,
credentials, and recognized encoded key material are rejected before persistence. Public summary
fields require an exact
source-reviewed key, type, and value. Other non-secret typed extension fields remain private until
an authorized inspect and must pass bounded value/content checks. The `ssh.*` namespace is reserved
for dedicated connection and identity fields. Complete sensitive key components and recognized
compounds for credentials, fingerprints, keys, Keychain locators, passwords, tokens, PEM,
certificates, passcodes/PINs, passphrases, JWK/JWKS, and locators are rejected without treating benign components
such as `keyboard` as key material. Authorization/header and connection-string/DSN keys are reserved;
recognizable Basic or Bearer credentials, URI userinfo, and JSON documents are rejected while
ordinary credential-free URLs and prose using words such as `bearer` remain usable. Content checks
cover scalar text, individual text-list
items, and both spaced and unspaced
combined list representations. They match complete sensitive terms plus explicit private-key formats
or section markers, including supported and legacy OpenSSH algorithm/payload pairs, decoded OpenSSH
wire public-key blobs, split OpenSSH
keys, compact JWT/JWS/JWE credentials, unarmored DER PKCS#8/PKCS#1/SEC1 private keys, encrypted
PKCS#8 blobs, password- or public-key-integrity PKCS#12/PFX containers, DER X.509 certificates,
standalone DER SubjectPublicKeyInfo and PKCS#1 RSA public-key blobs, standard or
URL-safe whitespace-grouped Base64 key material, and PuTTY PPK text lists, without rejecting benign operational
phrases such as `uncertain` or `ssh-service running`. Existing or corrupted records that violate the same rules
remain encrypted but are filtered from Agent-visible projections.
Encrypted PKCS#8 classification requires a recognized PKCS#5 or PKCS#12 password-based encryption
OID, so structurally similar DER values such as artifact `DigestInfo` checksums remain valid metadata.
Encoded-material scanning is capped at 64 whitespace fragments per checked representation; more
fragmented values fail closed before any reassembly work.

Format recognition is defense in depth, not an exhaustive parser for every cryptographic container.
Credentials and private keys must use dedicated credential/identity bindings regardless of their
encoding. Additional public-only containers are added only when a concrete product risk justifies
their implementation and maintenance cost; PKCS#7 certificate bundles and PKCS#10 certificate
requests are deferred from this contract.

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
configuration cannot mark an arbitrary field public. Text summary values are closed, reviewed
identifiers; adding a new public value requires a code and test change.

## Relationship lifecycle

A live relationship must target a distinct live resource. Removing a resource with an incoming
relationship is rejected with the referencing alias so a trusted setup flow can first remove or
retarget that dependency. Removal never leaves a live resource pointing at a deleted target and
never silently rewrites another resource's topology.

## Query and mutation contracts

The Agent XPC surface uses separate explicit DTOs instead of the legacy dynamic broker map:
`ResourceDirectoryRequestV1`/`ReplyV1` for queries and
`ResourceMutationRequestV1`/`ReplyV1` for mutations.

- `list`: safe summaries, optionally filtered by lifecycle state; never prompts.
- `show`: one safe summary by canonical or alternate alias; never prompts.
- `inspect`: resolves the canonical resource, rate-limits prompts, and asks macOS for device-owner
  authentication. Only an approved request receives `ResourceDetailsV1`.
- `add` / `edit`: require device-owner authentication and accept only logical aliases and an
  optional supported host type. The broker resolves private connection fields locally;
  imports stay `draft/needs_setup`, trusted resources cannot be silently retargeted, and only
  `host.linux`, `host.macos`, or `host.nas` is accepted by this adapter.
- `setup`: requires device-owner authentication, resolves the same explicit OpenSSH alias, imports
  prior `known_hosts` trust plus an available existing identity-file/agent locator, and runs bounded
  direct-route verification. It commits `active` only when the draft revision remains unchanged.
  `ProxyJump` and `ProxyCommand` routes fail closed pending reviewed route snapshot support.
- `disable` / `remove`: require device-owner authentication and use revisioned broker transactions;
  removal refuses to break a live relationship.

Denied, rate-limited, malformed, and unknown-resource replies contain no protected detail object.
No resource-directory reply includes a credential ID, Keychain locator, password, token, access
key, host fingerprint, or private/public key material.

## Future adapters

Database, object-storage, cache, and service adapters must add typed operations and policies at the
broker boundary. They reuse resource aliases and credential bindings but must not interpret metadata
as executable instructions. Least-privilege accounts remain separate resources or credential roles;
one generic credential must not become a cross-service superuser.
