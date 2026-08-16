# SAFA Rust runtime

This workspace is the non-shipping foundation for a shared SAFA CLI and future Linux and Windows
runtimes. It makes the public contract and platform boundary executable before credential storage,
authorization, IPC, or remote execution code is added.

## Current crates

- `safa-cli` — a minimal Agent-facing parser/presenter implementing local `version`, fail-closed
  `doctor`, stable v1 JSON envelopes, and stable local exit codes.
- `safa-runtime-core` — platform-neutral vocabulary and required security-capability model.
- `safa-platform-linux` — a Linux adapter boundary that currently reports every protected capability
  as unavailable.

The `safa` binary is deliberately not packaged or advertised as a Runtime. `resource`, `exec`, and
every protected operation remain unavailable until a reviewed native Broker client exists. The
working Swift CLI remains the macOS product implementation during this migration.

## Dependency direction

```text
safa-cli ─────────────► safa-runtime-core ◄── safa-platform-linux
                                ▲
                                └──────────── future safa-platform-windows
```

The CLI parses and presents; it has no vault authority or transport fallback. The core must not
import a platform adapter. Platform crates implement narrow capabilities without putting secret
values into shared DTOs.

## Contract provenance

The repository-root `conformance/` directory is a pinned snapshot of fixtures whose canonical
source is `juju-w/safa`. The source commit is recorded in `conformance/SOURCE.md`. Swift and Rust
tests consume the same snapshot; Runtime code may not redefine it independently.

## Validation

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
