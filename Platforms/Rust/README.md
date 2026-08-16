# SAFA Rust runtime

This workspace is the non-shipping foundation for future Linux and Windows SAFA runtimes. It exists
to make the platform boundary executable before credential storage, authorization, IPC, or remote
execution code is added.

## Current crates

- `safa-runtime-core` — platform-neutral vocabulary and required security-capability model.
- `safa-platform-linux` — a Linux adapter boundary that currently reports every protected capability
  as unavailable.

There is deliberately no `safa` binary or daemon yet. Adding a half-working executable would make it
too easy to mistake scaffolding for supported access. The CLI and daemon should be introduced only
with imported `dev.safa.cli/v1` conformance fixtures and a real OS credential/peer-identity design.

## Dependency direction

```text
future safa CLI/daemon
        │
        ▼
safa-runtime-core ◄── safa-platform-linux
        ▲
        └──────────── future safa-platform-windows
```

The core must not import a platform adapter. Platform crates implement narrow capabilities without
putting secret values into shared DTOs.

## Validation

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
