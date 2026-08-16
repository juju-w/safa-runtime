# Runtime platforms

The production-shaped Swift macOS runtime remains at the repository root (`Package.swift`,
`Sources/`, `Apps/`, and `Tests/`). Moving those paths during the cross-platform boundary change
would create a large, low-value diff and disturb Xcode, SwiftPM, Spec Kit, and signing paths.

`Rust/` is a separate Cargo workspace for the future shared CLI and Linux/Windows runtimes. It
contains a non-shipping CLI contract shell, a platform-neutral core, and a Linux adapter that
explicitly reports every protected capability as unavailable. This does not provide a distributable
Runtime, Broker, credential fallback, remote operation, or platform-support claim.

Both runtime families implement contracts owned by [`juju-w/safa`](https://github.com/juju-w/safa).
