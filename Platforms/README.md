# Runtime platforms

The production-shaped Swift macOS runtime remains at the repository root (`Package.swift`,
`Sources/`, `Apps/`, and `Tests/`). Moving those paths during the cross-platform boundary change
would create a large, low-value diff and disturb Xcode, SwiftPM, Spec Kit, and signing paths.

`Rust/` is a separate Cargo workspace for the future Linux and Windows runtimes. It begins with a
small platform-neutral core and an explicit Linux adapter boundary. It intentionally contains no
distributable CLI, broker, credential fallback, or support claim.

Both runtime families implement contracts owned by [`juju-w/safa`](https://github.com/juju-w/safa).
