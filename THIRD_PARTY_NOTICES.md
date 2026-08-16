# Third-Party Notices

SAFA is distributed under the MIT License. The following dependency retains its own license.

## Swift Argument Parser

- Project: `apple/swift-argument-parser`
- Requested package range: `1.8.2 ..< 2.0.0`
- License: Apache License 2.0 with Runtime Library Exception
- Source: <https://github.com/apple/swift-argument-parser>
- License text: <https://github.com/apple/swift-argument-parser/blob/1.8.2/LICENSE.txt>

Binary distributions must reproduce the dependency's copyright and license notices. SAFA's release
assembly and verification tasks must include this notice and the complete upstream license text.

## Rust CLI contract shell

The non-shipping Rust workspace currently uses `serde` and `serde_json`; their exact direct and
transitive versions are pinned in `Platforms/Rust/Cargo.lock`. This scaffold is not included in any
distributed artifact while the publication hold is active.

Before a Rust artifact may be distributed, release automation must generate and bundle the complete
license/copyright notice set for the locked dependency graph. The direct dependencies are licensed
under `MIT OR Apache-2.0`:

- Serde: <https://github.com/serde-rs/serde>
- Serde JSON: <https://github.com/serde-rs/json>
