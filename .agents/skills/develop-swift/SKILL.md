---
name: develop-swift
description: Develop and review production Swift 6 code with strict concurrency, Swift Package Manager boundaries, typed APIs, and Swift Testing. Use for changes to .swift files, Package.swift, Swift modules, actors or Sendable code, Codable contracts, subprocess/runtime adapters, tests, refactors, and code-quality reviews in this repository.
---

# Develop Swift

Produce small, readable Swift changes that preserve SAFA's trust boundaries. Treat compilation as
the first check, not the definition of correctness.

## Establish context

Before editing:

1. Read `AGENTS.md`, `ARCHITECTURE.md`, and the relevant feature spec.
2. Inspect `Package.swift` and the touched target's dependency direction.
3. Read the complete type and its tests; do not infer behavior from one call site.
4. Check the working tree and preserve unrelated changes.
5. State which module owns the behavior before adding a type or dependency.

If the requested behavior conflicts with a trust boundary, stop that implementation path and
explain the conflict. Do not weaken an invariant to make a test or demo pass.

## Design the change

- Prefer a value type and pure function for validation, classification, canonicalization, and state
  transitions.
- Put I/O behind a narrow protocol and inject the implementation, clock, or process runner.
- Keep parsing, domain decisions, platform adapters, and presentation separate.
- Use one primary type per file. Split a file near 300 lines unless its cohesion is explicit.
- Add a target dependency only when the architecture permits that direction.
- Use explicit versioned request and response DTOs at CLI/XPC boundaries. Define `CodingKeys`; do not
  expose persistence models or add dynamic `[String: JSONValue]` payloads.
- Model expected failures with precise error types and stable boundary error codes. Avoid
  `fatalError`, force unwraps, `try!`, and catch-all success fallbacks.
- Prefer direct, unsurprising names. Avoid `Manager`, `Helper`, `Utils`, and generic dictionaries
  when a domain name or type exists.

## Apply Swift 6 concurrency rules

- Preserve Swift 6 language mode and strict concurrency.
- Make immutable value types `Sendable` when they cross tasks or actors.
- Isolate shared mutable state in an actor or a visibly synchronized adapter.
- Use `@unchecked Sendable` only for a small Foundation, Security, XPC, or process bridge whose
  synchronization is reviewable in the same file.
- Prefer structured concurrency. Use `Task.detached` only when actor inheritance would be wrong and
  document ownership, cancellation, and lifetime.
- Propagate cancellation and deadlines through subprocess and XPC boundaries.
- Never block an actor executor with process waits, pipe reads, semaphores, or file I/O.
- Ensure continuations resume exactly once on success, failure, cancellation, and invalidation.

## Test before implementation

For security-sensitive behavior, add the failing test first.

- Put pure invariants and policy cases in `Tests/Unit`.
- Put stable CLI/XPC encoding and exit behavior in `Tests/Contract`.
- Put composition and adapter journeys in `Tests/Integration`.
- Put trust-boundary, tamper, secret-exposure, and fail-closed cases in `Tests/Security`.
- Use synthetic resources only. Tests must not contact real infrastructure or read real Keychain
  items.
- Test invalid inputs and cancellation, not only the happy path.
- Prefer deterministic fakes over sleeps. When time is the subject, inject a clock where practical.

## Keep APIs readable

- Prefer labeled initializers and small methods with one reason to change.
- Keep public surface area minimal; default to internal visibility.
- Use extensions only to group a real conformance or cohesive capability.
- Keep comments focused on invariants, platform quirks, and security rationale. Do not narrate the
  syntax.
- Do not hide side effects behind computed properties or innocent names.
- Make resource ownership explicit for file handles, pipes, tasks, XPC connections, and temporary
  files; close or invalidate them on every path.

## Validate the slice

Run the narrow test while iterating, then the repository gates:

```bash
xcrun swift-format lint --recursive --strict Sources Tests Apps/SAFA/Targets Package.swift
swift test --parallel
swift build -c release
xcodebuild -quiet -project Apps/SAFA/SAFA.xcodeproj -scheme "SAFA Runtime" \
  -configuration Debug CODE_SIGNING_ALLOWED=NO build
```

Inspect the final diff for accidental public API, new dependencies, dynamic wire payloads, real
infrastructure data, and unbounded output. Follow the repository PR workflow and never publish a
tag, Release, signed artifact, or Skill package while the publication hold is active.
