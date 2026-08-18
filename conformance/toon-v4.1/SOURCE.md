# TOON 4.1 fixture provenance

SAFA's Agent CLI v2 encoder targets the TOON 4.1 Working Draft at this exact upstream revision:

- repository: <https://github.com/toon-format/spec>
- commit: `62f16b369408180f1faf1cba7da1b46d1f336f12`
- specification version: `4.1`
- specification date: `2026-07-26`
- license: MIT

The upstream fixture corpus remains the normative cross-implementation input. SAFA keeps only
product-specific golden outputs in its Swift contract tests so the repository does not silently
fork the format or copy fixtures without provenance. CI must fetch or cache the exact commit above,
strict-decode SAFA's canonical outputs with the pinned reference implementation, and fail when the
decoded JSON model differs.

Updating this pin requires a reviewed diff of the upstream specification and fixtures, refreshed
goldens, and a compatibility decision for `dev.safa.cli/v2`.
