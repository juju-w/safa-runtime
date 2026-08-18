# Agent CLI v2 benchmark inputs

The `compact-json-v1` files preserve the shapes emitted by SAFA's unpublished JSON v1 preview for
equivalent synthetic tasks. They are benchmark evidence only, not compatibility fixtures or a
supported output mode. `home.completed.json` contains the two v1 calls (`doctor` plus
`resource.list`) replaced by the v2 content-first home response.

`Scripts/benchmark-agent-cli-v2.mjs` reports both comparisons:

- TOON v2 versus the same v2 data serialized as compact JSON, isolating encoding overhead;
- the complete AXI v2 response versus legacy compact JSON v1, measuring the migration's field and
  turn reduction together.

Token counts use `o200k_base` data from `niieani/gpt-tokenizer` pinned in CI. They do not by
themselves prove task completion, turn count, or latency. `tasks.json` is the deterministic
question/answer corpus; `results.md` records both the tokenizer baseline and the completed direct
`gpt-5.4`/`gpt-5.4-mini` Agent runs required by T107 and SC-024.

Run the real-model task corpus manually with an authenticated Codex CLI; this command uses an
ephemeral session, a read-only empty working directory, ignores user/project configuration and
rules, and instructs the model not to call tools:

```bash
node Scripts/run-agent-cli-v2-eval.mjs \
  /path/to/codex MODEL \
  conformance/toon-v4.1/agent-cli-v2 \
  benchmarks/agent-cli-v2/compact-json-v1 \
  benchmarks/agent-cli-v2/tasks.json
```

The runner prints progress to stderr and one synthetic, credential-free JSON result document to
stdout. It exits nonzero if TOON v2 completes fewer tasks than JSON v1. Do not place an authenticated
model run in public CI or persist provider/session credentials with the benchmark results.
