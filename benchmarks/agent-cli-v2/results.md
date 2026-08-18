# Agent CLI v2 benchmark results

Run date: 2026-08-18

Tokenizer: `o200k_base` from `niieani/gpt-tokenizer` commit
`9182f2e567355e0a8f81022b6c52bdc688250ac8`.

| Fixture | TOON v2 | Same-semantics compact JSON | Legacy compact JSON v1 | v1 → TOON |
|---|---:|---:|---:|---:|
| execution-truncated.failed | 179 | 165 | 153 | -17.0% |
| home.completed | 110 | 107 | 174 | 36.8% |
| policy-denied.failed | 68 | 67 | 86 | 20.9% |
| protected-user-action.required | 86 | 85 | 74 | -16.2% |
| resource-list.empty | 40 | 37 | 58 | 31.0% |
| setup.no-op | 24 | 26 | 57 | 57.9% |
| topology-path.completed | 156 | 152 | 206 | 24.3% |
| transport.failed | 66 | 64 | 81 | 18.5% |
| usage-error.failed | 90 | 87 | 83 | -8.4% |
| **Total** | **819** | **790** | **972** | **15.7%** |

Across the nine conformance shapes, the complete AXI migration reduces aggregate legacy-v1 tokens
by 15.7%; the median per-shape change is a 20.9% reduction and six of nine shapes improve. The
richer execution preview, protected local action, and recoverable usage error are larger than their
legacy responses because v2 adds explicit byte counts, content classification, remediation context,
valid flags, and concrete next commands.

TOON by itself is not universally smaller: the same v2 data as compact JSON is 790 tokens, 3.5%
below TOON's 819. The migration's measured reduction comes from content-first roots, fewer calls,
minimal list fields, and omission of ambient null/empty boilerplate—not from assuming a serialization
format wins for every nested shape. TOON remains useful here for declared collection widths,
strict structural validation, and one Agent-facing grammar.

Reproduce locally with:

```bash
node Scripts/benchmark-agent-cli-v2.mjs \
  conformance/toon-v4.1/agent-cli-v2 \
  benchmarks/agent-cli-v2/compact-json-v1 \
  /path/to/pinned-gpt-tokenizer/data/o200k_base.tiktoken
```

This deterministic token baseline isolates payload size; the separate direct-model evidence follows.

## Direct Agent-model results

The same six questions were run on 2026-08-18 through the signed Codex CLI bundled with ChatGPT
(`codex-cli 0.148.0-alpha.9`). Each format/task pair used a new ephemeral session, a read-only empty
working directory, ignored user/project configuration and rules, and explicitly prohibited tool
calls. The JSONL event stream contained no command, MCP, web, file-change, or other tool item. The
model received only the synthetic payload, the question, and the required answer keys.
Answers were scored by strict deep equality with `tasks.json`; every invocation completed in one
turn.

| Model | Format | Passed | Rate | Turns | Wall time | Mean latency | Input tokens | Cached input | Output tokens | Reasoning tokens |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `gpt-5.4` | TOON v2 | 6/6 | 100.0% | 6 | 39,252 ms | 6,542 ms | 105,158 | 78,080 | 685 | 551 |
| `gpt-5.4` | JSON v1 | 3/6 | 50.0% | 6 | 40,076 ms | 6,679 ms | 105,285 | 87,296 | 682 | 554 |
| `gpt-5.4-mini` | TOON v2 | 4/6 | 66.7% | 6 | 49,052 ms | 8,175 ms | 103,046 | 63,744 | 1,161 | 1,027 |
| `gpt-5.4-mini` | JSON v1 | 2/6 | 33.3% | 6 | 42,668 ms | 7,111 ms | 103,173 | 76,032 | 1,093 | 963 |

| Task | `gpt-5.4` TOON | `gpt-5.4` JSON | `gpt-5.4-mini` TOON | `gpt-5.4-mini` JSON |
|---|:---:|:---:|:---:|:---:|
| Home readiness and alias | pass | pass | pass | pass |
| Definitive empty resource list | pass | fail | pass | fail |
| Idempotent setup | pass | fail | fail | fail |
| Recover usage error | pass | fail | pass | fail |
| Hostile truncated execution | pass | pass | fail | fail |
| Verified topology path | pass | pass | pass | pass |

TOON v2 regressed on zero tasks that JSON v1 completed. The smaller model still failed strict
scoring for two v2 tasks: it paraphrased `no_op` as `already complete`, and incorrectly classified
the text nested in stdout as a control instruction. Those failures remain visible evidence that the
Skill's remote-output rule and typed status consumption are necessary; this benchmark does not
claim that serialization alone makes a weaker Agent reliable.

The model-reported input totals include the Codex Agent system/tool context and provider caching, so
they are not a clean serialization-size measurement. The pinned `o200k_base` fixture counts above
remain the relevant Agent-visible payload comparison. The direct runs establish the separate
completion, single-turn, and latency evidence required by T107/SC-024.
