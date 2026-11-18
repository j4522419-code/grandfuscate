# Second-pass anti-analysis plan

This document supersedes the earlier plan. The old exact byte-0 identifying
comment requirement is reversed: production output must have zero comments and
start with `return` at byte 0.

## Motivation

A restricted Lua runtime executed the previous generated VM and recovered
`print(67)` from a startup dump. The old build also exposed a brand header,
fixed checksum constants, stable frame fields and a largely predictable router.
The second pass targets those specific shortcuts without claiming that a
client-side script can be made unrecoverable.

## Scope decisions

- Keep one VM runtime, one-line output, three presets, zero top-level locals and
  no dynamic loader.
- Remove the identifying comment entirely; do not replace it with another
  allowlisted marker.
- Do not silently skip unsupported Luau syntax. Raise `vm.Unsupported` or use a
  documented strongest-compatible fallback; the chosen implementation raises
  `vm.Unsupported`. Type-only declarations are explicit runtime no-ops in the
  private compile notes.
- Do not reintroduce nested VMs, anti-environment poisoning, anti-tamper
  poisoning, multi-megabyte blobs, old sliders, old hardening controls or fixed
  library chains.
- Keep official-Luau behavioural verification and mocked Roblox/executor
  compatibility fixtures.
- Keep deployment local-only: no remote, push, GitHub repo or Render service.

## 15 numbered requirements

1. Lazy/chunked payload storage for constant-pool slices and VM fragments.
2. Per-build structural layout randomization.
3. Per-build field-key randomization.
4. Remove stable router signatures.
5. Remove stable field signatures.
6. Remove fixed FNV/checksum signatures.
7. Remove stable format wording signatures.
8. Remove fixed library-chain signatures.
9. Make `vm.Unsupported` explicit; no silent source-mode fallback.
10. Preserve behaviour and syntax compatibility with official Luau.
11. Verify `print(67)` and complex fixtures.
12. Add a restricted runtime-analysis test.
13. Generate five structurally different randomized builds with identical
    behaviour.
14. Benchmark the old frozen engine vs the improved engine.
15. Verify scanner, private source map, full suite, report A–G and refreshed
    docs/examples/reports.

## Implementation map

- **A–B:** `obf/layout.py`, `obf/fields.py`, `obf/chunks.py`, `obf/checksum.py`.
- **C–D:** `obf/runtime.py`, `obf/vm/runtime.py`, `obf/vm/fragments.py`,
  `obf/vm/nodes.py`, `obf/format.py`, `obf/pipeline.py`.
- **E–F:** `tests/return_probe.py`, `tests/runtime_analysis.py`,
  `tests/build_diversity.py`, `tests/compare_versions.py`,
  `tests/anti_analysis.py`, `tests/run_tests.py`.
- **G:** `README.md`, `ARCHITECTURE.md`, `ROADMAP.md`, `NEXT_STEPS.md`,
  `DEPLOY.md`, `config/README.md`, `REPORT-anti-analysis-v2.md`, regenerated
  `examples/`, `BENCHMARKS-anti-analysis.md`,
  `BENCHMARKS-old-vs-improved.md`, `RUNTIME-ANALYSIS.md`.

## Acceptance criteria

- `output.startswith(b"return")`, `comments == 0`, one trailing newline, zero
  top-level locals, no `loadstring` / `load(` / `require(`.
- `tests/anti_analysis.scan_output()` returns no findings on production chunks.
- Public keys contain only a SHA-256 of the private source map; detailed
  layout/operand/control-flow objects stay private.
- `print(67)` preserves stdout, exit status and top-level return values.
- Complex fixtures preserve stdout, stderr and exit status on all presets.
- Runtime-analysis probes recover no source needles from startup or simple dumps.
- Five builds differ in output hash, token prefix, opcode map, payload digest,
  layout IDs and structural features while behaving identically.
- Old-vs-improved benchmark shows the old startup dump recovering source needles
  and the new build recovering none.
- Full suite prints `ALL GREEN` with zero failures.

## Non-goals

No claim of 100% decompile-proof protection, proven commercial superiority or
real security for client-side Roblox scripts. A capable executor-specific
debugger can still observe runtime values. Server-side authority remains the
security boundary.


## Third-pass extension (active)

The second-pass plan remains the foundation. A later restricted-runtime audit
showed that a scanner-clean `print("Hello World!")` build was still recoverable
through a stable central decoder/dispatcher shape. The third pass adds:

1. Per-build VM profiles, bank/group coefficients, handler groups and a private
   structural digest.
2. Ticketed group matrices for constants, pool bytes, VM bytes, words, nodes,
   `eval` and `exec`; no central `D(i)`, `W(i)`, `NODE`, `EVAL`, `EXEC` or `DEC`.
3. Deliberate spread of source constants across pool slices, banks, constant
   groups and byte groups; chained call-site tickets rather than stable keys.
4. Per-node operand permutations, opaque NOPs, nested blocks and branch
   inversion without changing evaluation order.
5. Scanner, runtime-analysis, five-build diversity, differential, benchmark and
   exact Hello World production-output checks. See `REPORT-anti-analysis-v3.md`.

Client-side scripts remain recoverable to a capable debugger. Runtime hooks on
`print` or ordinary library calls are unavoidable; this pass removes the clean
IR and single obvious central decoder shortcut, not runtime observability.
