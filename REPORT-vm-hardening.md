# First-pass VM hardening report (superseded)

This report describes the first VM-hardening pass and is retained only as
history. It has been superseded by `REPORT-anti-analysis-v2.md`.

The acceptance criteria in the old report are no longer active. In particular,
its exact byte-0 identifying comment requirement was explicitly reversed:
production output now has zero comments and begins with `return` at byte 0.
Its scanner allowlist for that comment, its fixed-checksum description and its
stable frame-field assumptions are obsolete.

Use these current artifacts instead:

- `REPORT-anti-analysis-v2.md` — sections A–G and the second-pass checklist.
- `RUNTIME-ANALYSIS.md` / `RUNTIME-ANALYSIS.json` — restricted-runtime probes.
- `BENCHMARKS-anti-analysis.md` — current size, startup and runtime benchmark.
- `BENCHMARKS-old-vs-improved.md` — frozen baseline vs current engine.
- `tests/builds/manifest.json` — five structurally different builds.

No implementation or verification claims in this historical document should be
used to judge the current engine.
