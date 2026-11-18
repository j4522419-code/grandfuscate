# Second-pass anti-analysis report

Status: **verified**. The final full suite printed `ALL GREEN` with zero
failures; numbers are recorded below. This report supersedes
`REPORT-vm-hardening.md`. It is a local engineering report, not a red-team or
commercial-obfuscator evaluation.

## A. Scope, decision and threat model

The motivating failure was a restricted Lua runtime that executed the previous
generated VM and recovered `print(67)` from a startup dump. The user chose to
remove the old identifying byte-0 comment entirely. Current production output
has zero comments, starts with `return` at byte 0, has one trailing newline,
zero top-level locals and no dynamic loader.

The threat model is a restricted instrumented environment that can interpose
global libraries, hook `string.char` / `table.concat`, inspect simple dumps and
look for a single dispatcher. A capable executor-specific debugger can observe
more. No 100% decompile-proof protection, proven commercial superiority or real
security for client-side Roblox scripts is claimed; server-side authority
remains the caveat.

Deployment stays local-only: no Git remote, no push, no GitHub repository and no
Render service.

## B. Lazy/chunked payload storage and structural randomization

`obf/chunks.py` creates per-build lazy chunk plans for every constant-pool slice
blob/key and every VM stream fragment blob/key. Each plan uses randomized chunk
sizes, randomized numeric closure keys, shuffled assignment order and one of two
assembly styles. The original payload is assembled only on first use.

`obf/layout.py` chooses per-seed node style (`sparse`, `nested`, `cursor`),
dispatch style (`direct`, `split`, `bucket`), router style (`direct`, `split`,
`chain`), chunk assembly, chunk strategy, randomized dispatch slot bases and
randomized constant-byte rotation. `obf/fields.py` rewrites private frame and
record fields to randomized numeric keys; direct handler tables no longer use
small 1..N keys. Public metadata exposes opaque numeric entry/boot layout IDs.

`obf/checksum.py` replaces the fixed FNV seed/prime pair with randomized rolling
coefficients. `tests/anti_analysis.py` rejects the old fixed constants, stable
`.n` / `.V` / `.proto`-style fields, fixed library chains, semantic names and
private-map markers in production bytes.

## C. Startup-dump and signature removal

Constants are decoded byte-by-byte in a rotated reverse order and restored with
`..`. A simple `string.char` or `table.concat` hook sees reversed individual
bytes or encoded chunk literals, not contiguous source text. Interpolated
strings are also assembled with `..` instead of one hooked `table.concat`.

The router is distributed across per-slice and per-fragment handler tables with
thin lookup routers. There is no central `if op == ...` chain, no sequential
small opcode table, no fixed `D(i)` decoder and no stable format/boot wording in
public keys. `obf/format.py` replaces semantic shape and boot names with opaque
ID values; `obf/web.py` exposes numeric layout lists.

## D. Explicit unsupported syntax and compatibility

`obf/vm/compiler.py` raises `vm.Unsupported` for IR constructs it cannot safely
represent. `pipeline.obfuscate()` no longer catches it and silently falls back
to source mode. Type-only declarations are recorded as explicit runtime no-ops
in the private compile notes rather than disappearing silently.

Verification uses official Luau 0.747 for parsing, compile-only checks and
behaviour. `tests/return_probe.py` captures stdout plus top-level return values.
`tests/cases/print67.luau` and `tests/cases/semantics_matrix.luau` cover
`print(67)`, multiple returns, errors, closures, upvalues, globals, varargs,
nil, tables, metatables, callbacks, self-calls, nested functions, loops,
coroutines and yielding. Compatibility fixtures also cover executor-like `_G`,
advanced Luau semantics and mocked Roblox APIs.

## E. Runtime-analysis probe and five-build diversity

`tests/runtime_analysis.py` executes two instrumented probes:
`tests/scan_fixture.luau` and `print(67)`. It tries to identify an instruction
table, a main dispatcher, startup constants, one decode function, one execute
function and a clean IR. Current result: both probes succeed. The `scan_fixture` probe used 10 source
needles and the `print(67)` probe used 3; both had 0 startup hits and 0 simple
dump hits. The primary probe saw 12 distinct encoded blobs and 9,557 byte reads
before/around startup, 0 small handler groups, no central numeric dispatcher,
no fixed checksum constants, 0 global dispatcher candidates and no clean IR
reconstruction. Full counts are in `RUNTIME-ANALYSIS.md` and
`RUNTIME-ANALYSIS.json`.

`tests/build_diversity.py` generates five medium builds with different structural
features but identical behaviour. The current manifest is
`tests/builds/manifest.json` with seeds `[1, 74, 22, 33, 3]`; per-build hashes,
chunk plans and token prefixes are recorded there.
Diversity covers all three node/dispatch/router styles, both chunk assemblies,
all three operand modes, both word orders, both stream orders, five opcode maps,
five payload digests, five token prefixes, four entry layouts, four boot layouts,
five slot bases, both constant spans and five constant biases.

## F. Old-vs-improved benchmark, scanner, private map and suite

`tests/compare_versions.py` builds the frozen pre-change engine from
`tests/baseline/` in a separate Python process. On the `print(67)` probe, the
old startup dump recovered 2 source needles and the new build recovered 0. The
old output had one identifying comment, fixed checksum constants and seven
stable frame-field names; the new output had zero of each. Both old and new
preserve original behaviour.

`BENCHMARKS-old-vs-improved.md` records sizes, startup, RSS and 5,000-loop
runtime. The old heavy workload median overhead was 168.5x and the new one was
182.9x; the current standalone heavy benchmark in
`BENCHMARKS-anti-analysis.md` measured 173.9x. Tree-walker execution dominates;
these are local wall-clock/RSS measurements, not security scores.

The production scanner is token-aware, so `--` inside escaped encoded bytes is
not mistaken for a comment. Private-source-map verification checks the marker,
nodes, constants, opaque layout IDs, runtime layout, field keys, chunk plans,
control-flow/compile notes, operand layout and absence of the map, marker or
detailed layout objects from production output/public keys.

Full-suite status: `python3 -m obf.cli --self-test` printed `ALL GREEN` with
**78 base transform/run + 26 VM-mode transform/run + 12 compatibility
differential + 12 production scans + 6 return probes + 6 complex checks + 16
reliability + 8 second-pass checks, 0 failure(s)**. The run also regenerated
the scanner sample, private-map checks, runtime-analysis artifacts, five-build
manifest, current benchmark and old-vs-improved benchmark.

## G. Refreshed deliverables, limitations and next state

Refreshed deliverables include this report, `README.md`, `ARCHITECTURE.md`,
`ROADMAP.md`, `NEXT_STEPS.md`, `PLAN-anti-deobfuscation.md`, `DEPLOY.md`,
`config/README.md`, three regenerated `examples/protected_*.luau` files with
matching keys, `BENCHMARKS-anti-analysis.md`,
`BENCHMARKS-old-vs-improved.md`, `RUNTIME-ANALYSIS.md`,
`RUNTIME-ANALYSIS.json`, `tests/builds/manifest.json` and five example build
files. `REPORT-vm-hardening.md` and `BENCHMARKS-hardening.md` are marked
superseded.

The 15 numbered requirements from the plan are all implemented and covered by
A–F. Current examples with seed `20261118` are 47,784 / 78,398 / 465,489 bytes
and each prints `grandfuscate\t15` under official Luau. The local web preview
was restarted on the current code: `/api/health` returned 200, `/api/meta`
exposed numeric entry/boot layouts, and `light`/`medium`/`heavy` obfuscation
smokes printed `live\t42` with zero comments and zero scanner findings.

Known limitations: side-effecting lvalue expressions can differ in evaluation
order; `getfenv` virtualization assumes no runtime `setfenv` swap; official Luau
is not a live Roblox executor; a full Lua debug API or executor hooks can still
recover behaviour. No red-team benchmark against real deobfuscators was run.
Deployment remains paused and local-only.

---

Final verification: `ALL GREEN`, 0 failures. No push or deployment performed.
