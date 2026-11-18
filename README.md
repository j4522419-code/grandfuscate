# Grandfuscate

Grandfuscate is a local, AST-based Luau obfuscator. It parses real Luau with the
official `luau-ast` tool, compiles a custom tree-walking VM program, encodes its
constants and instruction stream, and emits one `return`-first Luau chunk.

The third anti-analysis pass is active. Production output has **zero comments**,
begins with `return` at byte 0, contains no identifying brand, ships no top-level
`local` declarations, uses no dynamic loader, and keeps the private source map
out of the chunk.

## Quick start

```bash
python3 -m obf.cli examples/sample.luau \
  --preset medium --seed 20261118 --verify \
  -o protected.luau --keys keys.json
./tools/luau protected.luau
# grandfuscate	15
```

The public API is:

```python
from obf import pipeline
result = pipeline.obfuscate(source_bytes, pipeline.make_options("medium", seed=1))
result.output          # production bytes
result.keys            # public build metadata / provenance
result.stats           # aggregate counters
result.source_map      # private debug map; never embedded in output
```

`result.source_map` is available to library callers, via CLI `--source-map`, or
only when the web API caller explicitly sets `include_source_map: true`. It is
not part of the generated `.luau` file.

## What changed in the second and third passes

- Encoded payloads are split into per-build lazy chunk plans for every constant
  slice and VM stream fragment. Chunk closures use randomized numeric keys and
  are assembled only when needed.
- Constants are reconstructed in a rotated reverse byte order. A simple
  `string.char` / `table.concat` startup hook no longer sees a contiguous source
  string; the VM restores order with concatenation after the hook point.
- The compiler chooses one of several node layouts, dispatch styles, router
  styles, chunk assemblies, operand permutations, word orders and stream orders
  per seed. Frame/record fields become randomized numeric keys, and direct
  handler tables use randomized slot bases.
- Fixed FNV constants, stable `.n` / `.V` / `.proto`-style fields, fixed library
  chains, semantic format names and a single central router are absent from
  production output. Public metadata uses opaque numeric layout IDs.
- Checksums use randomized coefficients. The legacy FNV helper remains only for
  explicit library experiments and is not used by any normal preset.
- Unsupported VM syntax raises `vm.Unsupported`; there is no silent source-mode
  fallback. Type-only declarations are recorded as runtime no-ops in the private
  compile notes.
- `print(67)` plus complex fixtures, a restricted-runtime probe, five
  structurally different builds, old-vs-improved benchmarks, private-map policy,
  production scanner and full suite are part of verification.

Third-pass additions:

- Constants, pool bytes, instruction bytes, words, nodes and dispatch steps use
  per-build ticketed group matrices. There is no central `D(i)`, `W(i)`, `NODE`,
  `EVAL`, `EXEC` or `DEC` router and no stable semantic prefix in production
  output.
- Group functions require chained capability tickets from their call sites;
  source constants are deliberately spread across pool slices, banks, constant
  groups and byte groups. Per-node operand permutations, opaque NOPs and
  randomized VM profiles make five seeded builds structurally distinct.
- The exact `print("Hello World!")` fixture has production outputs and private
  sidecars for `light`, `balanced` and `aggressive`. The A–F report is
  `REPORT-anti-analysis-v3.md`; runtime probe evidence is in
  `RUNTIME-ANALYSIS-V3.md` and `.json`. Runtime hooks on `print` or ordinary
  library calls still see values that the script must use.
- Distributed decoding adds interpreter overhead; the current local
  measurements and the 650x gross-regression sanity ceiling are recorded in
  `BENCHMARKS-anti-analysis.md` and `BENCHMARKS-old-vs-improved.md`.

## Presets

| Preset | Protection level | Pool slices / VM fragments | Padding |
|---|---|---:|---:|
| `light` | `light` | 2 / 2 | 0 B |
| `medium` | `balanced` | 3 / 4 | 4 KiB |
| `heavy` | `aggressive` | 5 / 7 | 64 KiB |

`balanced -> medium`, `aggressive -> heavy` and `max -> heavy` are aliases. The
public website, API and UI expose exactly `light`, `medium` and `heavy`.
`medium` is the default. All normal presets force the VM, one-line output and
safe compatibility: no nested VM, no environment poisoning, no anti-tamper
poisoning and no multi-megabyte blob.

## Verification

```bash
python3 -m obf.cli --self-test
PYTHONPATH=. python3 -c 'from tests import runtime_analysis as r; print(r.run()[0])'
PYTHONPATH=. python3 -c 'from tests import build_diversity as d; print(d.verify()[0])'
PYTHONPATH=. python3 -c 'from tests import compare_versions as c; print(c.verify()[0])'
```

Artifacts include `REPORT-anti-analysis-v2.md`, `RUNTIME-ANALYSIS.md`,
`BENCHMARKS-anti-analysis.md`, `BENCHMARKS-old-vs-improved.md` and
`tests/builds/manifest.json`.

## Web service

```bash
PORT=8000 OBF_TIMEOUT=60 python3 -m obf.web
```

The stdlib HTTP service parses and compile-checks untrusted Luau; it never
executes user Luau. Endpoints: `/`, `/index.html`, `/favicon.svg`, `/api/health`,
`/api/meta`, `/api/obfuscate`, `/api/identify`. Request-size, rate, concurrency,
CORS and CSP limits are enabled. No persistent storage is used.

## Limitations

This is obfuscation, not encryption or real security. A client-side Roblox
script must eventually expose enough runtime information to reproduce its
behaviour. A capable executor-specific debugger can inspect closures, local
calls and decoded values; no 100% decompile-proof protection or commercial
superiority is claimed. Roblox runtime behaviour is approximated with official
Luau 0.747 and mocked compatibility fixtures, not a live executor. Real
security requires server-side authority.

Deployment is intentionally paused: the repository is local-only, with no Git
remote, no push, no GitHub repo and no Render service. See `DEPLOY.md` and
`NEXT_STEPS.md`.
