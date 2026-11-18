# Next steps

## Current state

The third-pass anti-analysis implementation is local and verified. Production
chunks start with `return`, have zero comments, no identifying brand, one line,
zero top-level locals and no dynamic loader. The private source map stays out
of the chunk. The workspace contains refreshed examples, reports, benchmarks,
runtime-analysis results and a five-build diversity manifest.

Hosting remains paused. There is no Git remote, no push, no GitHub repository
and no Render service. Do not create or push to an origin unless the user
explicitly reverses that instruction.

## To use locally

```bash
# CLI
python3 -m obf.cli examples/sample.luau --preset medium --seed 20261118 --verify -o protected.luau

# Web service (local preview)
PORT=8000 OBF_TIMEOUT=60 python3 -m obf.web

# Full verification
python3 -m obf.cli --self-test
```

## To inspect the second- and third-pass evidence

- `REPORT-anti-analysis-v3.md` — third-pass A–F report and full file list.
- `RUNTIME-ANALYSIS-V3.md` / `RUNTIME-ANALYSIS-V3.json` — exact Hello World
  restricted-runtime probe, production output hashes and sidecar checks.
- `REPORT-anti-analysis-v2.md` — historical sections A–G and the 15-point
  checklist.
- `RUNTIME-ANALYSIS.md` / `RUNTIME-ANALYSIS.json` — restricted-runtime probes.
- `tests/builds/manifest.json` and `tests/builds/build_*.luau` — five builds.
- `BENCHMARKS-anti-analysis.md` — current size/startup/runtime benchmark.
- `BENCHMARKS-old-vs-improved.md` — frozen baseline vs current engine.
- `BENCHMARKS-hardening.md` and `REPORT-vm-hardening.md` — superseded first-pass
  artifacts.

## If deployment is resumed later

1. Confirm the user wants a remote and hosting account.
2. Create the GitHub repository and add the origin.
3. Push the local `main` branch.
4. Use `render.yaml` for the Render Blueprint, then wait for the free-tier cold
   start.
5. Smoke-test `/api/health`, `/api/meta` and `/api/obfuscate`.

None of those steps has been performed.

## Known limitations

Client-side Luau remains recoverable by a capable debugger. The runtime-analysis
probe only shows that simple startup dumps, one global dispatcher, one decode
function and a contiguous clean IR are not available. Hooks on `print` or
ordinary library calls such as `table.pack` still see values that the script
must pass at runtime. Official Luau 0.747 is not a live Roblox executor. No
commercial comparison or security proof is claimed.
