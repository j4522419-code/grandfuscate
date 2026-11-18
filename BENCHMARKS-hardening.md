# VM hardening benchmarks (superseded)

> This first-pass benchmark is historical. Use `BENCHMARKS-anti-analysis.md`
> for the current engine and `BENCHMARKS-old-vs-improved.md` for the frozen
> pre-second-pass baseline comparison. The old byte-0 identifying comment
> requirement is no longer active.

Measured 2026-11-18T01:58:52.061074+00:00 with official Luau 0.747 (tools/luau).
Three process launches per measurement; min/median wall time and max/median peak RSS (`ru_maxrss`).
RSS includes the interpreter's allocator baseline and can vary with process placement; small differences are not meaningful. Local engineering measurement only.

## Output size

Input fixture: `tests/scan_fixture.luau` (485 B).

| Preset | Output bytes | Expansion |
|---|---:|---:|
| light | 42,312 | 87.2x |
| medium | 70,471 | 145.3x |
| heavy | 452,481 | 933.0x |

## Startup (no-op script: `local x = 1`)

| Build | Min ms | Median ms | Max RSS KiB | Median RSS KiB |
|---|---:|---:|---:|---:|
| original | 1.58 | 1.61 | 41,048 | 41,048 |
| light | 3.88 | 3.94 | 39,856 | 39,832 |
| medium | 4.78 | 4.81 | 39,856 | 39,856 |
| heavy | 18.24 | 19.14 | 41,048 | 41,048 |

## Runtime overhead

Workload: `tests/bench_runtime.luau (5,000 loop iterations)`. Heavy build generation took 248.7 ms.

| Build | Min ms | Median ms | Max RSS KiB | Median RSS KiB |
|---|---:|---:|---:|---:|
| original | 1.76 | 1.81 | 41,052 | 41,052 |
| heavy | 298.27 | 323.09 | 41,052 | 41,052 |

Median runtime overhead: **178.31x** original.

These numbers measure this local toolchain and workload. They are not a comparison with Luraph, LuaProtect, or any deobfuscator, and they are not a security proof.
