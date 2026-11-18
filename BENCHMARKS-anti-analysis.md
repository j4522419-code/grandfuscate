# Anti-analysis benchmarks

Measured 2026-11-18T05:32:06.723377+00:00 with official Luau 0.747 (tools/luau).
Three process launches per measurement; min/median wall time and max/median peak RSS (`ru_maxrss`).
RSS includes the interpreter's allocator baseline and can vary with process placement; small differences are not meaningful. Local engineering measurement only.

## Output size

Input fixture: `tests/scan_fixture.luau` (485 B).

| Preset | Output bytes | Expansion |
|---|---:|---:|
| light | 156,438 | 322.6x |
| medium | 196,415 | 405.0x |
| heavy | 610,864 | 1259.5x |

## Startup (no-op script: `local x = 1`)

| Build | Min ms | Median ms | Max RSS KiB | Median RSS KiB |
|---|---:|---:|---:|---:|
| original | 2.03 | 2.11 | 90,904 | 90,904 |
| light | 13.64 | 14.46 | 90,904 | 90,904 |
| medium | 15.80 | 16.11 | 90,904 | 90,904 |
| heavy | 26.74 | 28.70 | 90,904 | 90,904 |

## Runtime overhead

Workload: `tests/bench_runtime.luau (5,000 loop iterations)`. Heavy build generation took 1136.5 ms.

| Build | Min ms | Median ms | Max RSS KiB | Median RSS KiB |
|---|---:|---:|---:|---:|
| original | 3.15 | 3.29 | 90,904 | 90,904 |
| heavy | 1209.01 | 1219.38 | 90,904 | 90,904 |

Median runtime overhead: **370.14x** original.

Third-pass distributed ticketed decoders and per-build group matrices add interpreter work; the suite uses a 650x gross-regression ceiling rather than the earlier single-router budget.

These numbers measure this local toolchain and workload. They are not a comparison with Luraph, LuaProtect, or any deobfuscator, and they are not a security proof.
