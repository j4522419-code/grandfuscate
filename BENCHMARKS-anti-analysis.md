# Anti-analysis benchmarks

Measured 2026-11-19T02:54:42.635284+00:00 with official Luau 0.747 (tools/luau).
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
| original | 2.05 | 2.21 | 93,096 | 93,096 |
| light | 13.41 | 14.46 | 93,096 | 93,096 |
| medium | 15.86 | 16.05 | 93,096 | 93,096 |
| heavy | 27.95 | 30.13 | 93,096 | 93,096 |

## Runtime overhead

Workload: `tests/bench_runtime.luau (5,000 loop iterations)`. Heavy build generation took 1094.5 ms.

| Build | Min ms | Median ms | Max RSS KiB | Median RSS KiB |
|---|---:|---:|---:|---:|
| original | 2.19 | 2.22 | 93,096 | 93,096 |
| heavy | 1193.53 | 1209.12 | 93,096 | 93,096 |

Median runtime overhead: **545.05x** original.

Third-pass distributed ticketed decoders and per-build group matrices add interpreter work; the suite uses a 650x gross-regression ceiling rather than the earlier single-router budget.

These numbers measure this local toolchain and workload. They are not a comparison with Luraph, LuaProtect, or any deobfuscator, and they are not a security proof.
