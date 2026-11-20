# Anti-analysis benchmarks

Measured 2026-11-20T02:42:29.769814+00:00 with official Luau 0.747 (tools/luau).
Three process launches per measurement; min/median wall time and max/median peak RSS where the OS exposes it (`ru_maxrss` on POSIX). Windows reports RSS as unavailable (0).
RSS includes the interpreter's allocator baseline and can vary with process placement; small differences are not meaningful. Local engineering measurement only.

## Output size

Input fixture: `tests/scan_fixture.luau` (485 B).

| Preset | Output bytes | Expansion |
|---|---:|---:|
| light | 150,857 | 311.0x |
| medium | 211,758 | 436.6x |
| heavy | 659,729 | 1360.3x |

## Startup (no-op script: `local x = 1`)

| Build | Min ms | Median ms | Max RSS KiB | Median RSS KiB |
|---|---:|---:|---:|---:|
| original | 8.57 | 8.89 | 0 | 0 |
| light | 28.44 | 29.30 | 0 | 0 |
| medium | 27.86 | 28.86 | 0 | 0 |
| heavy | 44.72 | 45.35 | 0 | 0 |

## Runtime overhead

Workload: `tests/bench_runtime.luau (5,000 loop iterations)`. Heavy build generation took 1620.0 ms.

| Build | Min ms | Median ms | Max RSS KiB | Median RSS KiB |
|---|---:|---:|---:|---:|
| original | 10.77 | 12.39 | 0 | 0 |
| heavy | 1432.48 | 1458.95 | 0 | 0 |

Median runtime overhead: **117.74x** original.

Third-pass distributed ticketed decoders and per-build group matrices add interpreter work; the suite uses a 650x gross-regression ceiling rather than the earlier single-router budget.

These numbers measure this local toolchain and workload. They are not a comparison with Luraph, LuaProtect, or any deobfuscator, and they are not a security proof.
