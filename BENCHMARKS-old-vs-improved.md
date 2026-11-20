# Old-vs-improved benchmark

Measured 2026-11-20T21:36:50.876864+00:00 with official Luau 0.747 (tools/luau), seed 20261118. Old = `tests/baseline (frozen pre-second-pass engine)`. Three fresh Luau process launches per timing; min/median wall time and peak RSS (`ru_maxrss` on POSIX; unavailable/0 on Windows) are local engineering numbers, not a red-team result.

## Output size

| Input | Old medium/heavy | New medium/heavy |
|---|---:|---:|
| `fixture_medium` | 70,471 B | 211,758 B |
| `startup_medium` | 66,926 B | 209,269 B |
| `workload_heavy` | 452,152 B | 658,931 B |

## Recoverability signatures

| Probe | Build | Comments | Brand | FNV constants | Stable fields | Startup needles | Simple dump needles | Distinct blobs |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| `print67` | old | 1 | True | 3 | 7 | 2 | 2 | 15 |
| `print67` | new | 0 | False | 0 | 0 | 0 | 0 | 22 |
| `scan_fixture` | old | 1 | True | 3 | 7 | 4 | 4 | 15 |
| `scan_fixture` | new | 0 | False | 0 | 0 | 0 | 0 | 19 |

The old `print(67)` build exposed the identifying byte-0 comment, fixed checksum constants and stable frame fields; the restricted runtime dump recovered source needles. The new build has one required top banner comment, then a `return`-first protected body with no other comments, randomized checksums and field keys; the same restricted probes recover no source needles.

## Performance

| Measurement | Original | Old | New |
|---|---:|---:|---:|
| Startup median ms | 13.85 | 19.91 | 40.67 |
| Startup min ms | 13.55 | 18.57 | 37.88 |
| Startup median RSS KiB | 0 | 0 | 0 |
| Workload median ms | 14.65 | 615.28 | 1901.41 |
| Workload min ms | 13.18 | 612.92 | 1851.58 |
| Workload max RSS KiB | 0 | 0 | 0 |

5,000-loop median overhead: old 42.0x, new 129.8x. Tree-walker cost remains the dominant runtime factor. The third-pass distributed ticketed decoder matrices add work relative to the old single-router build; 650x is a gross-regression sanity ceiling, not a speed target or a guarantee.

## Caveat

This is not proof that client-side Roblox scripts are secure or superior to commercial obfuscators. A capable executor debugger can still inspect closures and runtime values. Real security requires server-side authority.
