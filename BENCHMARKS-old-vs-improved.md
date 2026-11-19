# Old-vs-improved benchmark

Measured 2026-11-19T02:58:39.331915+00:00 with official Luau 0.747 (tools/luau), seed 20261118. Old = `tests/baseline (frozen pre-second-pass engine)`. Three fresh Luau process launches per timing; min/median wall time and peak RSS (`ru_maxrss`) are local engineering numbers, not a red-team result.

## Output size

| Input | Old medium/heavy | New medium/heavy |
|---|---:|---:|
| `fixture_medium` | 70,471 B | 196,415 B |
| `startup_medium` | 66,926 B | 195,196 B |
| `workload_heavy` | 452,152 B | 609,425 B |

## Recoverability signatures

| Probe | Build | Comments | Brand | FNV constants | Stable fields | Startup needles | Simple dump needles | Distinct blobs |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| `print67` | old | 1 | True | 3 | 7 | 2 | 2 | 15 |
| `print67` | new | 0 | False | 0 | 0 | 0 | 0 | 15 |
| `scan_fixture` | old | 1 | True | 3 | 7 | 4 | 4 | 15 |
| `scan_fixture` | new | 0 | False | 0 | 0 | 0 | 0 | 12 |

The old `print(67)` build exposed the identifying byte-0 comment, fixed checksum constants and stable frame fields; the restricted runtime dump recovered source needles. The new build has zero comments, starts with `return`, uses randomized checksums and field keys, and the same restricted probes recover no source needles.

## Performance

| Measurement | Original | Old | New |
|---|---:|---:|---:|
| Startup median ms | 2.91 | 9.62 | 16.72 |
| Startup min ms | 2.78 | 6.72 | 16.27 |
| Startup median RSS KiB | 113,428 | 113,428 | 113,428 |
| Workload median ms | 2.31 | 419.31 | 1239.09 |
| Workload min ms | 2.22 | 412.22 | 1235.82 |
| Workload max RSS KiB | 113,428 | 113,428 | 113,428 |

5,000-loop median overhead: old 181.6x, new 536.6x. Tree-walker cost remains the dominant runtime factor. The third-pass distributed ticketed decoder matrices add work relative to the old single-router build; 650x is a gross-regression sanity ceiling, not a speed target or a guarantee.

## Caveat

This is not proof that client-side Roblox scripts are secure or superior to commercial obfuscators. A capable executor debugger can still inspect closures and runtime values. Real security requires server-side authority.
