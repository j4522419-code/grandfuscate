# Runtime-analysis probe

Measured 2026-11-20T02:42:52.079871+00:00 with official Luau 0.747, medium preset and seed 20261118.

The protected scripts still produce their original output. This probe attempts the restricted-runtime shortcuts that recovered `print(67)` from the previous build. A capable executor-specific debugger can observe more; this is not a security proof or a commercial comparison.

| Probe | Output | Original stdout needles | Startup dump needles | All simple dump needles | Result |
|---|---:|---:|---:|---:|---|
| `scan_fixture` | 211,758 B | 10 | 0 | 0 | PASS |
| `print67` | 209,299 B | 3 | 0 | 0 | PASS |

## Attempts on both probes

| Attempt | Result | Evidence |
|---|---|---|
| Identify a readable instruction table | failed | 0 small numbered handler groups; sequential small array: False |
| Identify a main numeric dispatcher | failed | {} |
| Dump startup constants | failed | 0 needles in startup dump; 19/19 encoded blobs touched before first print |
| Hook one decode function | failed | 19 distinct byte-source blobs, 10233 byte reads |
| Hook one execute function | no single global candidate | portable `debug.sethook`: false; candidate globals: 0 |
| Reconstruct clean IR | failed | IR markers: 0, longest small-word run: 0, small-word ratio: 0 |
| Recover exact `print(67)` source needles | failed | startup hits: 0; all simple dump hits: 0 |

## Instrumentation counts

| Metric | scan_fixture | print67 |
|---|---:|---:|
| `chunk_ok` | true | true |
| `prints` | 1 | 1 |
| `byte_calls` | 10233 | 10494 |
| `distinct_blobs` | 19 | 22 |
| `startup_blobs` | 19 | 22 |
| `char_calls` | 95 | 10 |
| `concat_calls` | 8 | 10 |
| `pack_calls` | 17 | 3 |
| `unpack_calls` | 2 | 1 |
| `bxor_calls` | 7785 | 9506 |
| `band_calls` | 66 | 0 |
| `startup_source_hits` | 0 | 0 |
| `all_source_hits` | 0 | 0 |
| `small_word_hits` | 0 | 0 |
| `total_words` | 23 | 2 |
| `longest_small_word_run` | 0 | 0 |
| `ir_marker_hits` | 0 | 0 |
| `clean_ir` | false | false |
| `hook_available` | false | false |
| `hook_installed` | false | false |
| `call_samples` | 0 | 0 |
| `debug_getinfo` | false | false |
| `debug_sethook` | false | false |
| `debug_getupvalue` | false | false |
| `debug_traceback` | true | true |
| `global_dispatcher_candidates` | 0 | 0 |

Scanner findings: 0. Probe success: **True**.

## Limitation

Decoded constants become visible when the VM uses them at runtime. A full Lua debug API, executor-specific hooks, or a human can still trace local calls, inspect closures and recover behaviour. The probe only shows that a single startup dump, one global dispatcher, one decode function and a contiguous clean IR are not available. Client scripts remain recoverable; real security needs server-side authority.
