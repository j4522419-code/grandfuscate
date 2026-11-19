# V4 VM-integrity / decoy-trap benchmarks

Measured 2026-11-19T07:53:19.786964+00:00 with official Luau 0.747 (`tools/luau`), seed 20261118.

## Output size vs v3 baseline (`hello_world`, canonical seed)

| Preset | v3 baseline | V4 bytes | Change | 15% gate | Gate |
|---|---:|---:|---:|---:|---|
| light | 156,438 | 147,673 | -5.6% | 179,903 | PASS |
| medium | 196,415 | 209,143 | +6.5% | 225,877 | PASS |
| heavy | 610,864 | 657,027 | +7.6% | 702,493 | PASS |

## Anti-analysis benchmark (scan_fixture.luau)

| Preset | Output bytes | Expansion |
|---|---:|---:|
| light | 150,608 | 310.5x |
| medium | 211,588 | 436.3x |
| heavy | 659,712 | 1360.2x |

Startup (no-op `local x = 1`), heavy median: 29.55 ms (budget < 500 ms). Runtime overhead median: 496.8x (budget < 650x).

## V4 integrity / trap cost (canonical seed)

| Preset | Canonical manifest | Domains | Decoys | Markers | Window | Wrong-ticket errors | Valid-ticket defaults | Hang |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| light | 10,540 B | 7 | 8 | 7 | 96 | 104 | 8 | 0 |
| medium | 23,299 B | 7 | 24 | 7 | 96 | 312 | 24 | 0 |
| heavy | 219,745 B | 7 | 64 | 7 | 96 | 832 | 64 | 0 |

Window checks are startup-only (seven bounded 96-step loops); the v4 additions add ~0 s to the interpreted-loop differential fixture (no per-iteration integrity work). Decoys live in an inert, never-called table, so they cost no runtime on the real VM path.

Note: the third-pass VM interprets a 200000-iteration benchmark loop in ~55-60 s of CPU regardless of v4; `tests/run_tests.py::run()` uses a 120 s wall-clock guard (same as `timed()`), a liveness ceiling, not a correctness relaxation. Local engineering measurement only.
