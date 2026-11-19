# Report: V4 high-entropy emitted-byte surface

Generated 2026-11-19T07:53:19.786964+00:00. Status: **implemented locally, full suite ALL GREEN, not deployed**. Metric chosen by the user: `bytes_in_literals` — emitted-source bytes inside encoded string/byte/number literal regions.

## A. Constraint (why 99% is impossible, and 90–95% is not reached)

Verified with official Luau: raw `!@^&#%!%#^!@#%^!^& return 1` fails with `Expected identifier when parsing expression, got '!'`; escaped quoted strings and long-bracket strings such as `[==[\x41\042\#!]==]` parse and run. A literal 99% emitted-byte target would need ~10–14 MB outputs (22x–62x current sizes), which breaks the `<=15%` size gate. The user lowered the target to **90–95% encoded-literal share where feasible** (`lower_target`); the `<=15%` size gate **wins**. We record the achieved maximum and make no 99% claim.

## B. Exact literal-share numbers (hello_world, canonical seed)

| Preset | Output | v3 baseline | Change | 15% gate | String share | Encoded share | Padding |
|---|---:|---:|---:|---:|---:|---:|---:|
| light | 147,673 B | 156,438 B | -5.6% | 179,903 B | **37.97%** | **53.74%** | 40,000 B |
| medium | 209,143 B | 196,415 B | +6.5% | 225,877 B | **48.21%** | **61.38%** | 60,000 B |
| heavy | 657,027 B | 610,864 B | +7.6% | 702,493 B | **78.55%** | **84.00%** | 100,000 B |

Encoded-literal share (canonical seed): light 53.74%, medium 61.38%, heavy 84.00%. Across the full preset x seed matrix it ranges 28.50%–84.00% (string share 7.57%–78.55%). See `BENCHMARKS-high-entropy.md` for the full table.

## C. Techniques actually used

- Inert `!@^&#%$*~?/;:,.` symbol soup split across six randomised long-bracket markers (`[=[...]=]` .. `[====[...]====]`) and one mixed-escape quoted marker (`\xNN` / `\ddd` / `\u{...}` / raw bytes). Markers are never executed or `loadstring`-ed.
- A bounded 96-byte window of each marker feeds the v4 integrity checksums, so editing marker bytes trips a harmless-default guard.
- Compact 1–2 char identifiers, numeric payload encoding, short structural skeleton. No raw punctuation outside string literals, no multi-megabyte padding, no `loadstring`-based self-decoding chunk.
- `LiteralBudget` clamps padding to the exact zero-padding base, so a build already over the fixed gate gets zero padding (e.g. light/99991, medium/99991 in the benchmark table).

## D. Verification

`tests/high_entropy_v4.py`: **124 checks, 0 failures**. All outputs parse, run with identical behaviour, start with `return` at byte 0, have zero comments, contain no `while true do` added by v4, no `loadstring`/`HttpGet`, stay < 1 MiB, and keep symbol soup strictly inside string tokens. Standalone long-bracket (512 B) and mixed-escape (all 256 byte values) decode probes pass.

## E. Delivery state

No commit, push, bundle rebuild, checksum refresh or download-link change (deployment was not requested). Caps were raised in code/docs as conservative future-proofing only; outputs remain far below them.
