# Grandfuscate presets and public controls

Normal builds use **one VM runtime** and exactly three presets. Nested dispatch,
anti-environment poisoning, anti-tamper poisoning and multi-megabyte padding are
disabled.

| Preset | Protection level | Behaviour | Typical output |
|---|---|---|---:|
| `light` | `light` | single VM, no flatten, no padding | ~154 KB |
| `medium` | `balanced` | balanced transforms, 4 KiB padding | ~197 KB |
| `heavy` | `aggressive` | more chaff, 64 KiB padding | ~607 KB |

`medium` is the website, API and CLI default. Old `balanced`, `aggressive` and
`max` names are accepted as aliases for `balanced`/`aggressive` presets, but the
public preset list is only `light / medium / heavy`.

## Output policy

- Zero comments; `return` at byte 0.
- One line plus a trailing newline.
- Zero top-level `local` declarations.
- Production chunks contain no dynamic loader (`loadstring`, `load(` or
  `require(`). The optional web button generates a separate loader wrapper;
  see `LOADSTRINGS.md`.
- No identifying brand or source-map marker in production bytes.
- Public keys contain opaque numeric entry/boot layout IDs and a SHA-256 of the
  private source map, not the private map itself.

## Website controls

The simplified UI exposes only:

- source textarea;
- `light`, `medium`, `heavy` preset selector;
- seed field;
- obfuscate, copy and download actions;
- `make it a loadstring!` and `Copy loadstring` actions, when configured;
- syntax and size readouts.

It does not expose nested VM, anti-environment, anti-tamper, padding, ratio or
old slider controls. `Pretty` mode is removed. The API clamps stale legacy
payload fields to the safe presets.

## Verification

Run `python3 -m obf.cli --self-test`. Production chunks must pass the
token-aware scanner, official-Luau syntax checks and behaviour differential.
Third-pass output uses ticketed group matrices rather than a central decoder or
router. Distributed decoding increases size and runtime overhead; see
`BENCHMARKS-anti-analysis.md` for current measurements. See
`REPORT-anti-analysis-v3.md` for the current A–F report and
`REPORT-anti-analysis-v2.md` for the historical second-pass results.
