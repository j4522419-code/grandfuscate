# Report: V5 stealth / fail-closed active decoys

Status: **implemented, verified, and DEPLOYED by the user.** V5 was pushed as
`a567ed0` on 2026-11-19 and is live; see `DEPLOY-V5-STATUS.md` and
`TEST-RESULTS-v5-live-smoke.txt`. This report was written before that push and
remains part of the deployed bundle. V5 is an opt-in flag; default builds are
unchanged. No agent commit, push, remote, token or deploy was performed.

## What changed

V4 shipped `obf/vm/traps.py` decoys in a separate **inert** table that the real
VM never called. V5 adds `obf/vm/stealth.py`: many lookalike handler functions
that are **embedded in the real call path**.

- Decoys are assigned into the same real VM handler tables (`EH`, `SH`, `BH`,
  `UH`, `LH`, `GH`) via `layout.vm_assign(...)`, with keys outside the real
  opcode space.
- `Layout.guard_line(...)` now calls the active-decoy reactor `R(key, ticket)`
  on a wrong capability ticket instead of returning a harmless default. The
  reactor is defined once in the constant-pool prelude and is in scope for both
  prelude and VM-body guard lines.
- All four reaction classes are present across the decoy minefield:
  opaque `error`, `coroutine.yield` loop, garbage bait-table return, and
  error+poison hybrid. An uncaught `error` cannot also return garbage/yield in
  the same function, so the four are distributed across decoys, not chained.
- The bait table is cyclic, reports a huge `__len`, raises the opaque error in
  `__tostring`, and enters the yield loop in `__call`; hybrid decoys also call
  `pcall(tostring, bait)` to emit malformed log bait.
- Every helper global (`error`, `setmetatable`, `tostring`, `pcall`,
  `coroutine.yield`, `bit32.bxor`, `rawset`, `pairs`, `type`) is rewritten
  through the opaque alias table. `CYIELD` was added to `ALIAS_PATHS` /
  `MEMBER_REWRITES`; the production scanner forbids bare `coroutine` /
  `coroutine.yield` chains.

## Hard boundary

A Luau chunk **cannot crash a third-party env logger / dumper / debugger
process**. V5 makes the *protected script* fail closed (error / yield / garbage)
and exposes malformed bait to an enumerating logger. An analyst can still
`pcall` errors, patch checks, step past decoys, or execute the real path. No
100% dumper/env-logger defeat, 100% decompile-proof, commercial-superiority or
live Roblox executor certification claim is made.

## Opt-in surface

| Surface | Usage |
|---|---|
| CLI | `python3 -m obf.cli examples/sample.luau --preset heavy --seed 20261118 --stealth --verify` |
| CLI alias | `--fail-closed` |
| API | `"stealth": true` in `/api/obfuscate` |
| API alias | `"fail_closed": true` |
| Default | `false` in all presets and `web.meta()["defaults"]` |

`anti_env` / `anti_tamper` remain forced off. V5 does not use the legacy
`obf/hardening.py` environment-hook poisoning.

## Verification

Full suite: **`ALL GREEN`, 507 checks, 0 failures** —
`TEST-RESULTS-v5-full-suite.txt`.
Standalone: **`STEALTH-V5: ALL GREEN (92 checks)`** —
`TEST-RESULTS-stealth-v5.txt`.

Canonical seed `20261118`, source `print("Hello World!")`:

| Preset | Active decoys | Reactions (error/yield/garbage/hybrid) | Output | Gate | Within gate |
|---|---:|---|---:|---:|---|
| light | 16 | 4 / 4 / 4 / 4 | 150,399 B | 179,903 | yes |
| medium | 48 | 12 / 12 / 12 / 12 | 211,749 B | 225,877 | yes |
| heavy | 128 | 32 / 32 / 32 / 32 | 659,694 B | 702,493 | yes |

All three stealth builds:
- parse with `luau-compile`, start with the required top banner, then a
  `return`-first body with no other comments;
- run unchanged (`Hello World!`, rc 0, empty stderr);
- stay under the existing `<=15%` size gate;
- produce **0** production-scanner findings;
- contain no bare forbidden globals, no `loadstring`, no raw `!@^&#%` outside
  string literals;
- keep `anti_env` / `anti_tamper` false;
- pass the bounded Luau decoy probe (`DECOYS=N CHECKED=N ... HANG=0`) with
  reaction counts exactly matching the plan.

Normal builds (`stealth=False`) are unaffected: no active-decoy plan,
`stats.stealth=false`, `stealth_decoys=0`. V4's 87 integrity/trap checks and
124 high-entropy checks remain green.

## Files

- `obf/vm/stealth.py` — plan, emitters, probe, no-loader guard.
- `obf/render.py` — `Options.stealth`.
- `obf/pipeline.py` — presets, `Result.stealth`, stats/keys, prelude wiring.
- `obf/vm/integrity.py` — builds the V5 plan, installs it on `layout`.
- `obf/layout.py` — `stealth_plan` field, active `guard_line` reactor.
- `obf/runtime.py` — emits decoy table / bait helper / reactor once.
- `obf/vm/runtime.py` — embeds decoys into real handler tables.
- `obf/format.py` — `CYIELD` alias rewrite.
- `obf/web.py`, `obf/cli.py` — opt-in API/CLI flags.
- `tests/stealth_v5.py`, `tests/run_tests.py` §30 — 92 new checks.
- `PLAN-stealth-v5.md`, this report, `TEST-RESULTS-*.txt`.
- `build_bundles.py` / `refresh_public_links.py` file lists include the V5
  artifacts. V5 ZIPs, `SHA256SUMS.txt`, `PUBLIC-DOWNLOAD-LINKS.md` and
  `DEPLOY-V5-TO-RENDER.md` were rebuilt and byte-verified.

## Deployment completed

The user followed `DEPLOY-V5-TO-RENDER.md`, pushed `a567ed0` to `main`, and
Render deployed it. Live `/api/meta` now has `defaults.stealth=false`; the
authenticated `stealth:true` call returns 48 active decoys and the default
call returns 0. Full verified status: `DEPLOY-V5-STATUS.md`. Rollback reference:
`DEPLOY-V4-TO-RENDER.md` / known-good V4 `97d767a`.
