# Plan: V6 anti-enumeration lockdown

Status: **PROPOSED — not implemented.** V5 is already deployed by the user at
`a567ed0`; see `DEPLOY-V5-STATUS.md`. This plan answers the follow-up question
"how can we make the code stop showing up in dumps?" with the user's choices:

- **Dump type:** env logger / `getgc` / upvalue / constant / table enumeration.
- **Priority:** aggressive fail-closed, even at some compatibility cost.

## Hard boundary (unchanged)

A Luau chunk cannot crash a third-party env logger / dumper / debugger process,
and cannot guarantee that running code never appears in a dump. If the script
executes, its closures, bytecode and VM stream exist in memory. An analyst can
`pcall` errors, patch checks, step past decoys, snapshot memory, or enumerate
objects without invoking them.

V6 therefore aims to **make active enumeration fail the protected script and
poison the dump**, not to erase the code or claim 100% dumper defeat.

## Why V5 does not "stop showing up"

V5 (`obf/vm/stealth.py`) fixed V4's inert-table problem by embedding decoys in
the real `EH/SH/BH/UH/LH/GH` handler tables and calling a reactor `R(k,t)` on a
wrong capability ticket. But:

- those decoys are still **function objects** in real tables; an env logger that
  enumerates tables/`getgc` can still list them;
- the mixed reaction set includes `garbage` and `hybrid` decoys that **return**
  a bait table, so the logger gets something to inspect;
- a passive logger that only lists functions/upvalues without calling them does
  not trip any reaction.

So V5 is a poison/fail-closed minefield, not a low-visibility design.

## V6 design

### 1. New opt-in flag

Add `lockdown: bool = False` (CLI `--lockdown`, API `"lockdown": true`; optional
alias `"anti_enum": true`). It implies `stealth=true` but changes the decoy
policy. Normal builds and V5 `stealth=true` builds stay unchanged. The existing
`fail_closed` alias stays a V5 alias; it is not reused for V6 to avoid
confusion.

`web.meta()["defaults"]` reports `lockdown=false`; stats gain
`lockdown` / `lockdown_decoys` / `lockdown_tripped` style fields.

### 2. Terminal reactions only

`StealthPlan` gains a `mode`: `"mixed"` (V5 default) or `"lockdown"` (V6).

In `lockdown` mode:

- every decoy is terminal: opaque `error(<const>)` or a bounded
  `while true do CYIELD() end` yield loop;
- `garbage` / `hybrid` return paths are disabled for the protected script;
- the selector `R(k,t,...)` never returns a value — it sets a shared trip latch
  and then errors or yields;
- V5's cyclic bait / huge `__len` / error `__tostring` / yield `__call` are kept
  only as **canary metamethod tripwires**, not as normal return values.

This preserves "all four reactions" as the V5 default while giving the user's
chosen aggressive mode a single behaviour: **enumerate a decoy → script dies**.

### 3. One-shot trip latch

Add a fresh runtime local `X` (e.g. `local X = false`) emitted once in the
constant-pool prelude, before any guard line or VM body references it.

- `R(k,t)` sets `X = true` and then errors/yields.
- Canary metamethods (`__index`, `__newindex`, `__len`, `__tostring`, `__call`,
  and `__iter` if supported by the target Luau) also set `X = true` and then
  error/yield. `__iter` support is verified with `tools/luau` before shipping;
  if unavailable it is omitted, not guessed.
- `Layout.function_selector` / the real handler dispatch path checks `X` first:
  once tripped, every subsequent real handler call fails closed instead of
  continuing. The real path can no longer be used after enumeration starts.
- The latch is an upvalue shared by prelude and VM body, not a `_G` global.

### 4. Canaries stay in the real call path

Decoys remain assigned into the real handler tables via
`layout.vm_assign(...)` with keys outside the real opcode space, exactly as in
V5. This is deliberate: modern env loggers skip inert tables. The canaries must
be reachable from executable code. V6 changes their **reaction**, not their
placement.

### 5. Standing constraints carried forward

- No dynamic loader, no `loadstring`, no comments, no top-level locals.
- No raw `!@^&#%...` outside string literals.
- All helper globals rewritten through the opaque alias table (`CYIELD`, etc.).
- Default off; `anti_env` / `anti_tamper` stay forced off (legacy checks poisoned
  normal executors).
- Preserve the `<=15%` size gate; exact zero-padding base is measured with the
  new mode enabled.
- No 99% claim, no commercial-superiority claim, no live Roblox executor
  certification, no "crashes the external logger" claim.

## What V6 would actually achieve

| Observer behaviour | V6 result |
|---|---|
| Enumerates real handler tables and invokes/calls/tostring a decoy | Trip latch set; protected script errors or yields; dump fills with opaque errors / cyclic bait instead of clean real output |
| Enumerates functions/upvalues but never invokes them | Can still list function objects; V6 does **not** erase them |
| `pcall`s the error and retries | Can still analyse; no security boundary |
| Full process memory dump / decompiler | Out of scope; bytes still exist |
| External logger process | Not crashed |

If the user later wants fewer inspectable objects, that is the separate
`min_objects` path (data-driven VM, fewer closures, bigger rewrite) — not the
aggressive fail-closed path chosen here.

## Implementation touchpoints

- `obf/vm/stealth.py` — `mode`, terminal reaction set, latch var, canary
  metamethod emitters, `react_call`, probe.
- `obf/layout.py` — `Layout` gains `lockdown_latch`; `guard_line` keeps `R`;
  `function_selector` / VM dispatch checks the latch before real work.
- `obf/runtime.py` — emit latch + stealth lines once, in scope for prelude and
  VM body.
- `obf/vm/runtime.py` — handler assignments unchanged.
- `obf/render.py`, `obf/pipeline.py`, `obf/web.py`, `obf/cli.py` — flag, stats,
  meta default, CLI help.
- `obf/format.py` — alias coverage for any newly emitted globals.
- `tests/anti_enum_v6.py`, `tests/run_tests.py` §31 — model env logger.
- New docs/results: this plan, `REPORT-anti-enumeration-v6.md`,
  `TEST-RESULTS-anti-enumeration-v6.txt`.

## Tests / acceptance

- Default and V5 `stealth=true` builds unchanged.
- `lockdown=true` builds parse, run `Hello World!` when **not** enumerated, and
  stay under the size gate.
- A model env logger that walks the real handler tables and invokes decoys
  causes all reactions to be terminal, trips the latch, and makes subsequent
  real dispatch fail closed.
- Bounded probe reports `HANG=0`; no bare forbidden globals, no `loadstring`,
  no raw punctuation outside literals.
- Full suite ALL GREEN, 0 failures; standalone V6 checks ALL GREEN.
- Report states the hard boundary explicitly.

## Tradeoffs

- More aggressive than V5: legitimate callers that probe handler tables will
  kill the script. Keep it opt-in.
- Slight output growth; must be measured against the 15% gate.
- Cannot detect a passive `getgc` snapshot that never calls anything.
- Cannot protect code that is shipped to the client from a full memory dump.
  Moving critical logic server-side remains the only real guarantee.

## Next step

Say **build V6** and I will implement this as an opt-in mode, add tests, run the
full suite, rebuild bundles/checksums/links if you want a deployable package,
and report measured results without overclaiming dumper defeat.
