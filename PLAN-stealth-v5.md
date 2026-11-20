# Plan: V5 stealth / fail-closed active decoys

Status: **IMPLEMENTED and DEPLOYED by the user — full suite ALL GREEN, 0
failures.** V5 was pushed as `a567ed0` on 2026-11-19 and is live; see
`DEPLOY-V5-STATUS.md` and `TEST-RESULTS-v5-live-smoke.txt` for the verified
post-deploy state. This plan was written before that push and remains part of
the deployed bundle. It is an opt-in local/API flag. Standalone
`tests/stealth_v5.py`: **92 checks, ALL GREEN**. See `REPORT-stealth-v5.md`,
`TEST-RESULTS-stealth-v5.txt` and `TEST-RESULTS-v5-full-suite.txt`.

## What the user asked for

> "someone could still env log it, its meant to crash the env logger and the
> functions should be more secret and wayy less detectable, IT MUST CRASH IT"

Clarified choices:

- **Target:** `1 and 2` → fail closed / crash the protected script **and**
  poison the logger output.
- **Activation:** opt-in flag; normal builds stay compatible.
- **Trigger:** "lots of fake functions that the logger or dumper would figure
  out then accidentally catch but the functions must be embedded in the real
  code cus newer env loggers can just skip over them".
- **Reaction:** `all 4` → opaque error, permanent yield, garbage return, and
  error+poison.

## Hard boundary (must not be overclaimed)

A Luau chunk **cannot crash a third-party env logger / dumper / debugger
process** from inside the sandbox. It can only control its own behaviour:
refuse to run, raise an error, yield, or feed the observer garbage. An analyst
can `pcall` the error, patch the check, step past it, ignore the decoys, or
execute the real path. Runtime observation of output strings is unavoidable.

Therefore V5 delivers:

- **Fail closed:** any wrong-ticket decoy invocation terminates or hangs the
  protected script (opaque `error`, `coroutine.yield` loop, or garbage that
  breaks the VM downstream).
- **Poison:** malformed, cyclic, huge-length bait tables and error-throwing
  metamethods are returned / exposed to an enumerating logger.
- **No claim** that the external logger process crashes, that every third-party
  logger is defeated, or that the script is 100% decompile-proof.

## Why V4 was insufficient

V4 shipped `obf/vm/traps.py` decoys in a **separate inert table** (`T`) that
the real VM path never calls. A modern env logger that skips unreferenced
tables can ignore them. V4 also deliberately kept `anti_env`/`anti_tamper`
off because those legacy checks poisoned the constant decoder in ordinary
executors. The V4 plan/report explicitly disclaim dumper/env-logger defeat.

## V5 design

### 1. Opt-in flag

- `Options.stealth: bool = False` (also accepted as `fail_closed` in the web
  API for convenience).
- CLI: `--stealth`.
- API: `"stealth": true` in `/api/obfuscate`.
- Default off in all three presets; `web.meta()` defaults report `false`.
- `anti_env` / `anti_tamper` remain forced off. V5 does **not** use the legacy
  `obf/hardening.py` environment-hook poisoning.

### 2. Active decoys embedded in the real call path

New module `obf/vm/stealth.py` builds a `StealthPlan` with many lookalike
handler functions. Unlike V4's inert table:

- the decoys are assigned into the **same real VM handler tables**
  (`EH`, `SH`, `BH`, `UH`, `LH`, `GH`) via `layout.vm_assign(...)`, using keys
  outside the real opcode space;
- `Layout.guard_line(...)` is changed so that a **wrong capability ticket**
  calls a decoy from the real group function instead of just `return default`;
- the selector `R(k, t, ...)` is inlined into every guarded decoder path, so
  the decoys are referenced from executable code, not a dead table;
- all helper globals (`error`, `setmetatable`, `tostring`, `pcall`,
  `coroutine.yield`, `bit32.bxor`, `type`, `rawset`, `pairs`) are rewritten
  through the opaque alias table by `obf/format.py`; no bare forbidden globals.

Decoy count scales with the preset (`2 * decoy_traps`: 16 / 48 / 128) and stays
inside the existing `<=15%` size gate because the exact zero-padding base is
measured with stealth enabled.

### 3. Four reaction types (distributed, not sequential)

An uncaught `error` ends the call stack; it cannot also return garbage or
yield afterwards. So `all 4` is implemented as a **mixed minefield**: every
decoy belongs to one of four reaction classes, and `R` selects among them by
the wrong ticket.

| Reaction | Behaviour |
|---|---|
| `error` | Opaque `error(<build-time const>)`, fast, bounded. |
| `yield` | `while true do coroutine.yield() end` (no CPU spin; fails closed from a non-coroutine main thread). |
| `garbage` | Returns a cyclic, huge-length bait table with an error-throwing `__tostring`; breaks downstream VM expectations. |
| `hybrid` | Error + poison: emits malformed log bait, returns the bait table whose `__tostring`/`__index`/`__call` raise / yield. |

The bait table uses `setmetatable` with `__index` returning itself, `__len`
returning a huge value, `__tostring` raising the opaque error, and `__call`
entering the yield loop. `pcall(tostring, bait)` emits malformed log bait
without hanging the normal path.

### 4. Secrecy / detectability

- No `_G` registration, no named global dispatcher, no `loadstring`.
- All decoy locals come from `Names.fresh_runtime()` (compact, per-build).
- Decoy keys are random and excluded from real opcode values.
- The same arity / return shape as real handlers is preserved for enumeration
  plausibility.
- No comments, no top-level locals, no raw `!@^&#%` outside string literals.
- No 99% claim, no commercial-superiority proof, no live Roblox executor
  certification.

### 5. Tests

- `tests/stealth_v5.py` standalone + section 30 of `tests/run_tests.py`:
  - normal `stealth=False` builds are byte-for-byte unchanged in behaviour;
  - `stealth=True` builds parse, run and still produce the original output;
  - decoys are present in real handler tables and referenced from guard lines;
  - wrong-ticket probes trigger one of the four reactions under `pcall` with a
    bounded timeout; no hang escapes the harness;
  - no bare forbidden globals / member chains;
  - size gate `<=15%` still holds;
  - API/CLI accept the opt-in flag; default remains false;
  - no dynamic loader, no `loadstring`, no legacy `anti_env` poisoning.
- Full suite must remain `ALL GREEN`.

## Out of scope

- Crashing the external logger process (impossible from Luau).
- Guaranteeing any specific third-party env logger invokes a decoy.
- Live Roblox executor certification (official `luau` has no
  `debug.getupvalue`/`getinfo`/`sethook`).
- Push / Render deploy / bundle rebuild (ask separately).
