# V4 plan: VM integrity verification, opaque decoy traps + high-entropy output

**Status: IMPLEMENTED and DEPLOYED to Render (commit `97d767a`, verified live 2026-11-19). Full suite ALL GREEN.**  
The design below (extended with the high-entropy addendum in section 12) has been built into the local repo after the user's explicit `build it`. Production modules `obf/entropy.py`, `obf/vm/traps.py`, `obf/vm/integrity.py` plus the pipeline/VM emitter wiring are in place; `tests/vm_integrity_v4.py` (87 checks) and `tests/high_entropy_v4.py` (124 checks) are wired into `tests/run_tests.py` (sections 28–29). The complete suite passes with 0 failures. Examples, source maps, reports and benchmarks were regenerated. V4 bundles, checksums and download links were rebuilt, the user pushed `97d767a` to `main`, and Render deployed it (verified live `/api/meta` caps + V4 static docs). A separate opt-in **V5 stealth / fail-closed** follow-up (`PLAN-stealth-v5.md`) was subsequently deployed by the user at `a567ed0`; see `DEPLOY-V5-STATUS.md`. See `REPORT-vm-integrity-v4.md` and `REPORT-high-entropy-v4.md` for measured results.

## 1. Decision log

| Question | Answer | Meaning for v4 |
|---|---|---|
| What should this turn produce? | `plan` | Write this document, then wait for an explicit `build it`. |
| Trap behaviour | custom: `do 1 and 2` | Interpreted as options **1 + 2** on the trap-behaviour question: **harmless default** *and* **controlled error**. Bounded slowdown was not selected. |
| Integrity scope | `core` | Bytecode + constants + dispatch only. No full runtime attestation, no expansion of helper identity/ticket checks beyond what already exists. |
| “99% random” metric | `bytes_in_literals` | Means emitted-source bytes inside encoded string/byte/number literal regions; later revised to a lower 90–95% target in section 12. |
| Add to v4? | `add_to_v4` | High-entropy work is part of this plan, not a separate v5. |
| Size tradeoff | `lower_target` | Keep the existing `<=15%` size gate; target 90–95% literal share instead of a true 99% byte target. |
| Publish/body caps | `raise_both` | Raise `OBF_MAX_PUBLISH` and `OBF_MAX_BODY` as future-proofing, even though the lower target should keep outputs below 8 MiB. |

**Note on the last two rows:** `lower_target` and `raise_both` pull in different directions. I will treat `raise_both` as a conservative cap increase, **not** permission to produce multi-megabyte outputs. The `<=15%` size gate still wins.

**Interpretation to confirm before implementation:** `do 1 and 2` means:

- a **real decoder integrity mismatch** returns a harmless default (`0`, `nil`, `{}`), so ordinary execution is not harmed; and
- a **decoy / wrong-guess path** raises a deterministic controlled error, so it fails fast instead of hanging in `while true do`.

If that is not what you meant, correct it before saying `build it`.

---

## 2. Reality check and terminology

- The project is an **obfuscator/encoder**, not encryption. The new checks are **rolling integrity checksums over encoded VM state**, not a cryptographic MAC and not a security boundary. I will use “integrity verification” / “encoded VM state”, not “encryption flow”.
- Raw `!@^&#%...` outside a string literal is **not valid Luau** and will not parse; official Luau rejects it. Symbol soup can only live inside escaped quoted strings or long-bracket strings such as `[==[!@^&#%...]==]`. A literal 99% of emitted bytes is not reachable within the current size budget; see section 12.
- A client-side Luau script cannot force an external dumper, env logger or debugger to “brute force error 100% of the time”. A capable analyst can `pcall` decoys, ignore errors, patch checks, step past them, hook `print`/library calls, or simply execute the real path. What v4 can guarantee is **deterministic behaviour inside our own wrong-ticket probe**: every decoy called with a guessed ticket returns a controlled error quickly, with no hang.
- “Opaque prediction traps” are normally called **opaque predicates**: conditions whose outcome is known at build time but is not a literal `true`/`false` in the emitted script. I will use that term below.
- The existing `while true do` loops in `obf/runtime.py` and `obf/vm/runtime.py` are **semantic VM loops** (metadata parsing, `repeat`/`until`, `for ... in`, handler dispatch). They already have `break`/`return` exits. They are not anti-analysis traps and must not be replaced with errors. v4 adds **new trap paths** that contain no unbounded loops.
- Legacy `anti_env` / `anti_tamper` from `obf/hardening.py` stay clamped off. They were reverted because environment-hook checks can poison the constant decoder in ordinary Luau/Roblox executors. v4 must not revive `getfenv` poisoning, `debug.gethook` checks, executor-env name checks, or the legacy central FNV path.
- Runtime observation remains unavoidable: the protected program must call `print`, `table.pack`, etc., so an instrumented environment can still see values passed to those calls. v4 targets **enumeration/dumping cost and clean-IR recovery**, not runtime secrecy.

---

## 3. Current baseline (what already exists)

From `REPORT-anti-analysis-v3.md` and the current source tree:

- `light` / `medium` / `heavy` presets and aliases `balanced` → `medium`, `aggressive`/`max` → `heavy`; default `medium`.
- One `return`-based one-line output, zero comments, byte-0 `return`, private source maps as sidecars only.
- Distributed, ticketed group decoders for pool bytes, VM bytes, words, nodes, constants, `eval` and `exec`.
- `obf/layout.py`: `chain_ticket_expr`, `guard_line`, `function_selector`, per-build bank/group coefficients, dispatch/router/VM profiles.
- `obf/checksum.py`: `ChecksumParams`, `checksum`, `emit_verify_lines` (rolling checksum over one blob/key), and `emit_group_integrity_lines` (type/count checks that set `ok_var=false`). A mismatch currently makes the guarded decoder return a harmless default.
- `obf/vm/compiler.py`: `Program` holds `stream`, `stream_key`, `fragments`, `opcodes`, `binmap`, `unmap`, `decoy_opcodes`, operand coefficients/permutations, chunk plans, control-flow metadata.
- `obf/vm/fragments.py`, `obf/vm/nodes.py`, `obf/vm/runtime.py`: group matrices, handler tables, decoy opcodes/words and `return nil` decoy branches.
- `obf/junk.py`: simple `opaque_true` / `opaque_false` / `junk_stmt` used by the flattener.
- `obf/web.py`: `BOOL_KEYS` accepts only `flatten`, `virtualize_globals`, `virtualize_properties`, `integrity`; `anti_env` and `anti_tamper` are forced false; `nested_vm` is forced false.
- `tests/run_tests.py`: current full suite is `ALL GREEN`, including 13 mocked loadstring-publisher checks. v3 scanner/runtime-analysis checks are 0-finding on production outputs.
- v3 benchmark baseline: light `156,438 B`, medium `196,415 B`, heavy `610,864 B`; heavy workload overhead roughly `545x`.

v4 extends this baseline; it does not rewrite the VM.

---

## 4. Goals

1. **Core VM integrity verification** over:
   - VM instruction stream + stream key;
   - fragment blobs/keys and their checksum parameters;
   - constant-pool slices/keys;
   - opcode maps, binary/unary maps;
   - dispatch/handler group identities, bank/group coefficients and ticket-derivation coefficients;
   - per-node operand permutation coefficients.
2. **Distributed verification**, not one central “hash the whole payload” check. Each group verifies its own small digest slice; a mismatch sets that group's `ok` flag false and returns a harmless default.
3. **Capability tickets bound to the integrity digest**, so tampering with encoded bytecode/constants/dispatch also invalidates the tickets needed to use the real group functions.
4. **Many plausible decoy functions** that look like real VM bytecode/group functions to an enumerating dumper, with the same arity and return shape as real `vm_byte`, `word`, `node`, `constant`, `eval` and `exec` handlers.
5. **Dual failure behaviour**:
   - real path / integrity mismatch → harmless default;
   - decoy / wrong-guess path → controlled `error(<opaque runtime const>)`, no `while true do`, no unbounded work.
6. Preserve all current public behaviour, determinism, scanner cleanliness and differential compatibility.
7. **High-entropy output surface** within the existing `<=15%` size gate: push the encoded-literal byte share toward **90–95% where feasible**, without claiming 99%.


---

## 5. Proposed architecture

### 5.1 Build-time integrity manifest

New module: `obf/vm/integrity.py`.

Suggested data:

```text
VMIntegrityPlan
  global_digest: int
  group_digests: dict[domain, list[int]]
  trap_salt: int
  ticket_salt: int
  expected_by_group: dict[domain, list[ChecksumParams]]
```

Computed **after** `Compiler` serialises the VM program, from a canonical byte representation of:

```text
opcodes | binmap | unmap
stream | stream_key
fragment[i].blob | fragment[i].key | fragment[i].hash_params
pool slice blobs/keys
handler group ids | bank/group coefficients
chain-ticket coefficients | per-node operand c/d | word/stream order
```

Rules:

- Use the existing seeded `random.Random`; no new nondeterminism.
- Emit expected values as opaque numeric constants, not plaintext labels, build ids, source-map URLs or comments.
- Reuse `ChecksumParams` with per-group randomised coefficients. These are obfuscation checksums, not cryptographic digests.
- Do **not** concatenate the whole payload into one string for a central hash; that would recreate the single-obvious-hook problem v3 removed.
- Keep the private source map separate and never embed it.

### 5.2 Distributed runtime verification

Extend `obf/checksum.py` with helpers such as:

```text
make_group_params(rng, canonical_bytes) -> ChecksumParams
emit_distributed_verify_lines(ns, expr, params, ok_var, indent) -> list[str]
```

Wire into:

- `obf/vm/fragments.py` for `vm_byte` groups and fragment selectors;
- `obf/vm/nodes.py` for `word` / `node` groups;
- `obf/vm/runtime.py` for `constant`, `eval`, `exec` handler groups;
- `obf/runtime.py` where legacy slice checksums already exist, only if needed for constant-pool coverage.

Behaviour on mismatch:

```text
ok_<group> = false
return 0 / nil / {}   -- harmless default, no error, no hang
```

Extend `obf/layout.py` with an optional `integrity_salt` mixed into `chain_ticket_expr`, and update every real call site and guard in the same build so the real path stays internally consistent. Do not change public call-site arity. Differential fixtures must prove unchanged behaviour.

### 5.3 Opaque decoy traps

New module: `obf/vm/traps.py`.

Suggested API:

```text
TrapPlan
  count: int
  decoy_opcodes: list[int]
  predicates: list[OpaquePredicate]
  error_constant: int

make_trap_plan(rng, program, integrity, preset) -> TrapPlan
emit_trap_group_lines(...) -> list[str]
emit_trap_dispatch_lines(...) -> list[str]
opaque_predicate_v2(...) -> str
```

Decoy design:

- Generate preset-scaled counts, e.g. light `8–16`, medium `24–48`, heavy `64–128` decoy handlers, subject to benchmark gates.
- Insert them into the same group tables / dispatch tables as real handlers, under fresh random 32-bit `decoy_opcodes` (extend the current 8 decoy opcodes).
- Mirror real signatures:
  - `function(j, t, f)` for byte/fragment-style groups;
  - `function(i, t)` for word/node/constant groups;
  - `function(nd, fr)` for `eval`/`exec`-style handlers.
- Mirror real-looking structure: `type(function() end)` checks, guard-line-shaped ticket checks, group/bank arithmetic, default returns, similar table-slot expressions.
- Opaque predicates derive from `global_digest`, `trap_salt`, bank/group indices, key expressions, string lengths, `bit32` operations and modular arithmetic. No literal `true`/`false` and no simple `a*a+b` pattern reused from `obf/junk.py` alone.
- **Wrong ticket / wrong predicate** → `error(<opaque runtime const>)`. This is option 2 from `do 1 and 2`.
- **Real path never calls decoys.** If a decoy somehow receives a valid ticket (should be impossible), it returns a harmless default rather than erroring, to avoid false positives breaking ordinary execution.
- No `while true do` in trap code. Any loop is bounded and has an explicit `break`.
- No `getfenv`, `debug`, `hookfunction`, `os`, `io`, persistence, credential access, environment poisoning or debug output.

### 5.4 “Do 1 and 2” behaviour matrix

| Situation | v4 behaviour | Why |
|---|---|---|
| Untampered real build, real call site | Normal VM execution | Must preserve differential compatibility. |
| Real decoder sees integrity mismatch | `ok=false`, return harmless default | Option 1: avoids breaking ordinary executors. |
| Dumper enumerates a decoy and guesses a ticket | Controlled `error(...)` quickly | Option 2: fail fast, no hang, no `while true do`. |
| Decoy somehow receives a valid ticket | Harmless default | Safety valve against false positives. |
| Current semantic `while true do` VM loops | Unchanged | They are required control flow, not traps. |

### 5.5 Options and public API

- Reuse existing `Options.integrity` as the master switch; all current presets already set it `True`.
- Add an internal preset-scaled `Options.decoy_traps: int` (and optionally `Options.vm_integrity_salt: int`) in `obf/render.py` and `PRESETS` in `obf/pipeline.py`.
- Do **not** add new public web API keys initially. `BOOL_KEYS`, `INT_KEYS`, `FLOAT_KEYS`, `RANGES`, preset names, aliases and `anti_env`/`anti_tamper` clamps stay exactly as they are.
- `obf/web.py` `meta()["hardening"]["version"]` can move from `3` to `4` only after implementation and green tests.
- `obf/cli.py` self-test stats may report `integrity groups` / `decoy traps`, but CLI output format must stay deterministic.
- The loadstring publisher, `OBF_GITHUB_*`, `OBF_API_KEY`, `OBF_MAX_SOURCE`, `OBF_MAX_BODY`, `OBF_TIMEOUT`, `OBF_MAX_PUBLISH` and Render Blueprint are unchanged.

### 5.6 High-entropy emitted-byte surface (addendum)

New module: `obf/entropy.py`.

Goals, in priority order:

1. **Never exceed the `<=15%` output-size gate** from section 7.
2. Raise the measured **encoded-literal byte share** toward 90–95% where feasible.
3. Keep zero comments, one line, byte-0 `return`, no `loadstring`/`HttpGet`, no dynamic loader, private source maps separate.

Measurement definition, to be implemented in `tests/high_entropy_v4.py`:

```text
encoded-literal bytes = bytes inside quoted string literals
                      + bytes inside long-bracket string literals
                      + bytes of numeric payload tables that are themselves
                        emitted as escaped byte strings
structural bytes      = all other bytes (reserved words, identifiers,
                        operators, delimiters, short numeric indices)
```

Target: `encoded-literal bytes / total output bytes >= 0.90` for heavy, best effort 90–95% for light/medium, **subject to the size gate**. If a preset cannot reach 90% inside the gate, record the achieved maximum and keep the gate; do not pad to multi-megabyte sizes and do not claim 99%.

Techniques:

- Extend `obf/pool.py::lua_bytes_literal` and `obf/format.py::_escaped` to mix `\xNN`, `\ddd`, `\u{...}` and safe printable bytes more aggressively.
- Add inert long-bracket symbol padding `[==[!@^&#%!%#^!@#%^!^&]==]` with a randomised equality level and a safe alphabet that cannot contain the closing delimiter. Verified with official Luau: a 540,000-byte long-bracket string parses and runs.
- Encode numeric tables (opcode maps, coefficients, expected digests, trap salts, error constants, decoy words) as escaped byte strings decoded lazily through `string.byte` and the existing ticketed group getters. Do **not** serialise executable Luau into a string and call `loadstring`.
- Shorten runtime identifier names to 1–2 characters where collision-free, and replace long numeric literals with short encoded-table indices.
- Keep structural Luau skeleton minimal but valid; reserved words and delimiters remain.
- Add a `LiteralBudget` that refuses to emit padding once the `<=15%` size gate would be crossed.

Cap changes (future-proofing from `raise_both`, not permission for large outputs):

| File | Current | Planned |
|---|---:|---:|
| `render.yaml` `OBF_MAX_PUBLISH` | `8388608` (8 MiB) | `16777216` (16 MiB) |
| `render.yaml` `OBF_MAX_BODY` | `16777216` (16 MiB) | `33554432` (32 MiB) |
| `render-large-source.env.example` same keys | same | same |
| `LOADSTRINGS.md` / `DOWNLOADS-AND-DEPLOY.md` / `WINDOWS-STEP-BY-STEP.md` | document 8 MiB | document new values |

`OBF_MAX_SOURCE`, `OBF_TIMEOUT`, `OBF_API_KEY`, `OBF_GITHUB_*`, `OBF_MAX_IDENTIFY`, presets and aliases stay unchanged. The user must still set Render Environment values manually; no agent push/deploy/token/service.

---

## 6. File-by-file implementation map

| Path | Change |
|---|---|
| `obf/vm/integrity.py` | **New.** Canonical manifest, per-group `ChecksumParams`, digest/ticket salts. |
| `obf/vm/traps.py` | **New.** Decoy trap plan, opaque predicates, decoy group/dispatch emitters. |
| `obf/checksum.py` | Add `make_group_params` / `emit_distributed_verify_lines`; keep existing helpers for compatibility. |
| `obf/vm/compiler.py` | After program serialisation, compute `VMIntegrityPlan`; store on `Program`; expand `decoy_opcodes`. |
| `obf/layout.py` | Optional `integrity_salt` in `chain_ticket_expr`; keep `guard_line` / selector semantics consistent. |
| `obf/vm/fragments.py` | Verify `vm_byte`/fragment group digests; install decoy byte/fragment handlers. |
| `obf/vm/nodes.py` | Verify `word`/`node` group digests; install decoy word/node handlers. |
| `obf/vm/runtime.py` | Verify `constant`/`eval`/`exec` group digests; install decoy dispatch branches. |
| `obf/runtime.py` | Only if constant-pool slice coverage needs the new distributed helper; otherwise leave. |
| `obf/junk.py` | Optionally expose richer predicate helpers, or keep v2 predicates inside `traps.py`. |
| `obf/render.py` | Add internal `decoy_traps` (and optional salt) to `Options`. |
| `obf/pipeline.py` | Add preset-scaled `decoy_traps` values; include integrity/trap summary in private source map only. |
| `obf/cli.py` | Report integrity group / trap counts in self-test stats. |
| `obf/web.py` | Bump `meta()` hardening version after green tests; no new public keys. |
| `obf/entropy.py` | **New.** `LiteralBudget`, mixed escapes, long-bracket symbol padding, numeric-table encoding helpers. |
| `obf/pool.py`, `obf/format.py`, `obf/chunks.py`, `obf/vm/compiler.py` | Use the new literal emitters and move more numeric payload into encoded byte strings. |
| `obf/render.py`, `obf/pipeline.py` | Internal preset-scaled entropy budget; no new public API keys. |
| `tests/vm_integrity_v4.py` | **New.** Integrity, trap, tamper, decoy-probe and determinism checks. |
| `tests/high_entropy_v4.py` | **New.** Literal-share measurement, escape/long-bracket parse, size gate, no-dynamic-loader checks. |
| `tests/run_tests.py` | Add section 28 (`vm integrity checks`) and section 29 (`entropy checks`) to the summary. |
| `render.yaml`, `render-large-source.env.example`, `LOADSTRINGS.md`, `DOWNLOADS-AND-DEPLOY.md`, `WINDOWS-STEP-BY-STEP.md` | Raise/document `OBF_MAX_PUBLISH` and `OBF_MAX_BODY` as above. |
| `REPORT-high-entropy-v4.md`, `BENCHMARKS-high-entropy.md`, `TEST-RESULTS-high-entropy.txt` | **New.** High-entropy report, before/after size and literal-share benchmarks, full-suite output. |
| `tests/anti_analysis_v3.py` / `tests/runtime_analysis.py` | Extend static/runtime probes for decoys, central digest and trap loops. |
| `REPORT-vm-integrity-v4.md` | **New.** Implementation report. |
| `BENCHMARKS-vm-integrity.md` | **New.** Before/after size, startup and loop benchmarks. |
| `RUNTIME-ANALYSIS-V4.json` / `.md` | **New.** Instrumented probe results. |
| `TEST-RESULTS-vm-integrity.txt` | **New.** Full-suite output. |
| `examples/*`, `keys_*.json`, `source_map_*.json`, `tests/builds/*` | Regenerate after implementation. |
| `README.md`, `ARCHITECTURE.md`, `ROADMAP.md`, `NEXT_STEPS.md`, `config/README.md` | Document v4 after green tests. |

`obf/hardening.py`, `obf/vm/armor.py`, `render.yaml`, `LOADSTRINGS.md`, `WINDOWS-STEP-BY-STEP.md`, `DOWNLOADS-AND-DEPLOY.md` and deployment bundles are **not** modified by the plan itself. Bundles/checksums/download links are rebuilt only after implementation if the user asks to deploy.

---

## 7. Test plan

New `tests/vm_integrity_v4.py`:

1. **Seeded reproducibility**: same seed → byte-identical output; five seeds → five distinct structural digests.
2. **Manifest coverage**: tamper one byte of stream, one fragment blob/key, one pool key, one opcode map value and one dispatch coefficient; each tamper changes the relevant expected group digest.
3. **Harmless-default probe**: mutate an emitted blob/key in a controlled build; the affected real decoder returns `0`/`nil`/`{}`, does not raise, does not hang, and does not poison the environment.
4. **Decoy wrong-ticket probe**: enumerate every generated decoy, call with N guessed tickets under `pcall`; every call returns `ok=false` (controlled error) within a bounded time. This is the “100% in our harness” result, not a claim about third-party dumpers.
5. **No-trap-loop check**: static scan of generated trap code finds no `while true do`, no unbounded `for`, no `repeat ... until false`.
6. **Real-path safety**: assert no real call site targets a decoy opcode; assert decoys with an accidental valid ticket return a default.
7. **Differential compatibility**: run existing fixtures (closures, upvalues, varargs, multiple returns, nil, tables, metatables, callbacks, `:` calls, `pcall`/`xpcall`, coroutines, yielding, mocked Roblox APIs) through official Luau 0.747 and compare outputs.
8. **Scanner / runtime analysis**: `AA.scan_output` 0 findings on light/medium/heavy; no central digest table, no plaintext marker, no `loadstring`/`HttpGet`, no dynamic loader, no clean IR, no whole-payload table/function. `print` and `table.pack` observation remains expected.
9. **Output shape**: byte-0 `return`, one line, zero comments, private source map not embedded.

New `tests/high_entropy_v4.py`:

1. Tokenizer-aware `encoded-literal bytes / total bytes` measurement on light/medium/heavy outputs.
2. Assert the `<=15%` size gate is never crossed; record achieved literal share, target 90–95% where feasible, no 99% claim.
3. Parse every generated short escape and long-bracket string with official Luau; verify mixed `\xNN`, `\ddd`, `\u{...}` and `[==[...]==]` forms.
4. Verify raw symbol soup never appears outside string literals; no `loadstring`, `HttpGet`, `require` or dynamic loader.
5. Verify zero comments, one line, byte-0 `return`, private source map not embedded, seeded reproducibility and differential compatibility.
6. Scanner/runtime-analysis checks remain 0-finding; decoys and integrity traps still behave as in sections 5.2–5.4.

`tests/run_tests.py` section 28 calls `V4.run(failures)`, section 29 calls `ENTROPY.run(failures)`, and the final line becomes:

```text
... + 13 loadstring checks + N vm integrity checks + M entropy checks, 0 failure(s)
ALL GREEN
```

Benchmark gates, measured against the v3 baseline:

- output size increase `<= 15%` per preset;
- startup and 5,000-loop median increase `<= 10%`;
- if gates fail, reduce `decoy_traps` rather than removing integrity checks;
- record heavy overhead explicitly; do not hide it.

---

## 8. Acceptance criteria

Implementation is accepted only when:

- Public presets, aliases, default `medium`, API keys, web clamps and `anti_env`/`anti_tamper` policy are unchanged.
- Full `python3 tests/run_tests.py` is `ALL GREEN`, `0 failure(s)`.
- Untampered outputs run identically in official Luau and mocked Roblox fixtures.
- Integrity mismatch returns a harmless default; decoy wrong-guess returns a controlled error; neither hangs.
- No `while true do` is added by trap code; existing semantic loops remain.
- Scanner findings are 0; runtime-analysis expectations remain as documented in the v3 report.
- Seeded reproducibility and five-build diversity still hold.
- Production chunks still start with `return`, contain zero comments, embed no source map, and contain no `loadstring`/`HttpGet`.
- Benchmarks stay within the gates above.
- Encoded-literal byte share is measured and reported for every preset; 90–95% is targeted where feasible inside the `<=15%` size gate, and no 99% claim is made.
- `OBF_MAX_PUBLISH` / `OBF_MAX_BODY` are raised in checked-in config/docs as future-proofing; `OBF_MAX_SOURCE` and the checked-in source cap remain unchanged.
- Raw `!@^&` symbol soup appears only inside valid string literals; no dynamic loader is introduced.
- No git remote, commit, push, GitHub repo, token, Render service, secret, or deployment is created by the agent.
- No 100% decompile-proof, commercial-superiority, red-team or live-executor certification claim is made.

---

## 9. Non-goals

- No full runtime attestation (you selected `core`).
- No expansion of helper identity/ticket checks beyond existing `emit_group_integrity_lines`.
- No bounded-slowdown option (not selected).
- No `anti_env` / `anti_tamper` revival, no environment poisoning, no `debug`/`getfenv` hooks.
- No double VM / `nested_vm`, no `obf/vm/armor.py` changes.
- No unbounded loops, no infinite hangs, no destructive behaviour, no credential access, no persistence.
- No change to the 256 KiB checked-in `OBF_MAX_SOURCE` default; no uncap.
- No literal 99% emitted-byte target, no multi-megabyte padding, no raw `!@^&` outside string literals, no `loadstring`-based self-decoding chunk.
- No change to loadstring publisher, GitHub raw hosting, Render env vars, API key, or deployment workflow.
- No paid host, GitHub Pro, Render disk, or new service.
- No agent-side push/deploy; any rollout remains a manual user action.

---

## 10. Phasing

| Phase | Work | Exit condition |
|---|---|---|
| 0 | This plan | User confirms interpretation and says `build it`. |
| 1 | `obf/vm/integrity.py`, `obf/checksum.py`, compiler/layout wiring | Distributed checks green, harmless-default tamper probe passes. |
| 2 | `obf/vm/traps.py`, fragments/nodes/runtime wiring | Decoy wrong-ticket probe passes, no trap loops, scanner clean. |
| 2b | `obf/entropy.py`, literal emitters, numeric-table encoding, long-bracket padding | Literal-share target met where feasible, `<=15%` size gate respected. |
| 3 | Options/meta/CLI/docs/caps, regenerate examples/keys/maps/reports | Full suite `ALL GREEN`, benchmarks within gates, caps documented. |
| 4 | Optional deliverables | Rebuild 3 ZIPs, `SHA256SUMS.txt`, `download/`, fresh direct links **only if** the user wants to deploy. Otherwise stop at local code. |

No phase 4 work has been done. The current fresh download links from the UI-cleanup build remain valid for that build only.

---

## 11. Open items

- I interpreted `do 1 and 2` as **harmless default + controlled error**. Correct this before implementation if that is wrong.
- I interpreted the high-entropy follow-up as `bytes_in_literals` added to v4, then revised by `lower_target` + `raise_both` as described in section 12.
- The `<=15%` size gate and the cap increase are both recorded; the size gate wins if they conflict.

---

## 12. Addendum: high-entropy output, final decisions

### 12.1 What was measured

Current production outputs, measured with a string-literal-aware counter:

| Preset | File | Bytes | Quoted-string bytes | Share |
|---|---|---:|---:|---:|
| light | `examples/protected_hello_light.luau` | 154,402 | 14,723 | 9.5% |
| medium | `examples/protected_hello_balanced.luau` | 198,810 | 39,105 | 19.7% |
| heavy | `examples/protected_hello_aggressive.luau` | 607,349 | 413,468 | 68.1% |

Non-string bytes are mostly identifiers and numeric literals:

| Preset | Identifier bytes | Numeric bytes | Punctuation/space |
|---|---:|---:|---:|
| light | 87,259 | 35,110 | 17,310 |
| medium | 100,225 | 42,534 | 16,946 |
| heavy | 121,992 | 49,167 | 22,722 |

Official Luau probes:

- `\x41`, `\042`, `\u{4c}` escapes parse and run.
- `[==[!@^&#%!%#^!@#%^!^&]==]` long-bracket strings parse and run; a 540,000-byte probe returned `540000`.
- Raw `!@^&#%...` before `return 1` fails with `Expected identifier when parsing expression, got '!'`.

A rough estimate showed that a **true 99% emitted-byte target** would require roughly 10–14 MB outputs (22×–62× current sizes) after even aggressive name shortening and numeric-table encoding. That conflicts with the `<=15%` size gate and would exceed the 8 MiB publish cap.

### 12.2 Final decisions from the follow-up

| Follow-up question | Answer | Effect |
|---|---|---|
| What does 99% random mean? | `bytes_in_literals` | Measure emitted source bytes inside encoded literal regions, not tokens or visual impression alone. |
| Add to v4? | `add_to_v4` | This addendum is part of the pending v4 plan. |
| Size tradeoff | `lower_target` | **Replace the 99% target** with 90–95% literal share where feasible, keeping the `<=15%` size gate. |
| Publish/body caps | `raise_both` | Raise `OBF_MAX_PUBLISH` to 16 MiB and `OBF_MAX_BODY` to 32 MiB as future-proofing; still no large outputs in v4. |

### 12.3 Conflict resolution

`lower_target` and `raise_both` are not contradictory if treated conservatively:

- v4 outputs stay within `<=15%` of current sizes, so they should remain far below 8 MiB.
- The caps are raised anyway so a future larger build or a user-supplied bigger output does not immediately hit 413 responses.
- No agent sets these Render values; the user pastes them into the existing service's **Environment** page after pushing updated code.
- `OBF_MAX_SOURCE` stays `262144` in checked-in code; the env-only large-source guidance is unchanged.

### 12.4 Revised non-goals

- No 99% emitted-byte claim.
- No multi-megabyte padding to force a percentage.
- No raw punctuation outside strings.
- No `loadstring(game:HttpGet(...))()` inside the protected chunk to execute encoded code; the one-line loader remains a separate feature of the loadstring button only.
- No new public preset or API key for entropy; it is internal and preset-scaled.

---

## 13. Final approval

If the interpretations above are right, say:

> **`build it`**

I will then implement locally, run the full suite, regenerate examples/reports/benchmarks, report exact literal-share numbers and test results, and rebuild bundles/checksums/download links only if you want to deploy. I will not push, deploy, create a GitHub repo/token/Render service, or touch your live service.
