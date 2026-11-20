> **Post-deploy note:** V4 was deployed by the user at `97d767a`; V5 was later deployed at `a567ed0`. See `DEPLOY-V5-STATUS.md` for the current live status. This report retains its original pre-deploy wording below.

# Report: V4 VM integrity verification + opaque decoy traps

Generated 2026-11-19T07:53:19.786964+00:00. Status: **implemented locally, full suite ALL GREEN, not deployed**.

## A. What was built

- `obf/vm/integrity.py`: a **private, build-time canonical manifest** (`canonical_bytes`) covering bytecode, encoded stream, fragment blobs, constant slices, opcode maps (real + decoy), dispatch coefficients, layout profile and per-node coefficients. It is folded into seven per-domain checksums plus a global digest (`plan_digests`), salted by a randomized per-build `integrity_salt`. The manifest is never emitted.
- Distributed **bounded window checks** (`INTEGRITY_WINDOW = 96`) hash a fixed prefix of seven high-entropy markers and fold `byte/fragment -> ok_byte`, `word -> ok_word`, `node -> ok_node`, `eval/constant -> ok_eval`, `exec -> ok_exec`. Only `for j = 1, 96` loops; no `while`, no unbounded work. A real-decoder mismatch sets an `ok_*` flag false and the decoder returns a **harmless default** (`0`/`nil`) — no error, no hang.
- `obf/vm/traps.py`: an **inert, never-called** table of opaque decoy handlers. A guessed (wrong) capability ticket deterministically raises `error(<opaque const>)`; the unguessable build-time valid ticket returns a harmless default. Decoy keys are disjoint from real opcodes. No `while true do`, no environment poisoning, no debug hooks, no double VM, no legacy `anti_env`/`anti_tamper`.
- `obf/entropy.py`: symbol-soup markers in valid long-bracket and mixed-escape quoted literals (never `loadstring`-ed).
- `obf/pipeline.py` wires `prepare_v4` when `opts.vm and opts.integrity`; the private `V4Plan` is attached to `Result.v4` for tests/reports.
- Compact identifiers were made collision-safe: single letters and all hard-coded raw locals are reserved, and reserved boot locals (`env`/`alias`) use long distinctive names. This fixed the `attempt to index number with number` shadowing that appeared when compact names were introduced.
- Entropy padding is clamped against the **exact zero-padding base** of each build, so the `<=15%` output-size gate holds at the canonical seed and no build is enlarged past `max(fixed_gate, own_base)`.

## B. Verification (real measurements)

| Preset | Manifest | Decoys | Wrong-ticket errors | Valid-ticket defaults | Window clean | Window tampered | Decoder tamper | Scanner |
|---|---:|---:|---:|---:|---|---|---|---:|
| light | 10,540 B | 8 | 104 | 8 | OK_TRUE | OK_FALSE | rc=0 (no error) | 0 |
| medium | 23,299 B | 24 | 312 | 24 | OK_TRUE | OK_FALSE | rc=0 (no error) | 0 |
| heavy | 219,745 B | 64 | 832 | 64 | OK_TRUE | OK_FALSE | rc=0 (no error) | 0 |

- `tests/vm_integrity_v4.py`: **87 checks, 0 failures**. Includes digest determinism, single-byte tamper detection, decoy probe (`HANG=0`), bounded-window static guards, clean/tampered/quoted window probes, real-decoder harmless default, no bare globals, no dynamic loader, decoy/real-opcode disjointness.
- `tests/high_entropy_v4.py`: **124 checks, 0 failures**.
- No bare `error(` / `bit32.bxor` / `type(` / `string.byte` survive in shipped chunks (all alias-rewritten): light=0, medium=0, heavy=0 total bare occurrences across all presets.
- Full suite: `96 + 32 + 12 + 12 + 6 + 6 + 16 + 8 + 3 + 13 + 87 + 124` checks, **0 failure(s), ALL GREEN**. A fresh benchmark run taken during report generation measured light 150,608 / medium 211,588 / heavy 659,712 B, startup heavy median 29.55 ms, runtime overhead median 496.8x (budget 650x). Sizes are deterministic; wall-time overhead varies run-to-run (the full-suite run and this report each reported a different value, both well under the 650x budget).

## C. Caps (`raise_both`, conservative future-proofing)

`OBF_MAX_PUBLISH` 8 MiB -> **16 MiB (16777216)**, `OBF_MAX_BODY` 16 MiB -> **32 MiB (33554432)** in `render.yaml`, `render-large-source.env.example`, `obf/publish.py`, `obf/web.py`, and `LOADSTRINGS.md` / `DOWNLOADS-AND-DEPLOY.md` / `WINDOWS-STEP-BY-STEP.md`. `OBF_MAX_SOURCE=262144`, `OBF_TIMEOUT`, presets/aliases, `OBF_API_KEY`, `OBF_GITHUB_*`, the hard-coded 8 MiB identify cap and `OBF_MAX_IDENTIFY` are unchanged. The user sets the new Render Environment values manually after pushing updated code.

## D. Scope and limitations (no overclaim)

Core integrity = bytecode + constants + dispatch only; there is no full runtime attestation, no helper-identity/ticket expansion beyond the existing checks, and no claim of defeating a third-party dumper or environment logger 100% of the time. Client scripts remain recoverable to an analyst who executes/debugs them; runtime observation of output strings is unavoidable. These are obfuscation decoys, not a security boundary. Official Luau `debug.getupvalue/getinfo/sethook` are nil, so this is not a certification of Roblox executor behaviour. No red-team benchmark, commercial-superiority proof, 100% decompile-proof claim, or live executor certification is made.

## E. Delivery state

Implemented locally and fully tested. No commit, push, GitHub repo, remote, token, Render service, bundle rebuild, checksum refresh or download-link change was performed (deployment was not requested). The existing 03:29 UI-cleanup bundles/links remain the current downloadable artifacts; the v4 code is not yet in them.
