# Plan: V7 custom-key encryption / whitening layer

Status: **IMPLEMENTED LOCALLY — not committed, pushed, bundled or deployed.**
V5 remains the live deployment at `a567ed0` (`DEPLOY-V5-STATUS.md`); V6
anti-enumeration lockdown remains a separate proposal
(`PLAN-anti-enumeration-v6.md`). The user's `plan_only` choice was reversed by
"Build it", so the opt-in layer described below is now in the local workspace.
The local hosted website was later changed to force V7 on with seed-only
derivation and no key/checkbox/status UI; the CLI/library default remains off.
Every output now starts with the required `--protected by grand6_7 (on discord)`
Luau comment, so the old zero-comment / byte-0 `return` policy is superseded by
"banner first, then return-first protected body".

User choices from the clarifying questions:

- **Use of the 78-character custom string:** as an **encryption key**, not as a
  visible alphabet or watermark.
- **Encryption:** "SHA-256 or whatever the strongest one is".
- **Rollout:** assistant picks → **opt-in, default off**.
- **Next step:** originally `plan_only`, then explicitly reversed by "Build it".

## 1. First correction: SHA-256 is not encryption

SHA-256 is a hash. It cannot encrypt/decrypt. It can be used as a building
block:

- **HKDF-SHA256** — derive a 256-bit key from the custom string + salt + build id.
- **HMAC-SHA256** — authenticate the ciphertext (encrypt-then-MAC).
- **SHA-256 counter-mode keystream** — possible but homebrew; not the first pick.

"Strongest" here has to respect the existing constraints: valid Luau, no
dynamic loader / `loadstring`, no comments beyond the required top banner,
no raw punctuation outside literals, default off, and the `<=15%` size gate.
A full AEAD such as AES-256-GCM or
ChaCha20-Poly1305 is the cryptographic gold standard, but a pure-Luau
implementation is large and would need an audit.

**Chosen primary design:** `HKDF-SHA256` key derivation +
`ChaCha20` stream cipher + `HMAC-SHA256` authentication (encrypt-then-MAC).
It uses SHA-256, is feasible with `bit32`, gives both encryption-style
whitening and tamper detection, and is much smaller than a full GCM/Poly1305
implementation. Optional phase 2 can upgrade to a named AEAD if the size budget
and audit allow.

This is **not** a claim of unbreakable encryption. With the key embedded in the
chunk, it is obfuscation, not confidentiality.

## 2. What is encrypted

We do **not** encrypt the Luau source text itself — that would need a loader to
compile decrypted source, which is forbidden. Instead:

1. Build the existing V5/V6 output as usual.
2. Identify the **inert high-entropy padding bytes**, the **encoded VM stream**,
   and the **constant-pool byte payloads** that are already emitted as escaped
   string/byte literals.
3. Encrypt those byte arrays at build time.
4. Emit the **ciphertext**, nonce, salt, derived key material and HMAC tag as
   opaque escaped literals.
5. At runtime, decrypt them back into the same byte tables the VM already uses.

The Luau skeleton stays valid source. No `loadstring`, no dynamic loader, no
comments, no raw `!@^&#%...` outside string literals.

## 3. Key handling

- The 78-character custom string is treated as **passphrase bytes** (UTF-8).
- Build-time KDF: `key = HKDF-SHA256(passphrase, salt, info, 32)` where `info`
  includes preset, seed, build id and a fixed domain string.
- `salt` and `nonce` are random per build (derived from the build RNG), embedded
  as escaped bytes.
- We ship the **derived 32-byte key**, not the passphrase string itself, so the
  custom text does not appear verbatim in dumps.
- Because that derived key is embedded in the chunk, anyone who dumps the chunk
  can recover it. This protects against casual static reading, not against a
  determined analyst.

> Security note: the passphrase was pasted into chat, so treat it as public. For
> any real-secret use, generate a fresh key locally with `--key-file` and never
> share it. A runtime-supplied key (the `runtime_key` option) would be real
> confidentiality, but it changes the API: the chunk cannot run standalone
> without the caller passing the key.

## 4. Core opt-in surface (assistant's rollout choice)

Core flags are **default off**, so V4/V5/V6 builds and their tests stay
unchanged. The local hosted website later overrode this to always-on seed-only:

| Surface | Delivered |
|---|---|
| CLI | `--crypto` plus `--key-text "<passphrase>"` or `--key-file <path>` |
| Core options | `Options(crypto=True, key_text=..., key_file=...)`; not web JSON fields |
| Local website | forces `crypto=True`, seed-only; ignores web `crypto`/`key_text`/`key_file` |
| Config | optional local key file, not committed into bundles |
| Output banner | first line is exactly `--protected by grand6_7 (on discord)` |
| Meta | core `defaults.crypto=false`; local website reports `true` |
| Stats | `crypto`, `crypto_alg`, `crypto_bytes`, `crypto_tag_ok` |
| Alias | none; keep `fail_closed` / `lockdown` separate |

If core `crypto=true` and no key is supplied, derive from the build seed only
and label it explicitly as **convenience whitening**, not passphrase
encryption. The local hosted website is permanently in this seed-only mode.

## 5. Runtime flow

- Emit one small decryptor prelude before the VM/constant tables are consumed.
- It reconstructs the key from embedded material, verifies the HMAC tag over
  `aad || nonce || ciphertext`, then decrypts with ChaCha20 into byte tables.
- `aad` binds the ciphertext to the build id / V4 integrity digest, so swapping
  literals between builds fails verification.
- Tag failure:
  - delivered → harmless-default guard, same philosophy as V4 integrity;
  - V6 `lockdown` is still proposal-only, so no one-shot latch is wired here.
- Decrypted bytes feed the existing VM stream / constant pool exactly as before.

## 6. Custom symbol string

Your choice was **key**, not alphabet/watermark. Therefore:

- `SYMBOL_ALPHABET` stays `!@^&#%$*~?/;:,.`.
- The 78-character string is **not** emitted verbatim.
- Its unsafe characters (`[`, `=`, `\`, `'`, `<`, `>`, etc.) never need to be
  pasted raw into a long-bracket literal, because only derived key bytes are
  emitted, as `\xNN` / `\ddd` escapes.
- If you later also want the exact text visible, that is a separate
  `--watermark` option with escaped-literal encoding and regenerated checksums.

## 7. Standing constraints

- No dynamic loader, no `loadstring`, no comments beyond the required top banner.
- No raw punctuation outside string literals.
- All new globals rewritten through the opaque alias table.
- Default off; `anti_env` / `anti_tamper` stay forced off.
- Preserve the `<=15%` size gate; measure exact zero-padding base with crypto
  enabled. Measured canonical-seed overhead with the synthetic test passphrase
  was +8,016 B (light), +2,405 B (medium) and +2,398 B (heavy); all three
  stayed under the fixed gate.
- No 99% literal-share claim, no "unbreakable", no commercial-superiority claim,
  no live Roblox executor certification, no external logger/dumper crash claim.

## 8. Tests / acceptance — DONE

- New `tests/crypto_v7.py` (248 standalone checks) + `tests/run_tests.py` §32.
- RFC 8439 ChaCha20, RFC 5869 HKDF-SHA256, standard HMAC/SHA-256 vectors;
  pure-Luau SHA-256 / HMAC-SHA256 / ChaCha20 / DECRYPT known-answer probe.
- Round-trip: every byte value 0–255, ten lengths, three seeds.
- Tamper a ciphertext byte, nonce, salt, tag, AAD, or use a wrong passphrase →
  HMAC verification fails.
- CLI/library `crypto=false` protected bodies are byte-for-byte identical to
  deployed V5 output for nine preset/seed combinations after stripping the
  required top banner.
- `crypto=true` builds parse, run `Hello World!`, stay under the `<=15%` gate,
  contain no bare forbidden globals, no `loadstring`, no comments beyond the
  required top banner and no raw punctuation outside literals.
- Full suite after the banner change: `ALL GREEN`, 0 failures
  (`TEST-RESULTS-v7-full-suite.txt`).
- `REPORT-crypto-v7.md` states: embedded-key encryption is obfuscation, not
  confidentiality.

## 9. Files actually touched

- New `obf/crypto.py` — HKDF-SHA256, ChaCha20, HMAC-SHA256, build-time plan.
- New `obf/vm/crypto_runtime.py` — pure-Luau decryptor emitter.
- `obf/render.py` — `crypto`, `key_text`, `key_file` options, default off.
- `obf/pipeline.py` — plan creation, AAD bound to V4 integrity digest, private
  key/stats fields, `Result.crypto`.
- `obf/runtime.py` — one decryptor prelude and encrypted pool-slice chunks.
- `obf/vm/fragments.py` — encrypted VM-instruction-stream chunks.
- `obf/web.py` — local website forces `crypto=True`, seed-only; it ignores
  client `crypto`/`key_text`/`key_file`, exposes no `key_text_max`, and no
  server-side `key_file` path is accepted.
- `obf/cli.py` — `--crypto`, `--key-text`, `--key-file`, conflict guard.
- `obf/banner.py`, `obf/pipeline.py`, `obf/publish.py` — required first-line
  Luau comment on generated chunks and the separate loadstring wrapper.
- `web/index.html` — local preview with V7 forced on; no key field, opt-in,
  note or build-status text.
- `obf/chunks.py`, `obf/vm/runtime.py` — honest docstring updates.
- `tests/anti_analysis.py`, `tests/stealth_v5.py` — stronger forbidden-chain
  checks; `tests/run_tests.py` — meta default, §31 V6 proposal-only, §32 V7.
- New `tests/crypto_v7.py`, `TEST-RESULTS-crypto-v7.txt`,
  `TEST-RESULTS-v7-full-suite.txt`, `REPORT-crypto-v7.md`, this plan.
- `obf/format.py` and `obf/names.py` were deliberately left at their V5 state:
  the decryptor uses only existing alias paths, so default output stays
  body-byte-compatible after stripping the banner. `obf/entropy.py`,
  `obf/pool.py` and `obf/vm/integrity.py`
  were not changed.

## 10. Why this does not "stop dumps"

A dumper can still:

- read the escaped ciphertext literals,
- read the embedded key/salt/nonce,
- hook the decryptor and capture the decrypted byte tables,
- snapshot process memory after decryption.

So V7 changes the **static text** from readable-looking encoded bytes to
ciphertext-looking bytes and adds tamper detection. It does not erase the code.
V6 lockdown is still the right layer for active env-logger enumeration;
server-side execution is still the only real guarantee against client dumps.

## Current state / optional next steps

V7 is built and verified locally. It is **not** committed, pushed, rebuilt into
the deployment bundles, uploaded, or deployed; the live service is still V5.
The optional named-AEAD phase (ChaCha20-Poly1305 / AES-256-GCM) was not built,
because the chosen primary design was HKDF-SHA256 + ChaCha20 + HMAC-SHA256.
If you later want a deployment package or a full AEAD upgrade, ask for that
explicitly; both would need fresh measurements and an audit.
