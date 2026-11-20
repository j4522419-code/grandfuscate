# Report: V7 custom-key encryption / whitening layer

Status: **built and verified locally. Not committed, pushed, bundled, uploaded
or deployed.** The live Render service is still V5 at `a567ed0`
(`DEPLOY-V5-STATUS.md`). V6 anti-enumeration remains proposal-only
(`PLAN-anti-enumeration-v6.md`). No deploy bundles, SHA256SUMS, public links,
Render environment values, Git remotes, commits, pushes or connector actions
were changed for V7.

The user originally chose `plan_only`, then explicitly reversed it with
**"Build it"**. This report covers the local implementation.

## 1. What was requested, and the first correction

The user's choices were:

- use the pasted 78-character custom string as an **encryption key**, not a
  visible alphabet or watermark;
- use "SHA-256 or whatever the strongest one is";
- let the assistant pick the rollout → **opt-in, default off**.

SHA-256 is a **hash**, not encryption. It cannot decrypt anything. "Strongest"
also has to respect this project's hard constraints: valid Luau, no
`loadstring` / dynamic loader, no extra comments beyond the required top banner,
no raw punctuation outside literals, default off, and the existing `<=15%` size
gate. A full named AEAD
(ChaCha20-Poly1305 / AES-256-GCM) is the cryptographic gold standard but would
need a larger pure-Luau runtime and an audit. It was **not** built.

**Delivered primary design:**

| Role | Algorithm |
|---|---|
| Key derivation | HKDF-SHA256 from passphrase + per-build salt + build id / preset / seed |
| Encryption-style whitening | ChaCha20 stream cipher |
| Authentication | HMAC-SHA256, encrypt-then-MAC over `aad .. nonce .. ciphertext` |
| Hash primitive | SHA-256 inside HKDF/HMAC and the pure-Luau runtime |

This is **not** unbreakable encryption. The derived 32-byte key is embedded in
the emitted chunk as an escaped byte literal. Anyone who can read or hook the
chunk can recover it. V7 is therefore **obfuscation and tamper detection**, not
confidentiality. It does not stop dumps, erase running code, crash external
env-loggers, or certify any Roblox executor.

## 2. Custom string handling

- The user's 78-character string was pasted into chat, so it is treated as
  **public**. It is **not** hardcoded in any workspace file, test, bundle or
  emitted chunk.
- Tests use a separate synthetic passphrase
  (`v7 synthetic test passphrase 2026`).
- With `crypto=true`, the caller supplies key bytes through CLI `--key-text` /
  `--key-file` or API `key_text`.
- The derived key, per-build salt, nonces, tags and AAD are emitted as escaped
  byte literals. The raw passphrase is never emitted verbatim, and private
  key files store only hashes (`crypto_passphrase_sha256`,
  `crypto_key_sha256`), never the raw key material.
- If `crypto=true` and no key is supplied, the build derives from the seed only
  and is explicitly labelled `crypto_key_source = "seed"`: **convenience
  whitening**, not passphrase encryption.

## 3. What is encrypted

We do **not** encrypt Luau source text and then compile it — that would need a
forbidden dynamic loader. Instead, the build keeps the valid Luau skeleton and
whitens the byte payloads that were already shipped as escaped literals in
chunk getters:

- every constant-pool slice's encoded blob and key;
- every VM instruction-stream fragment's encoded blob and key;
- the inert high-entropy padding bytes that live inside those pool slices.

The runtime emits one small pure-Luau decryptor prelude. Each lazy chunk getter
assembles ciphertext; `DECRYPT(nonce, aad, tag, ciphertext)` verifies the
HMAC tag and returns the original plaintext bytes to the existing VM. There is
no `loadstring`, no `load`, no `require`, no comments beyond the required top
banner, and no second contiguous copy of each ciphertext literal.

The AAD binds each payload to:

- fixed domain string `grandfuscate-v7`;
- build id, preset, seed;
- payload domain (`pool` / `vm`) and slice/fragment index;
- salt and plaintext length;
- the private V4 integrity digest and expected hash.

The nonce is authenticated separately in the MAC input, so swapping it fails
verification. Tag failure uses the existing harmless-default philosophy: the
affected slice/fragment becomes unavailable instead of trying to crash a
third-party process. V6's proposed `lockdown` latch is not wired here.

## 4. Core surface and local hosted override

| Surface | Delivered |
|---|---|
| CLI | `--crypto`, `--key-text "<passphrase>"`, `--key-file <path>` |
| Library options | `Options(crypto=True, key_text=..., key_file=...)`; default off |
| Output banner | first line is exactly `--protected by grand6_7 (on discord)` |
| Local hosted website | forces `crypto=True`, seed-only; ignores client `crypto`, `key_text`, `key_file` |
| API safety | the web API does not resolve server-side `key_file` paths |
| Meta | `defaults.crypto = true`; no `key_text_max` is exposed |
| Stats | `crypto`, `crypto_alg`, `crypto_key_source`, `crypto_bytes`, `crypto_payloads`, `crypto_tag_ok` |
| Keys | hashes and public stats only; no raw passphrase / derived-key hex |
| Default | CLI/library `crypto=false` body stays V5-identical; local website is always V7 |

Example local CLI:

```powershell
python -m obf.cli --preset medium --seed 20261118 --crypto `
  --key-file .\my-private-key.bin --verify -o protected.luau .\input.luau
```

`--key-text` works too, but it can land in shell history; `--key-file` is the
better choice for a real secret. Do not paste a real key into chat.

Example local website request body — V7 is forced on, so no crypto or key
fields are needed:

```json
{
  "source": "print(\"Hello World!\")",
  "preset": "medium",
  "seed": 20261118
}
```

## 5. Implementation notes

- `obf/crypto.py` — Python-side HKDF-SHA256, ChaCha20, HMAC-SHA256,
  encrypt-then-MAC plan, build-time verification, chunk helpers.
- `obf/vm/crypto_runtime.py` — emits pure-Luau SHA-256, HMAC-SHA256,
  ChaCha20 block/stream, and `DECRYPT`. Rotations/shifts use exact double
  arithmetic and the existing `bit32.bxor` / `band` / `bor` aliases, so
  `obf/format.py` and `obf/names.py` stay at their V5 state. Hard-coded local
  names are prefixed before `_rename_locals` runs, avoiding collisions with
  generated one/two-character identifiers.
- `obf/runtime.py` — one decryptor prelude plus encrypted pool-slice chunks.
- `obf/vm/fragments.py` — encrypted VM fragment chunks.
- `obf/pipeline.py` — creates the plan after V4 integrity is computed, binds
  AAD to the integrity digest, exposes `Result.crypto`, and records ciphertext
  material / hashes in private keys and stats.
- `obf/render.py`, `obf/web.py`, `obf/cli.py` — options, API, meta and CLI.
- `obf/banner.py`, `obf/pipeline.py`, `obf/publish.py` — required first-line
  Luau comment on generated chunks and the separate loadstring wrapper.
- `web/index.html` — local preview with V7 forced on; no key field, opt-in,
  note or build-status text.
- `tests/crypto_v7.py` — 248 standalone checks.
- `tests/run_tests.py` — §31 confirms V6 is still proposal-only; §32 runs V7.

CLI/library default builds take no new RNG draws, allocate no new runtime
names, and emit no extra lines, so the `crypto=false` protected body (after
stripping the fixed 37-byte top banner) is byte-for-byte compatible with
deployed V5. The local hosted website overrides that default and always uses
`crypto=true` with seed-only derivation.

## 6. Measured sizes

Source: `print("Hello World!")`, synthetic test passphrase from
`tests/crypto_v7.py`. Sizes below are protected-body bytes after stripping the
required 37-byte top banner; every full output file is exactly +37 bytes.
The default body column matches deployed V5.

| Preset | Seed | V5 default B | V7 crypto B | Overhead B | Fixed `<=15%` gate B | Within gate |
|---|---:|---:|---:|---:|---:|:---:|
| light | 11 | 144,932 | 152,467 | +7,535 | 179,903 | yes |
| light | 24301 | 166,006 | 168,481 | +2,475 | 179,903 | yes |
| light | 20261118 | 147,851 | 155,867 | +8,016 | 179,903 | yes |
| medium | 11 | 207,547 | 211,683 | +4,136 | 225,877 | yes |
| medium | 24301 | 211,651 | 211,706 | +55 | 225,877 | yes |
| medium | 20261118 | 209,285 | 211,690 | +2,405 | 225,877 | yes |
| heavy | 11 | 653,168 | 659,766 | +6,598 | 702,493 | yes |
| heavy | 24301 | 659,690 | 659,704 | +14 | 702,493 | yes |
| heavy | 20261118 | 657,312 | 659,710 | +2,398 | 702,493 | yes |

The exact zero-padding base is measured with crypto enabled, so the V4 entropy
budget shrinks where needed. All nine measured builds stay under the fixed
gate. The canonical seed `20261118` overhead is +8,016 / +2,405 / +2,398 B for
light / medium / heavy.

## 7. Verification

Standalone:

```
CRYPTO-V7: ALL GREEN (248 checks)
```

Full suite (`TEST-RESULTS-v7-full-suite.txt`, rerun after the banner change):

```
banner + return          OK
refreshed artifacts      OK
loadstring publisher     OK       13 checks
vm integrity v4          OK       87 integrity/trap checks
high entropy v4          OK       124 entropy/gate checks
stealth v5               OK       92 active-decoy checks
v6 proposal-only         OK       3 boundary checks
crypto v7                OK       248 crypto checks
...
ALL GREEN
RC=0
```

Covered by `tests/crypto_v7.py`:

- RFC 8439 §2.4.2 ChaCha20 known-answer vector;
- RFC 5869 HKDF-SHA256 test case 1;
- standard HMAC-SHA256 and SHA-256(`abc`) vectors;
- pure-Luau SHA-256 / HMAC-SHA256 / ChaCha20 / `DECRYPT` known-answer probe;
- all byte values 0–255, ten payload lengths (including 0, 63, 64, 65, 128,
  129, 256, 771), and multiple seeds;
- tampered ciphertext / nonce / tag / AAD / salt, and wrong passphrase, all
  rejected;
- CLI/library `crypto=false` protected bodies are byte-identical to deployed
  V5 for nine preset/seed pairs after stripping the required top banner;
- every output starts with the exact required Luau banner comment;
- `crypto=true` builds parse with `luau-compile`, run `Hello World!` with the
  official Luau interpreter, stay under the size gate, have a `return`-first
  protected body, contain no other comments, no `loadstring`, no bare
  forbidden globals, no raw `!` or `@` outside literals, and produce zero
  `AA.scan_output` findings;
- CLI / API / meta flags default off; API `key_file` cannot read server paths;
  CLI rejects `--key-text` + `--key-file` together.

## 8. Boundaries and non-claims

- **SHA-256 is a hash, not a cipher.** HKDF-SHA256 derives a key;
  HMAC-SHA256 authenticates; ChaCha20 is the actual stream cipher.
- **Embedded key = no real secrecy.** This is obfuscation / tamper detection,
  not confidentiality. A dumper can read the escaped ciphertext and key,
  hook the decryptor, or snapshot decrypted bytes in memory.
- No claim of 99% literal share, "unbreakable", commercial superiority,
  live Roblox executor certification, total dumper/env-logger defeat, or
  crashing a third-party logger process.
- No `loadstring`, no dynamic loader, no comments beyond the required top
  banner, no raw punctuation outside literals, no bare forbidden globals.
  `anti_env` / `anti_tamper` remain off.
- V6 is still proposal-only; V7 does not implement its active-enumeration
  `lockdown` latch or `min_objects` VM path.
- Optional named AEAD (ChaCha20-Poly1305 / AES-256-GCM) was **not** built.
- V5's exposed `OBF_API_KEY` rotation warning from `DEPLOY-V5-STATUS.md` is
  still outstanding and unrelated to V7. No key is stored in these V7 files.

## 9. Local test site

A local V7-enabled web preview is running on port `8000`. Per the latest user
request, the UI has **no V7 key text field, no V7 crypto opt-in checkbox, no
"V7 embeds a derived key" note, and no "V7 crypto ON" status line**. V7 crypto
is forced on for every website build with **seed-only** derivation. The web API
ignores any client-supplied `crypto`, `key_text`, or `key_file`.

Verified on the local site:

- `/api/meta`: `defaults.crypto=true`, no `key_text_max`, `requires_api_key=false`;
- `/` contains none of the removed V7 labels/controls/status strings, while its
  `collect()` still sends `crypto: true`;
- `/api/obfuscate` with `crypto:false` and stray `key_text`/`key_file` returns
  `ok=true`, `syntax.ok=true`, `stats.crypto=true`,
  `crypto_key_source=seed`, `crypto_bytes=13005`, `crypto_tag_ok=true`,
  `output_len=211779`, first line exactly
  `--protected by grand6_7 (on discord)`, `return`-first protected body, no
  other comments, no `loadstring`, and no raw key text;
- the returned output runs `Hello World!` with the official Luau interpreter
  (rc 0, empty stderr);
- `/api/obfuscate` with no `crypto` field also returns `stats.crypto=true`,
  `crypto_key_source=seed`, and the same 211,779-byte output;
- the separate loadstring wrapper also starts with the same banner;
- the CLI/library `crypto=false` protected body remains byte-compatible with
  deployed V5 after stripping the banner, but the local website no longer
  offers that default;
- V7 standalone `crypto_v7.py` remains 248 checks / ALL GREEN and the full
  suite was rerun after the banner change: `ALL GREEN`, `0 failure(s)`, `RC=0`.

This is a **local preview only**, not the public Render service. No API key is
required on this local instance. The CLI still supports `--crypto`,
`--key-text`, and `--key-file` for local advanced use.

## 10. Deployment state

No V7 commit, push, remote change, bundle rebuild, SHA/link refresh, upload,
Render deploy, connector action, or token was performed. Local HEAD is still
`68592e7`; remotes remain 0. The user's GitHub `main` and live service are V5
`a567ed0`. If V7 should go live later, that needs a separate explicit request,
fresh deployment packages, a new commit/push by the user, and a fresh live
smoke test.
