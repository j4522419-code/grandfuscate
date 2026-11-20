"""V7 opt-in custom-key encryption / whitening verification.

Imported by ``tests/run_tests.py`` (section 32) and runnable standalone:
``python3 tests/crypto_v7.py``.

Checks:

* RFC 8439 ChaCha20, RFC 5869 HKDF-SHA256 and standard HMAC/SHA-256 vectors;
* the emitted pure-Luau SHA-256 / HMAC-SHA256 / ChaCha20 / DECRYPT routines;
* every byte value, multiple lengths, multiple seeds and build-time tag checks;
* tampered ciphertext / nonce / tag / AAD / salt and wrong passphrase fail;
* ``crypto=False`` protected bodies stay byte-compatible with deployed V5
  output after stripping the required top banner;
* every output starts with the required Luau banner comment;
* ``crypto=True`` builds parse, run ``Hello World!``, stay under the ``<=15%``
  size gate, and contain no bare forbidden globals, dynamic loader, extra
  comments or raw punctuation outside literals;
* CLI / API / meta opt-in surface is default off.

Hard boundary: the derived key is embedded. This is obfuscation and tamper
detection, not confidentiality, and it does not stop dumps.
"""
from __future__ import annotations

import hashlib
import hmac as std_hmac
import json
import os
import random
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from obf import ast as A  # noqa: E402
from obf.banner import BANNER_BYTES, BANNER_TEXT, strip_banner  # noqa: E402
from obf import crypto as CR  # noqa: E402
from obf import minify, pipeline, web  # noqa: E402
from obf.cli import build_parser  # noqa: E402
from obf.crypto import CryptoPlan  # noqa: E402
from obf.names import Names  # noqa: E402
from obf.pool import lua_bytes_literal  # noqa: E402
from obf.vm import crypto_runtime as CRT  # noqa: E402
from obf.vm import integrity as IN  # noqa: E402
from tests import anti_analysis as AA  # noqa: E402
from tests.high_entropy_v4 import _structural_bytes  # noqa: E402
from tests.stealth_v5 import _name_tokens  # noqa: E402

SRC = b'print("Hello World!")'
EXPECTED = b"Hello World!\n"
PRESETS = ("light", "medium", "heavy")
SEEDS = (11, 0x5EED, 20261118)
BUILD_SEEDS = (11, 20261118)
# Synthetic test key material. The user's pasted 78-character string is public
# and is deliberately not stored in this file or emitted by any build.
PASSPHRASE = b"v7 synthetic test passphrase 2026"
KEY_TEXT = PASSPHRASE.decode("utf-8")

# Exact output SHA-256 of deployed V5 commit a567ed0 for SRC, preset and seed.
V5_BASELINE_SHA = {
    ("light", 11): "a043ae92e2b5549fe1d2d952713f2ea0e6c42b9d39c7d6853facbbe5bdfa2396",
    ("light", 0x5EED): "67a3b72709848bd90d8bcb44e9ef669062c626d1ce0e31c5aff20d7b6614d5b3",
    ("light", 20261118): "a8e8628aeb7b7c0a9a97afe37cc650b1fbf83829ea56a4f2afb94c2b8a20b7f6",
    ("medium", 11): "8b6da16bcd2128c069f9a4763688b840936f467e54002cd0f6c7443e29542b53",
    ("medium", 0x5EED): "883fcf7d57b76b6f565f08ccf36c5440298a9f5e1fc5d27f1b03deee73157570",
    ("medium", 20261118): "6e43f58b75de9fdc8e01ef3b091423d55a6dca3cff5ca35d35e76a5fbe1d54c4",
    ("heavy", 11): "8133d5619784b25d487559b57a342529720200b2ed8f13d2eb3f38fa0eedc1ea",
    ("heavy", 0x5EED): "1b5ca59bb0ed8336ff17d6a58998b5039eedb342cfe5ac6112c8c5c278a2bc41",
    ("heavy", 20261118): "3eabfa232f5d881acbfb3b80b0b169d0d1e3ed0e20592fe5e30e1a0eee05508f",
}

CHA_KEY = bytes(range(32))
CHA_NONCE = bytes.fromhex("000000000000004a00000000")
CHA_PT = (
    b"Ladies and Gentlemen of the class of '99: If I could offer you only "
    b"one tip for the future, sunscreen would be it."
)
CHA_CT = bytes.fromhex(
    "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
    "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
    "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937"
    "365af90bbf74a35be6b40b8eedf2785e42874d"
)
HMAC_KEY = b"key"
HMAC_MSG = b"The quick brown fox jumps over the lazy dog"
HMAC_EXPECTED = bytes.fromhex(
    "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
)
HKDF_IKM = bytes.fromhex("0b" * 22)
HKDF_SALT = bytes.fromhex("000102030405060708090a0b0c")
HKDF_INFO = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
HKDF_EXPECTED = bytes.fromhex(
    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
    "34007208d5b887185865"
)

HEX_FN = """local function hex(s)
  local t = {}
  for i = 1, #s do t[i] = string.format("%02x", string.byte(s, i)) end
  return table.concat(t)
end
"""

FORBIDDEN_NAMES = {
    "error", "coroutine", "yield", "setmetatable", "tostring", "pcall",
    "rawset", "pairs", "loadstring", "load", "require",
    "bit32", "string", "table", "math",
}


def check(failures: list[str], condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


def _luau(script: str, timeout: int = 180) -> tuple[int, str, str]:
    exe = A.tool_path("luau")
    fd, path = tempfile.mkstemp(suffix=".luau")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(script)
        p = subprocess.run([exe, path], capture_output=True, text=True,
                           timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _run_output(data: bytes, timeout: int = 120) -> tuple[int, bytes, bytes]:
    exe = A.tool_path("luau")
    fd, path = tempfile.mkstemp(suffix=".luau")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        p = subprocess.run([exe, path], capture_output=True, timeout=timeout)
        return p.returncode, p.stdout.replace(b"\r\n", b"\n"), p.stderr
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _parse_kv(out: str) -> dict[str, str]:
    vals: dict[str, str] = {}
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) == 2:
            vals[parts[0]] = parts[1]
    return vals


def _info(preset: str, seed: int, build_id: str) -> bytes:
    return b"|".join([
        CR.DOMAIN,
        preset.encode("ascii"),
        str(seed).encode("ascii"),
        build_id.encode("ascii"),
    ])


def _known_answer_python(failures: list[str]) -> int:
    checks = 0
    check(failures, CR.chacha20_xor(CHA_KEY, CHA_NONCE, CHA_PT, 1) == CHA_CT,
          "crypto-v7: RFC 8439 ChaCha20 vector mismatch"); checks += 1
    check(failures, CR.chacha20_xor(CHA_KEY, CHA_NONCE, CHA_CT, 1) == CHA_PT,
          "crypto-v7: ChaCha20 is not invertible"); checks += 1
    check(failures, CR.hmac_sha256(HMAC_KEY, HMAC_MSG) == HMAC_EXPECTED,
          "crypto-v7: HMAC-SHA256 known-answer mismatch"); checks += 1
    check(failures, CR.hmac_sha256(HMAC_KEY, HMAC_MSG) ==
          std_hmac.new(HMAC_KEY, HMAC_MSG, hashlib.sha256).digest(),
          "crypto-v7: HMAC-SHA256 disagrees with stdlib"); checks += 1
    check(failures, CR.hkdf_sha256(HKDF_IKM, HKDF_SALT, HKDF_INFO, 42) ==
          HKDF_EXPECTED,
          "crypto-v7: RFC 5869 HKDF-SHA256 vector mismatch"); checks += 1
    check(failures, hashlib.sha256(b"abc").hexdigest() ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
          "crypto-v7: SHA-256 known-answer mismatch"); checks += 1
    return checks


def _known_answer_luau(failures: list[str]) -> int:
    checks = 0
    probe = CryptoPlan(
        key=CHA_KEY,
        salt=b"\x00" * CR.SALT_BYTES,
        build_id="v7probe00000001",
        preset="medium",
        seed=1,
        key_source="probe",
        passphrase_sha256="",
        payloads=[],
    )
    lines = CRT.emit_crypto_lines(probe, Names(123))
    r = probe.runtime
    body = f'''{HEX_FN}
print("SHA_ABC", hex({r.sha_var}("abc")))
print("HMAC_KEY", hex({r.hmac_var}("key", "The quick brown fox jumps over the lazy dog")))
print("CHACHA_PT", hex({r.chacha_var}({probe.key_literal}, {lua_bytes_literal(CHA_NONCE)}, {lua_bytes_literal(CHA_CT)})))
'''
    rc, out, err = _luau("\n".join(lines) + "\n" + body)
    vals = _parse_kv(out)
    check(failures, rc == 0 and not err.strip(),
          f"crypto-v7: Luau primitive probe failed rc={rc} err={err[:160]!r}")
    checks += 1
    check(failures, vals.get("SHA_ABC") == hashlib.sha256(b"abc").hexdigest(),
          "crypto-v7: emitted SHA-256 does not match known answer"); checks += 1
    check(failures, vals.get("HMAC_KEY") == HMAC_EXPECTED.hex(),
          "crypto-v7: emitted HMAC-SHA256 does not match known answer"); checks += 1
    check(failures, vals.get("CHACHA_PT") == CHA_PT.hex(),
          "crypto-v7: emitted ChaCha20 does not match RFC 8439"); checks += 1
    return checks


def _roundtrip_tamper_luau(failures: list[str]) -> int:
    checks = 0
    lengths = [0, 1, 63, 64, 65, 127, 128, 129, 256, 771]
    payloads: list[tuple[str, int, bytes]] = []
    plain: dict[int, bytes] = {}
    for i, n in enumerate(lengths, 1):
        if n == 0:
            pt = b""
        elif n == 771:
            pt = bytes(range(256)) * 3 + b"tail"
        else:
            pt = bytes(((j * 37 + i) & 0xFF) for j in range(n))
        plain[i] = pt
        payloads.append(("probe", i, pt))

    plan = CR.make_crypto_plan(
        PASSPHRASE,
        build_id="v7probe00000002",
        preset="medium",
        seed=42,
        rng=random.Random(7),
        payloads=payloads,
        aad_extra=b"v4-integrity-digest",
    )
    check(failures, CR.verify_plan(plan),
          "crypto-v7: build-time plan verification failed"); checks += 1
    check(failures, len(plan.payloads) == len(lengths),
          "crypto-v7: payload count mismatch"); checks += 1
    check(failures, plan.key_source == "passphrase" and len(plan.key) == 32,
          "crypto-v7: passphrase-derived key missing"); checks += 1
    check(failures, len(plan.salt) == CR.SALT_BYTES,
          "crypto-v7: salt length mismatch"); checks += 1
    for p in plan.payloads:
        check(failures, len(p.nonce) == CR.NONCE_BYTES
              and len(p.tag) == CR.TAG_BYTES,
              f"crypto-v7: nonce/tag length mismatch for {p.domain}/{p.index}")
        checks += 1
        pt = plain[p.index]
        check(failures, p.plaintext_sha256 == hashlib.sha256(pt).hexdigest(),
              f"crypto-v7: plaintext hash mismatch for {p.index}"); checks += 1
        check(failures, CR.chacha20_xor(plan.key, p.nonce, p.ciphertext) == pt,
              f"crypto-v7: Python roundtrip failed for {p.index}"); checks += 1
        check(failures, CR.hmac_sha256(
            plan.key, p.aad + p.nonce + p.ciphertext) == p.tag,
            f"crypto-v7: HMAC tag mismatch for {p.index}"); checks += 1
    check(failures, bytes(range(256)) in plain[10],
          "crypto-v7: all-byte-value fixture missing"); checks += 1

    wrong_info = _info("medium", 42, plan.build_id)
    wrong_key = CR.hkdf_sha256(b"wrong passphrase", plan.salt,
                               wrong_info, CR.KEY_BYTES)
    wrong_plan = CryptoPlan(
        key=wrong_key,
        salt=plan.salt,
        build_id=plan.build_id,
        preset=plan.preset,
        seed=plan.seed,
        key_source="wrong",
        passphrase_sha256="",
        payloads=plan.payloads,
    )
    mutated_salt = plan.salt[:-1] + bytes([plan.salt[-1] ^ 1])
    salt_key = CR.hkdf_sha256(PASSPHRASE, mutated_salt,
                              wrong_info, CR.KEY_BYTES)
    p10 = plan.payload("probe", 10)
    check(failures, CR.hmac_sha256(
        wrong_key, p10.aad + p10.nonce + p10.ciphertext) != p10.tag,
        "crypto-v7: wrong passphrase did not change the HMAC tag"); checks += 1
    check(failures, CR.hmac_sha256(
        salt_key, p10.aad + p10.nonce + p10.ciphertext) != p10.tag,
        "crypto-v7: tampered salt did not change the derived key/tag"); checks += 1

    seed_plans: list[tuple[int, CryptoPlan]] = []
    for seed in (1, 2, 3):
        sp = CR.make_crypto_plan(
            PASSPHRASE,
            build_id=f"v7seed{seed:09d}",
            preset="medium",
            seed=seed,
            rng=random.Random(seed),
            payloads=[("probe", 1, b"seed roundtrip")],
            aad_extra=b"",
        )
        seed_plans.append((seed, sp))
        check(failures, CR.verify_plan(sp),
              f"crypto-v7: seed {seed} plan verification failed"); checks += 1

    ns = Names(456)
    lines = CRT.emit_crypto_lines(plan, ns)
    lines += CRT.emit_crypto_lines(wrong_plan, ns)
    seed_lines: list[str] = []
    for _, sp in seed_plans:
        seed_lines += CRT.emit_crypto_lines(sp, ns)
    lines += seed_lines

    body_parts = [HEX_FN]
    for i in plain:
        p = plan.payload("probe", i)
        body_parts.append(
            f'local pt{i} = {plan.runtime.decrypt_var}('
            f'{p.nonce_literal}, {p.aad_literal}, '
            f'{p.tag_literal}, {p.ciphertext_literal})\n'
            f'print("PT{i}", pt{i} and hex(pt{i}) or "NIL")'
        )
    p = p10
    body_parts.append(f'''local ct = {p.ciphertext_literal}
local nonce = {p.nonce_literal}
local aad = {p.aad_literal}
local tag = {p.tag_literal}
print("GOOD", {plan.runtime.decrypt_var}(nonce, aad, tag, ct) ~= nil)
print("BAD_CT", {plan.runtime.decrypt_var}(nonce, aad, tag, ct:sub(1, #ct - 1) .. string.char(bit32.bxor(string.byte(ct, #ct), 1))) == nil)
print("BAD_NONCE", {plan.runtime.decrypt_var}(nonce:sub(1, 11) .. string.char(bit32.bxor(string.byte(nonce, 12), 1)), aad, tag, ct) == nil)
print("BAD_TAG", {plan.runtime.decrypt_var}(nonce, aad, string.char(bit32.bxor(string.byte(tag, 1), 1)) .. tag:sub(2), ct) == nil)
print("BAD_AAD", {plan.runtime.decrypt_var}(nonce, aad:sub(1, #aad - 1) .. string.char(bit32.bxor(string.byte(aad, #aad), 1)), tag, ct) == nil)
print("WRONG_KEY", {wrong_plan.runtime.decrypt_var}(nonce, aad, tag, ct) == nil)''')
    for seed, sp in seed_plans:
        p = sp.payload("probe", 1)
        body_parts.append(
            f'local sp{seed} = {sp.runtime.decrypt_var}('
            f'{p.nonce_literal}, {p.aad_literal}, '
            f'{p.tag_literal}, {p.ciphertext_literal})\n'
            f'print("SEED{seed}", sp{seed} and hex(sp{seed}) or "NIL")'
        )

    rc, out, err = _luau("\n".join(lines) + "\n" + "\n".join(body_parts))
    vals = _parse_kv(out)
    check(failures, rc == 0 and not err.strip(),
          f"crypto-v7: Luau DECRYPT probe failed rc={rc} err={err[:200]!r}")
    checks += 1
    for i, pt in plain.items():
        check(failures, vals.get(f"PT{i}") == pt.hex(),
              f"crypto-v7: Luau DECRYPT roundtrip failed for length {lengths[i-1]}")
        checks += 1
    for label in ("GOOD", "BAD_CT", "BAD_NONCE", "BAD_TAG", "BAD_AAD",
                  "WRONG_KEY"):
        check(failures, vals.get(label) == "true",
              f"crypto-v7: Luau {label} result was not true")
        checks += 1
    for seed, _ in seed_plans:
        check(failures, vals.get(f"SEED{seed}") == b"seed roundtrip".hex(),
              f"crypto-v7: seed {seed} Luau roundtrip failed")
        checks += 1
    return checks


def _surface(failures: list[str]) -> int:
    checks = 0
    p = build_parser()
    a = p.parse_args([])
    check(failures, a.crypto is False and a.key_text is None and a.key_file is None,
          "crypto-v7: CLI defaults are not off"); checks += 1
    b = p.parse_args(["--crypto", "--key-text", "abc", "in.luau"])
    check(failures, b.crypto is True and b.key_text == "abc",
          "crypto-v7: CLI --crypto/--key-text not accepted"); checks += 1
    c = p.parse_args(["--crypto", "--key-file", "key.bin", "in.luau"])
    check(failures, c.crypto is True and c.key_file == "key.bin",
          "crypto-v7: CLI --key-file not accepted"); checks += 1

    meta = web.meta()
    check(failures, meta["defaults"]["crypto"] is True,
          "crypto-v7: /api/meta default crypto is not always on"); checks += 1
    check(failures, "key_text_max" not in meta["limits"],
          "crypto-v7: /api/meta still exposes a key_text limit"); checks += 1

    # The local hosted website ignores client attempts to disable V7 or pass
    # key material. It is always on and seed-only.
    opts, _, _ = web.build_request({
        "source": SRC.decode("utf-8"),
        "crypto": False,
        "key_text": KEY_TEXT,
        "key_file": "/etc/passwd",
        "seed": 20261118,
    })
    check(failures, opts.crypto is True and opts.key_text is None
          and opts.key_file is None,
          "crypto-v7: website did not force always-on seed-only V7"); checks += 1
    opts2, _, _ = web.build_request({
        "source": SRC.decode("utf-8"),
        "crypto": False,
    })
    check(failures, opts2.crypto is True and opts2.key_text is None
          and opts2.key_file is None,
          "crypto-v7: API crypto=false was not overridden"); checks += 1
    opts3, _, _ = web.build_request({
        "source": SRC.decode("utf-8"),
        "key_text": "ignored",
        "key_file": "/etc/passwd",
    })
    check(failures, opts3.crypto is True and opts3.key_text is None
          and opts3.key_file is None,
          "crypto-v7: API accepted client key material / server key_file")
    checks += 1

    resp = web.do_obfuscate({
        "source": SRC.decode("utf-8"),
        "crypto": False,
        "key_text": KEY_TEXT,
        "seed": 20261118,
        "verify": False,
    })
    check(failures, resp["ok"] is True and resp["stats"]["crypto"] is True
          and resp["stats"]["crypto_key_source"] == "seed",
          "crypto-v7: API obfuscate did not force seed-only V7"); checks += 1
    check(failures, resp["keys"]["crypto"] is True
          and resp["keys"]["crypto_tag_ok"] is True,
          "crypto-v7: API keys missing crypto metadata"); checks += 1
    check(failures, KEY_TEXT not in resp["output"]
          and "loadstring" not in resp["output"],
          "crypto-v7: API output leaked key text or dynamic loader"); checks += 1
    check(failures, any("seed-only" in w for w in resp["warnings"])
          and not any("V7 embeds" in w or "key_text" in w
                      or "V7 crypto ON" in w for w in resp["warnings"]),
          "crypto-v7: API warning still exposed removed UI text")
    checks += 1
    return checks


def _cli_smoke(failures: list[str]) -> int:
    checks = 0
    fd, src_path = tempfile.mkstemp(suffix=".luau")
    with os.fdopen(fd, "wb") as f:
        f.write(SRC)
    fd, key_path = tempfile.mkstemp(suffix=".bin")
    with os.fdopen(fd, "wb") as f:
        f.write(PASSPHRASE)
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    outs: list[bytes] = []
    try:
        for extra in (["--key-text", KEY_TEXT], ["--key-file", key_path]):
            fd, out_path = tempfile.mkstemp(suffix=".luau")
            os.close(fd)
            cmd = [
                sys.executable, "-m", "obf.cli",
                "--preset", "medium", "--seed", "20261118",
                "--crypto", *extra, "--verify", "--quiet",
                "-o", out_path, src_path,
            ]
            p = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True,
                               timeout=180)
            check(failures, p.returncode == 0,
                  f"crypto-v7: CLI failed rc={p.returncode} err={p.stderr[:160]!r}")
            checks += 1
            data = Path(out_path).read_bytes()
            outs.append(data)
            check(failures, data.startswith(BANNER_BYTES)
                  and KEY_TEXT.encode("utf-8") not in data
                  and str(key_path).encode("utf-8") not in data
                  and b"loadstring" not in data,
                  "crypto-v7: CLI output leaked key material or loader"); checks += 1
            ok, msg = pipeline.validate_syntax(data)
            check(failures, ok, f"crypto-v7: CLI output syntax failed: {msg[:120]}")
            checks += 1
            rc, stdout, stderr = _run_output(data)
            check(failures, rc == 0 and stdout == EXPECTED and not stderr,
                  f"crypto-v7: CLI output did not run Hello World! rc={rc}")
            checks += 1
            os.unlink(out_path)
        check(failures, outs[0] == outs[1],
              "crypto-v7: --key-text and --key-file differ for same passphrase")
        checks += 1

        fd, conflict_out = tempfile.mkstemp(suffix=".luau")
        os.close(fd)
        cmd = [
            sys.executable, "-m", "obf.cli", "--crypto",
            "--key-text", "x", "--key-file", key_path,
            "--quiet", "-o", conflict_out, src_path,
        ]
        p = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True,
                           timeout=60)
        check(failures, p.returncode == 2,
              "crypto-v7: CLI did not reject key_text + key_file together")
        checks += 1
        os.unlink(conflict_out)
    finally:
        for path in (src_path, key_path):
            try:
                os.unlink(path)
            except OSError:
                pass
    return checks


def _default_off(failures: list[str]) -> int:
    checks = 0
    for preset in PRESETS:
        for seed in SEEDS:
            opts = pipeline.make_options(preset, seed=seed)
            r = pipeline.obfuscate(SRC, opts)
            body = strip_banner(r.output)
            sha = hashlib.sha256(body).hexdigest()
            check(failures, r.output.startswith(BANNER_BYTES)
                  and opts.crypto is False and r.crypto is None
                  and r.stats.get("crypto") is False,
                  f"crypto-v7: {preset}/{seed} default is not off / missing banner"); checks += 1
            check(failures, sha == V5_BASELINE_SHA[(preset, seed)],
                  f"crypto-v7: {preset}/{seed} protected body is not byte-compatible with V5")
            checks += 1
            off = pipeline.make_options(
                preset, seed=seed, crypto=False, key_text="ignored"
            )
            r2 = pipeline.obfuscate(SRC, off)
            check(failures, r2.output == r.output,
                  f"crypto-v7: {preset}/{seed} explicit crypto=False changed output")
            checks += 1
    return checks


def _crypto_builds(failures: list[str]) -> int:
    checks = 0
    for preset in PRESETS:
        gate = int(IN.V3_BASELINE[preset] * 1.15)
        for seed in BUILD_SEEDS:
            tag = f"{preset}/{seed}"
            opts = pipeline.make_options(
                preset, seed=seed, crypto=True, key_text=KEY_TEXT
            )
            r = pipeline.obfuscate(SRC, opts)
            s = r.stats
            check(failures, s.get("crypto") is True and r.crypto is not None,
                  f"{tag}: crypto plan missing"); checks += 1
            check(failures, s.get("crypto_alg") ==
                  "HKDF-SHA256/ChaCha20/HMAC-SHA256",
                  f"{tag}: unexpected crypto algorithm"); checks += 1
            check(failures, s.get("crypto_key_source") == "passphrase",
                  f"{tag}: key source is not passphrase"); checks += 1
            check(failures, s.get("crypto_bytes", 0) > 0
                  and s.get("crypto_payloads", 0) > 0
                  and s.get("crypto_tag_ok") is True,
                  f"{tag}: crypto statistics missing"); checks += 1
            check(failures, CR.verify_plan(r.crypto),
                  f"{tag}: build-time crypto verification failed"); checks += 1
            check(failures, s.get("anti_env") is False
                  and s.get("anti_tamper") is False,
                  f"{tag}: legacy hardening flags were re-enabled"); checks += 1
            check(failures, len(strip_banner(r.output)) <= gate,
                  f"{tag}: protected body {len(strip_banner(r.output))} exceeds <=15% gate {gate}")
            checks += 1
            check(failures, r.v4 is not None and r.v4.budget is not None,
                  f"{tag}: v4 size-gate budget missing"); checks += 1

            out = r.output
            body = strip_banner(out)
            check(failures, out.startswith(BANNER_BYTES)
                  and body.startswith(b"return")
                  and not any(t.kind == "comment" for t in minify.tokenize(body)),
                  f"{tag}: banner / return entry / no-extra-comment policy broken"); checks += 1
            check(failures, not AA.scan_output(SRC, out, r.keys, r.source_map),
                  f"{tag}: production scanner findings: "
                  f"{AA.scan_output(SRC, out, r.keys, r.source_map)[:2]}")
            checks += 1
            struct = _structural_bytes(out)
            check(failures, b"!" not in struct and b"@" not in struct,
                  f"{tag}: raw symbol soup outside string literals"); checks += 1
            names = _name_tokens(out)
            check(failures, not (names & FORBIDDEN_NAMES),
                  f"{tag}: bare forbidden globals: {sorted(names & FORBIDDEN_NAMES)}")
            checks += 1
            check(failures, b"loadstring" not in out
                  and b"load(" not in out and b"require(" not in out,
                  f"{tag}: dynamic loader present"); checks += 1
            check(failures, KEY_TEXT.encode("utf-8") not in out
                  and r.crypto.key.hex().encode("ascii") not in out,
                  f"{tag}: raw passphrase or derived-key hex leaked"); checks += 1
            check(failures, r.keys.get("crypto_passphrase_sha256") ==
                  hashlib.sha256(PASSPHRASE).hexdigest()
                  and r.keys.get("crypto_key_sha256") ==
                  hashlib.sha256(r.crypto.key).hexdigest(),
                  f"{tag}: private key hashes missing"); checks += 1
            check(failures, KEY_TEXT not in json.dumps(r.keys)
                  and r.crypto.key.hex() not in json.dumps(r.keys),
                  f"{tag}: private keys leaked raw key material"); checks += 1
            p = r.crypto.payload("pool_blob", r.build.slices[0].index)
            check(failures, p.ciphertext_literal.encode("latin-1") not in out
                  and p.ciphertext[:64] not in out,
                  f"{tag}: full ciphertext literal was shipped twice"); checks += 1

            ok, msg = pipeline.validate_syntax(out)
            check(failures, ok, f"{tag}: syntax failed: {msg[:160]}"); checks += 1
            rc, stdout, stderr = _run_output(out)
            check(failures, rc == 0 and stdout == EXPECTED and not stderr,
                  f"{tag}: output did not run Hello World! rc={rc} "
                  f"err={stderr[:120]!r}"); checks += 1

    # Seed-only convenience mode is explicitly labelled and still runs.
    seed_only = pipeline.obfuscate(
        SRC, pipeline.make_options("medium", seed=20261118, crypto=True)
    )
    check(failures, seed_only.stats.get("crypto_key_source") == "seed",
          "crypto-v7: seed-only mode is not labelled"); checks += 1
    check(failures, CR.verify_plan(seed_only.crypto),
          "crypto-v7: seed-only plan verification failed"); checks += 1
    rc, stdout, stderr = _run_output(seed_only.output)
    check(failures, rc == 0 and stdout == EXPECTED and not stderr,
          "crypto-v7: seed-only output did not run Hello World!"); checks += 1
    with_key = pipeline.obfuscate(
        SRC, pipeline.make_options(
            "medium", seed=20261118, crypto=True, key_text=KEY_TEXT
        )
    )
    check(failures, seed_only.crypto.key != with_key.crypto.key,
          "crypto-v7: passphrase did not change derived key"); checks += 1
    check(failures, seed_only.output != with_key.output,
          "crypto-v7: passphrase did not change output"); checks += 1
    return checks


def run(failures: list[str]) -> int:
    checks = 0
    checks += _known_answer_python(failures)
    checks += _known_answer_luau(failures)
    checks += _roundtrip_tamper_luau(failures)
    checks += _surface(failures)
    checks += _cli_smoke(failures)
    checks += _default_off(failures)
    checks += _crypto_builds(failures)
    return checks


if __name__ == "__main__":
    failures: list[str] = []
    total = run(failures)
    if failures:
        print(f"CRYPTO-V7: FAIL ({total} checks, {len(failures)} failures)")
        for f in failures[:40]:
            print(" -", f)
        raise SystemExit(1)
    print(f"CRYPTO-V7: ALL GREEN ({total} checks)")
