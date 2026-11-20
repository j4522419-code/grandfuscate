"""V7 build-time encryption helpers.

This module is Python-side only. It derives a 256-bit key from the user's
passphrase (or from the build seed in convenience mode), whitens selected
constant-pool / VM-stream byte payloads with ChaCha20, and authenticates them
with HMAC-SHA256. The matching pure-Luau decryptor is emitted by
``obf/vm/crypto_runtime.py``.

Hard boundary: the derived key is embedded in the emitted chunk. This is
obfuscation, not confidentiality. It does not use a dynamic loader or
``loadstring``; decrypted bytes are consumed as data by the existing VM.
"""
from __future__ import annotations

import hashlib
import hmac
import random
from dataclasses import dataclass, field
from typing import Iterable

from .pool import lua_bytes_literal

MASK32 = 0xFFFFFFFF
DOMAIN = b"grandfuscate-v7"
KEY_BYTES = 32
SALT_BYTES = 16
NONCE_BYTES = 12
TAG_BYTES = 32


def _u32(x: int) -> int:
    return x & MASK32


def _rotl(x: int, n: int) -> int:
    x = _u32(x)
    return _u32((x << n) | (x >> (32 - n)))


def _rotr(x: int, n: int) -> int:
    return _rotl(x, 32 - n)


def _le_words(data: bytes) -> list[int]:
    if len(data) % 4:
        raise ValueError("word input must be a multiple of 4 bytes")
    return [
        int.from_bytes(data[i:i + 4], "little")
        for i in range(0, len(data), 4)
    ]


def _words_to_le(words: Iterable[int]) -> bytes:
    return b"".join(_u32(w).to_bytes(4, "little") for w in words)


def chacha20_block(key_words: list[int], counter: int, nonce_words: list[int]) -> bytes:
    """One 64-byte ChaCha20 keystream block."""
    if len(key_words) != 8 or len(nonce_words) != 3:
        raise ValueError("ChaCha20 needs 8 key words and 3 nonce words")
    st = [
        0x61707865, 0x3320646E, 0x79622D32, 0x6B206574,
        *key_words, _u32(counter), *nonce_words,
    ]
    x = list(st)

    def qr(a: int, b: int, c: int, d: int) -> None:
        x[a] = _u32(x[a] + x[b])
        x[d] = _rotl(x[d] ^ x[a], 16)
        x[c] = _u32(x[c] + x[d])
        x[b] = _rotl(x[b] ^ x[c], 12)
        x[a] = _u32(x[a] + x[b])
        x[d] = _rotl(x[d] ^ x[a], 8)
        x[c] = _u32(x[c] + x[d])
        x[b] = _rotl(x[b] ^ x[c], 7)

    for _ in range(10):
        qr(0, 4, 8, 12)
        qr(1, 5, 9, 13)
        qr(2, 6, 10, 14)
        qr(3, 7, 11, 15)
        qr(0, 5, 10, 15)
        qr(1, 6, 11, 12)
        qr(2, 7, 8, 13)
        qr(3, 4, 9, 14)

    return _words_to_le(_u32(x[i] + st[i]) for i in range(16))


def chacha20_xor(key: bytes, nonce: bytes, data: bytes, counter: int = 1) -> bytes:
    """ChaCha20 stream XOR. Encryption and decryption are the same operation."""
    if len(key) != KEY_BYTES:
        raise ValueError("ChaCha20 key must be 32 bytes")
    if len(nonce) != NONCE_BYTES:
        raise ValueError("ChaCha20 nonce must be 12 bytes")
    kw = _le_words(key)
    nw = _le_words(nonce)
    out = bytearray()
    c = _u32(counter)
    for off in range(0, len(data), 64):
        block = chacha20_block(kw, c, nw)
        chunk = data[off:off + 64]
        out.extend(a ^ b for a, b in zip(chunk, block))
        c = _u32(c + 1)
    return bytes(out)


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """Minimal HKDF-SHA256 extract + expand."""
    if not salt:
        salt = b"\x00" * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out = bytearray()
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out.extend(t)
        counter += 1
    return bytes(out[:length])


@dataclass
class CryptoPayload:
    domain: str
    index: int
    nonce: bytes
    ciphertext: bytes
    tag: bytes
    aad: bytes
    plaintext_len: int
    plaintext_sha256: str

    @property
    def nonce_literal(self) -> str:
        return lua_bytes_literal(self.nonce)

    @property
    def tag_literal(self) -> str:
        return lua_bytes_literal(self.tag)

    @property
    def aad_literal(self) -> str:
        return lua_bytes_literal(self.aad)

    @property
    def ciphertext_literal(self) -> str:
        return lua_bytes_literal(self.ciphertext)


@dataclass
class CryptoRuntime:
    """Fresh Luau local names shared by the prelude and VM body."""
    key_var: str = ""
    hmac_var: str = ""
    chacha_var: str = ""
    decrypt_var: str = ""
    sha_var: str = ""
    block_var: str = ""
    qr_var: str = ""
    le32_var: str = ""
    wb_var: str = ""
    wble_var: str = ""
    kconst_var: str = ""
    rotr_var: str = ""
    lrot_var: str = ""
    rshift_var: str = ""
    bnot_var: str = ""


@dataclass
class CryptoPlan:
    key: bytes
    salt: bytes
    build_id: str
    preset: str
    seed: int
    key_source: str
    passphrase_sha256: str
    alg: str = "HKDF-SHA256/ChaCha20/HMAC-SHA256"
    aad_extra_sha256: str = ""
    payloads: list[CryptoPayload] = field(default_factory=list)
    runtime: CryptoRuntime = field(default_factory=CryptoRuntime)

    @property
    def key_literal(self) -> str:
        return lua_bytes_literal(self.key)

    @property
    def salt_literal(self) -> str:
        return lua_bytes_literal(self.salt)

    @property
    def build_id_literal(self) -> str:
        return lua_bytes_literal(self.build_id.encode("ascii"))

    def payload(self, domain: str, index: int) -> CryptoPayload:
        for p in self.payloads:
            if p.domain == domain and p.index == index:
                return p
        raise KeyError(f"missing crypto payload {domain}/{index}")

    @property
    def encrypted_bytes(self) -> int:
        return sum(len(p.ciphertext) for p in self.payloads)


def make_crypto_plan(
    passphrase: bytes,
    *,
    build_id: str,
    preset: str,
    seed: int,
    rng: random.Random,
    payloads: list[tuple[str, int, bytes]],
    aad_extra: bytes = b"",
) -> CryptoPlan:
    """Derive key material and encrypt every selected byte payload."""
    salt = bytes(rng.randrange(256) for _ in range(SALT_BYTES))
    if passphrase:
        ikm = passphrase
        key_source = "passphrase"
    else:
        ikm = hashlib.sha256(
            f"seed-only|{build_id}|{preset}|{seed}".encode("ascii")
        ).digest()
        key_source = "seed"
    info = b"|".join([
        DOMAIN,
        preset.encode("ascii"),
        str(seed).encode("ascii"),
        build_id.encode("ascii"),
    ])
    key = hkdf_sha256(ikm, salt, info, KEY_BYTES)

    built: list[CryptoPayload] = []
    for domain, index, plaintext in payloads:
        nonce = bytes(rng.randrange(256) for _ in range(NONCE_BYTES))
        ciphertext = chacha20_xor(key, nonce, plaintext)
        aad = b"|".join([
            DOMAIN,
            build_id.encode("ascii"),
            preset.encode("ascii"),
            str(seed).encode("ascii"),
            domain.encode("ascii"),
            str(index).encode("ascii"),
            salt,
            len(plaintext).to_bytes(4, "big"),
            aad_extra,
        ])
        # The nonce is authenticated as part of the MAC input, not just trusted
        # as a separate argument: swapping it must fail verification.
        tag = hmac_sha256(key, aad + nonce + ciphertext)
        built.append(CryptoPayload(
            domain=domain,
            index=index,
            nonce=nonce,
            ciphertext=ciphertext,
            tag=tag,
            aad=aad,
            plaintext_len=len(plaintext),
            plaintext_sha256=hashlib.sha256(plaintext).hexdigest(),
        ))
    return CryptoPlan(
        key=key,
        salt=salt,
        build_id=build_id,
        preset=preset,
        seed=seed,
        key_source=key_source,
        passphrase_sha256=hashlib.sha256(passphrase).hexdigest(),
        aad_extra_sha256=hashlib.sha256(aad_extra).hexdigest(),
        payloads=built,
    )


def load_passphrase(key_text: str | None, key_file: str | None) -> bytes:
    """Resolve key material without ever writing it into the emitted chunk."""
    if key_text and key_file:
        raise ValueError("use either key_text or key_file, not both")
    if key_file:
        with open(key_file, "rb") as f:
            return f.read()
    if key_text:
        return key_text.encode("utf-8", "surrogateescape")
    return b""


def verify_plan(plan: CryptoPlan) -> bool:
    """Build-time check that every tag matches and every ciphertext decrypts."""
    for p in plan.payloads:
        if hmac_sha256(plan.key, p.aad + p.nonce + p.ciphertext) != p.tag:
            return False
        plain = chacha20_xor(plan.key, p.nonce, p.ciphertext)
        if len(plain) != p.plaintext_len:
            return False
        if hashlib.sha256(plain).hexdigest() != p.plaintext_sha256:
            return False
    return True


def crypto_chunk_bytes(
    plan: CryptoPlan | None,
    domain: str,
    index: int,
    blob: bytes,
    key: bytes,
) -> tuple[bytes, bytes, tuple[CryptoPayload, CryptoPayload] | None]:
    """Return the literal bytes to chunk, plus their decrypt payloads."""
    if plan is None:
        return blob, key, None
    pb = plan.payload(f"{domain}_blob", index)
    pk = plan.payload(f"{domain}_key", index)
    return pb.ciphertext, pk.ciphertext, (pb, pk)


def emit_decrypt_lines(
    plan: CryptoPlan | None,
    payloads: tuple[CryptoPayload, CryptoPayload] | None,
    q_var: str,
    kq_var: str,
    ok_var: str,
    indent: str = "    ",
) -> list[str]:
    """Verify HMAC tags and recover the plaintext blob/key inside ``ensure``."""
    if plan is None or payloads is None:
        return []
    pb, pk = payloads
    dec = plan.runtime.decrypt_var

    def call(p: CryptoPayload, ct_expr: str) -> str:
        return (
            f"{dec}({p.nonce_literal}, {p.aad_literal}, "
            f"{p.tag_literal}, {ct_expr})"
        )

    # The chunk getter already assembled the ciphertext into q_var/kq_var.
    # Passing it as the ct argument avoids shipping every ciphertext twice.
    return [
        f"{indent}{q_var} = {call(pb, q_var)}",
        f"{indent}{kq_var} = {call(pk, kq_var)}",
        f"{indent}if not {q_var} or not {kq_var} then {ok_var} = false return end",
    ]
