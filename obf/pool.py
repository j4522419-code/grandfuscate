"""Distributed, late-decoded typed constant pool.

Every string / number / boolean / nil literal becomes `D(i)`.  Instead of one
blob, one key, one metadata table and one cache, each build emits several
independent encoded slices.  A small arithmetic router maps a public constant
index to `(slice, local index)`; each slice owns one residue class, has its own
key/rolling coefficients, parses its own metadata on first use, caches only its
own values, and performs its own lightweight integrity check.  No plaintext
source text and no centralized decoded string table is emitted.

This is an obfuscation encoding, not cryptography with a security proof.
"""
from __future__ import annotations

import math
import random
import uuid
from dataclasses import dataclass, field

from .checksum import ChecksumParams, make_params


TAG_NIL, TAG_STRING, TAG_NUMBER, TAG_BOOL = 0, 1, 2, 3


def lua_bytes_literal(b: bytes) -> str:
    """A Luau double-quoted string literal with arbitrary bytes inside."""
    out = ['"']
    for x in b:
        if x == 0x22:
            out.append('\\"')
        elif x == 0x5C:
            out.append("\\\\")
        elif 0x20 <= x <= 0x7E:
            out.append(chr(x))
        elif x == 0x0A:
            out.append("\\n")
        elif x == 0x0D:
            out.append("\\r")
        elif x == 0x09:
            out.append("\\t")
        else:
            out.append("\\%03d" % x)
    out.append('"')
    return "".join(out)


def _next_prime(n: int) -> int:
    n = max(2, int(n))
    while True:
        if all(n % d for d in range(2, int(math.sqrt(n)) + 1)):
            return n
        n += 1


@dataclass
class Entry:
    tag: int
    payload: bytes
    span: tuple[int, int] | None = None
    text: str | None = None


@dataclass
class PoolSlice:
    index: int
    residue: int
    blob: bytes
    key: bytes
    delta: int
    gamma: int
    salt: int
    expected_hash: int
    hash_params: ChecksumParams
    blob_literal: str
    key_literal: str
    count: int
    order: tuple[int, int, int] = (0, 1, 2)
    tag_rot: int = 0
    indices: list[int] = field(default_factory=list)


@dataclass
class PoolBuild:
    blob: bytes
    key: bytes
    delta: int
    gamma: int
    salt: int
    expected_hash: int
    hash_params: ChecksumParams
    build_id: str
    count: int
    slices: list[PoolSlice] = field(default_factory=list)
    slice_count: int = 1
    slice_stride: int = 1
    slice_shift: int = 0
    blob_literal: str = ""
    key_literal: str = ""
    chunk_plans: list = field(default_factory=list)


class ConstantPool:
    def __init__(self, rng: random.Random, build_id: str | None = None):
        self.rng = rng
        self.entries: list[Entry] = []
        self._index: dict[tuple[int, bytes], int] = {}
        self.build_id = build_id or uuid.uuid4().hex[:16]
        # Entry #1 is an unreferenced high-entropy decoy. No provenance header,
        # build identifier or recognizable metadata is shipped in the chunk;
        # the build id stays in private keys/source-map material only.
        self.add_string(bytes(rng.randrange(256) for _ in range(rng.randint(16, 48))))

    def _add(self, tag: int, payload: bytes, span=None, text=None) -> int:
        k = (tag, payload)
        if k in self._index:
            return self._index[k]
        idx = len(self.entries) + 1
        self._index[k] = idx
        self.entries.append(Entry(tag, payload, span, text))
        return idx

    def add_string(self, s: str | bytes) -> int:
        b = s.encode("utf-8", "surrogateescape") if isinstance(s, str) else s
        return self._add(TAG_STRING, b, text=s if isinstance(s, str) else None)

    def add_number(self, v: float) -> int:
        if isinstance(v, int):
            v = float(v)
        if math.isnan(v):
            return self._add(TAG_NUMBER, b"nan", text="nan")
        text = repr(float(v))
        # tonumber("inf") / tonumber("-inf") work in Luau; nan does not, but a
        # nan literal cannot appear in Luau source anyway (it is 0/0).
        return self._add(TAG_NUMBER, text.encode("ascii"), text=text)

    def add_bool(self, v: bool) -> int:
        return self._add(TAG_BOOL, b"1" if v else b"0", text="true" if v else "false")

    def add_nil(self) -> int:
        return self._add(TAG_NIL, b"", text="nil")

    def add_decoy(self) -> int:
        n = self.rng.randint(3, 18)
        raw = bytes(self.rng.randrange(256) for _ in range(n))
        return self.add_string("".join(chr(0x41 + b % 26) for b in raw))

    def add_padding(self, total_bytes: int) -> int:
        """Add unreferenced high-entropy constant-pool entries."""
        if total_bytes <= 0:
            return 0
        added = 0
        left = total_bytes
        while left > 0:
            n = min(left, self.rng.randint(192, 768))
            self.add_string(bytes(self.rng.randrange(256) for _ in range(n)))
            left -= n
            added += 1
        return added

    def _build_slice(self, index: int, residue: int, owned: list[Entry], global_indices: list[int]) -> PoolSlice:
        r = self.rng
        keylen = r.randint(8, 28)
        key = bytes(r.randrange(256) for _ in range(keylen))
        delta = r.randint(1, 251)
        gamma = r.randint(1, 251)
        salt = r.randint(0, keylen - 1)

        order = [0, 1, 2]
        r.shuffle(order)
        order = tuple(order)
        tag_rot = r.randrange(4)

        def fmt(placements: list[tuple[int, int, int]]) -> bytes:
            records = []
            for o, l, t in placements:
                fields = (f"{o:08d}", f"{l:06d}", f"{(t + tag_rot) % 4}")
                records.append(",".join(fields[i] for i in order))
            return ";".join(records).encode("ascii") + b";"

        placements: list[tuple[int, int, int]] = []
        body = bytearray()
        junk = lambda: bytes(r.randrange(256) for _ in range(r.randint(0, 7)))
        for e in owned:
            body += junk()
            off = len(body)
            body += e.payload
            placements.append((off, len(e.payload), e.tag))
        body += junk()

        mlen = len(fmt(placements))
        placements = [(o + 4 + mlen, l, t) for o, l, t in placements]
        meta = fmt(placements)
        assert len(meta) == mlen
        plain = bytearray(mlen.to_bytes(4, "big") + meta + bytes(body))

        def enc(j: int, p: int) -> int:
            return (p + key[(j + salt) % keylen] + j * delta + (j // 8) * gamma) & 0xFF

        blob = bytes(enc(j, p) for j, p in enumerate(plain))
        hp = make_params(r, blob + key)
        return PoolSlice(
            index=index,
            residue=residue,
            blob=blob,
            key=key,
            delta=delta,
            gamma=gamma,
            salt=salt,
            expected_hash=hp.expected,
            hash_params=hp,
            blob_literal=lua_bytes_literal(blob),
            key_literal=lua_bytes_literal(key),
            count=len(owned),
            order=order,
            tag_rot=tag_rot,
            indices=global_indices,
        )

    def build(
        self,
        slices: int = 3,
        *,
        stride: int | None = None,
        shift: int | None = None,
    ) -> PoolBuild:
        r = self.rng
        S = _next_prime(slices)
        if S > 1:
            A = ((stride - 1) % (S - 1)) + 1 if stride is not None else r.randrange(1, S)
        else:
            A = 1
        Bv = (shift % S) if shift is not None else r.randrange(0, S)
        invA = pow(A, -1, S) if S > 1 else 1

        # Slice s owns the residue p0 where s = ((p0-1)*A + B) % S + 1.
        built_slices: list[PoolSlice] = []
        for s in range(1, S + 1):
            p0 = ((s - 1 - Bv) * invA) % S + 1
            global_indices = list(range(p0, len(self.entries) + 1, S))
            owned = [self.entries[i - 1] for i in global_indices]
            built_slices.append(self._build_slice(s, p0, owned, global_indices))

        blob = b"".join(x.blob for x in built_slices)
        key = b"".join(x.key for x in built_slices)
        first = built_slices[0]
        hp = make_params(r, blob + key)
        return PoolBuild(
            blob=blob,
            key=key,
            delta=first.delta,
            gamma=first.gamma,
            salt=first.salt,
            expected_hash=hp.expected,
            hash_params=hp,
            build_id=self.build_id,
            count=len(self.entries),
            slices=built_slices,
            slice_count=S,
            slice_stride=A,
            slice_shift=Bv,
            blob_literal=first.blob_literal,
            key_literal=first.key_literal,
        )
