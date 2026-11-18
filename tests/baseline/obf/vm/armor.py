"""Legacy second encrypted dispatch layer ("double VM") for the Luau IR program.

No normal preset calls this module. Its optional anti-environment re-check
could poison ordinary executors, so the shipped website/API/CLI use a single VM
runtime instead. Kept only for explicit library experiments.

The inner VM still interprets the original tree-walking IR.  This module wraps
its encrypted instruction stream in an OUTER program with:

* a second, independently shuffled opcode map;
* per-chunk rolling keys derived from a runtime hash state;
* multiple rolling checkpoints embedded in the outer stream;
* decoy meta-instructions and decoy chunks;
* a combined integrity hash over outer blob, inner stream, pool and keys;
* an optional anti-environment re-check before the inner VM is called.

No `loadstring`, `load`, `require` or source-text execution is used.  The inner
stream is rebuilt in memory as a byte string and parsed by the inner VM exactly
as before, so behaviour is unchanged.
"""
from __future__ import annotations

from dataclasses import dataclass, replace

from .. import hardening
from ..pool import PoolBuild, lua_bytes_literal
from ..render import Context
from .compiler import Program

META_OPS = ["DECRYPT", "CHECK", "SEED", "DECOY"]


def _b32(x: int) -> int:
    return x & 0xFFFFFFFF


@dataclass
class OuterProgram:
    prelude: str
    inner_program: Program
    inner_fn: str
    tail: str
    outer_blob: bytes
    outer_key: bytes
    meta_opcodes: dict[str, int]
    chunk_keys: list[int]
    chunk_count: int
    meta_count: int
    outer_hash: int
    combined_hash: int
    outer_delta: int
    chunk_delta: int
    rolling_seed: int
    extra_chunks: int
    extra_meta: int
    decoy_factor: float


def _fnv(data: bytes, seed: int) -> int:
    return hardening.fnv(data, seed)


def build_outer(program: Program, ctx: Context, built: PoolBuild) -> OuterProgram:
    ns = ctx.names
    rng = ctx.rng
    opts = ctx.opts
    N = ns.N

    # Fresh runtime identifiers for the outer layer.
    q_armor = ns.fresh_runtime("Q_ARMOR")
    kq_armor = ns.fresh_runtime("KQ_ARMOR")
    oq = ns.fresh_runtime("OQ")
    ok = ns.fresh_runtime("OK")
    odb = ns.fresh_runtime("ODB")
    oc = ns.fresh_runtime("OC")
    meta = ns.fresh_runtime("META")
    chunks = ns.fresh_runtime("CHUNKS")
    parts = ns.fresh_runtime("PARTS")
    roll = ns.fresh_runtime("ROLL")
    inner_fn = ns.fresh_runtime("INNER")

    # Shuffled outer opcode map + decoy codes.
    codes = list(range(1, len(META_OPS) + 9))
    rng.shuffle(codes)
    meta_opcodes = dict(zip(META_OPS, codes[: len(META_OPS)]))
    decoy_codes = codes[len(META_OPS) :]

    outer_delta = rng.randint(1, 251)
    chunk_delta = rng.randint(1, 251)
    rolling_seed = rng.randrange(1, 1 << 30)

    # Split the inner stream into real chunks; append unreferenced decoy chunks.
    stream = program.stream
    real_chunks: list[bytes] = []
    i = 0
    while i < len(stream):
        n = rng.randint(96, 768)
        real_chunks.append(stream[i : i + n])
        i += n
    if not real_chunks:
        real_chunks = [b""]

    # Build meta instructions while simulating the runtime rolling state.
    metas: list[tuple[str, list[int]]] = []
    enc_chunks: list[bytes] = []
    chunk_keys: list[int] = []
    rolling = rolling_seed

    def emit(op: str, args: list[int]) -> None:
        metas.append((op, args))

    for plain in real_chunks:
        if rng.random() < 0.75:
            arg = rng.randrange(1, 1 << 20)
            emit("DECOY", [arg])
            rolling = _b32(rolling ^ arg)
        if rng.random() < 0.55:
            add = rng.randrange(1, 1 << 20)
            emit("SEED", [add])
            rolling = _b32(rolling + add)

        ck = rng.randrange(256)
        enc = bytearray()
        for j, b in enumerate(plain, start=1):
            k = (ck + j * chunk_delta + rolling) % 256
            c = (b + k) & 0xFF
            enc.append(c)
            rolling = _b32(rolling * 31 + b + j + ck)
        enc_chunks.append(bytes(enc))
        chunk_keys.append(ck)
        ci = len(enc_chunks)
        emit("DECRYPT", [ci, ck])

        add = rng.randrange(0, 1 << 16)
        emit("CHECK", [rolling, add])
        rolling = _b32(rolling + add)

    # The same three sliders also scale outer-layer chaff.  `flatten_ratio > 1`
    # is a multiplier, `junk` adds decoys, and a low `min_stmts` adds more.
    decoy_factor = max(0.0, min(opts.flatten_ratio, 4.0))
    junk = max(0, opts.junk)
    min_gap = max(0, 64 - min(opts.min_stmts, 64))
    extra_chunks = min(3 + int(junk * decoy_factor * 1.5) + min_gap // 16, 96)
    extra_meta = min(5 + int(junk * decoy_factor * 4) + min_gap, 512)

    # Decoy chunks are present in the outer stream but never decrypted.
    for _ in range(extra_chunks):
        n = rng.randint(64, 768)
        enc_chunks.append(bytes(rng.randrange(256) for _ in range(n)))
        chunk_keys.append(rng.randrange(256))

    # Trailing meta decoys, then a final checkpoint.
    for _ in range(extra_meta):
        if rng.random() < 0.5:
            arg = rng.randrange(1, 1 << 20)
            emit("DECOY", [arg])
            rolling = _b32(rolling ^ arg)
        else:
            add = rng.randrange(1, 1 << 20)
            emit("SEED", [add])
            rolling = _b32(rolling + add)
    emit("CHECK", [rolling, 0])

    # Serialise outer program: [nmeta, (op,n,args...)*, nchunks, (len,bytes...)*, decoys]
    plain_ints: list[int] = [len(metas)]
    for op, args in metas:
        plain_ints += [meta_opcodes[op], len(args), *args]
    plain_ints += [len(enc_chunks)]
    for c in enc_chunks:
        plain_ints += [len(c), *list(c)]
    for _ in range(rng.randint(8, 32)):
        plain_ints.append(rng.randrange(0, 1 << 32))

    outer_keylen = rng.randint(12, 36)
    outer_key = bytes(rng.randrange(256) for _ in range(outer_keylen))
    outer_gamma = rng.randint(1, 251)
    outer_salt = rng.randrange(outer_keylen)
    plain = bytearray()
    for v in plain_ints:
        plain += (v & 0xFFFFFFFF).to_bytes(4, "big")

    def enc_byte(j: int, p: int) -> int:
        return (
            p
            + outer_key[(j + outer_salt) % outer_keylen]
            + j * outer_delta
            + (j // 8) * outer_gamma
        ) & 0xFF

    outer_blob = bytes(enc_byte(j, p) for j, p in enumerate(plain))

    outer_hash = _fnv(outer_blob + outer_key, 0x811C9DC5)
    combined_data = (
        outer_blob
        + outer_key
        + program.stream
        + program.stream_key
        + built.blob
        + built.key
    )
    combined_hash = _fnv(combined_data, 0x9E3779B9)

    L: list[str] = []
    add = L.append
    add(f"local {oq} = {lua_bytes_literal(outer_blob)}")
    add(f"local {ok} = {lua_bytes_literal(outer_key)}")
    add(f"local {kq_armor} = {program.key_literal}")
    add(f"local {q_armor} = \"\"")
    add(f"local {odb} = function(j)")
    add(f"  local c = string.byte({oq}, j + 1)")
    add(f"  local k = string.byte({ok}, ((j + {outer_salt}) % #{ok}) + 1)")
    add(f"  return (c - k - j * {outer_delta} - math.floor(j / 8) * {outer_gamma}) % 256")
    add("end")
    add(f"local {oc} = {{}}")
    add(f"for i = 1, #{oq} / 4 do")
    add("  local o = (i - 1) * 4")
    add(f"  {oc}[i] = {odb}(o) * 16777216 + {odb}(o + 1) * 65536 + {odb}(o + 2) * 256 + {odb}(o + 3)")
    add("end")
    add(f"local {meta}, {chunks} = {{}}, {{}}")
    add("do")
    add("  local p = 1")
    add(f"  local nm = {oc}[p]; p = p + 1")
    add("  for i = 1, nm do")
    add(f"    local op = {oc}[p]; local n = {oc}[p + 1]; p = p + 2")
    add("    local a = {}")
    add(f"    for j = 1, n do a[j] = {oc}[p]; p = p + 1 end")
    add(f"    {meta}[i] = {{ op, n, a }}")
    add("  end")
    add(f"  local nc = {oc}[p]; p = p + 1")
    add("  for i = 1, nc do")
    add(f"    local len = {oc}[p]; p = p + 1")
    add("    local t = {}")
    add(f"    for j = 1, len do t[j] = string.char({oc}[p]); p = p + 1 end")
    add(f"    {chunks}[i] = table.concat(t)")
    add("  end")
    add("end")

    add(f"local {parts} = {{}}")
    add(f"local {roll} = {rolling_seed}")
    add(f"for i = 1, #{meta} do")
    add(f"  local m = {meta}[i]")
    add("  local op = m[1]")

    branches: list[tuple[int, list[str]]] = []
    branches.append((meta_opcodes["DECRYPT"], [
        "    local ci = m[3][1]",
        "    local ck = m[3][2]",
        f"    local c = {chunks}[ci]",
        "    local out = {}",
        "    for j = 1, #c do",
        f"      local k = (ck + j * {chunk_delta} + {roll}) % 256",
        "      local b = (string.byte(c, j) - k) % 256",
        "      out[j] = string.char(b)",
        f"      {roll} = bit32.band({roll} * 31 + b + j + ck, 4294967295)",
        "    end",
        f"    {parts}[#{parts} + 1] = table.concat(out)",
    ]))
    branches.append((meta_opcodes["CHECK"], [
        f"    if {roll} ~= m[3][1] then {N('BAD')} = true end",
        f"    {roll} = bit32.band({roll} + m[3][2], 4294967295)",
    ]))
    branches.append((meta_opcodes["SEED"], [
        f"    {roll} = bit32.band({roll} + m[3][1], 4294967295)",
    ]))
    branches.append((meta_opcodes["DECOY"], [
        f"    {roll} = bit32.bxor({roll}, m[3][1])",
    ]))
    for d in decoy_codes[:4]:
        branches.append((d, [
            f"    {roll} = bit32.bxor({roll}, m[3][1] or 0)",
        ]))
    rng.shuffle(branches)
    for code, body in branches:
        add(f"  if op == {code} then")
        add("\n".join(body))
        add("  end")
    add("end")
    add(f"{q_armor} = table.concat({parts})")
    add(f"if #{q_armor} ~= {len(program.stream)} then {N('BAD')} = true end")

    # Layered integrity over the outer stream and over every blob together.
    L.extend(hardening.fnv_lines(ns, f"{oq} .. {ok}", outer_hash, 0x811C9DC5))
    L.extend(
        hardening.fnv_lines(
            ns,
            f"{oq} .. {ok} .. {q_armor} .. {kq_armor} .. {N('B')} .. {N('K')}",
            combined_hash,
            0x9E3779B9,
        )
    )
    if opts.anti_env:
        L.extend(hardening.anti_env_check(ns))

    # Poison the inner stream if any check failed.
    add(f"if {N('BAD')} then {q_armor} = \"\" end")

    inner_program = replace(
        program,
        stream_literal=q_armor,
        key_literal=kq_armor,
    )
    tail = f"return {inner_fn}()\n"

    return OuterProgram(
        prelude="\n".join(L) + "\n",
        inner_program=inner_program,
        inner_fn=inner_fn,
        tail=tail,
        outer_blob=outer_blob,
        outer_key=outer_key,
        meta_opcodes=meta_opcodes,
        chunk_keys=chunk_keys,
        chunk_count=len(enc_chunks),
        meta_count=len(metas),
        outer_hash=outer_hash,
        combined_hash=combined_hash,
        outer_delta=outer_delta,
        chunk_delta=chunk_delta,
        rolling_seed=rolling_seed,
        extra_chunks=extra_chunks,
        extra_meta=extra_meta,
        decoy_factor=decoy_factor,
    )
