"""Randomised, lazily assembled payload chunks.

A client-side VM cannot avoid carrying enough information to reproduce the
protected behaviour.  This module avoids handing the runtime one obvious
contiguous instruction/pool blob: each blob is split into small literals held
by separately generated closures in a table with randomised numeric keys.
The original blob is assembled only when that blob's getter is first used.

Normal builds are an obfuscation transform. With opt-in V7, the chunked bytes
are encrypted at build time using an embedded derived key; that is obfuscation,
not confidentiality.
"""
from __future__ import annotations

import hashlib
import math
import random
from dataclasses import dataclass, field

from .pool import lua_bytes_literal


@dataclass
class ChunkPlan:
    chunks: list[bytes]
    chunk_literals: list[str]
    count: int
    key_base: int
    key_a: int
    key_b: int
    keys: list[int]
    assignment_order: list[int]
    assembly: str
    strategy: str = "sbyte"
    digest: str = ""

    def summary(self) -> dict:
        return {
            "count": self.count,
            "sizes": [len(c) for c in self.chunks],
            "key_base": self.key_base,
            "key_a": self.key_a,
            "key_b": self.key_b,
            "keys": self.keys,
            "assignment_order": self.assignment_order,
            "assembly": self.assembly,
            "strategy": self.strategy,
            "digest": self.digest,
        }


def _coprime(rng: random.Random, n: int) -> int:
    while True:
        a = rng.randrange(1, max(2, n * 4))
        if math.gcd(a, n) == 1:
            return a


def make_chunk_plan(
    blob: bytes,
    rng: random.Random,
    *,
    assembly: str,
    strategy: str,
    max_chunk_bytes: int = 220,
    min_chunks: int = 2,
    max_extra: int = 3,
    hard_cap: int = 2048,
) -> ChunkPlan:
    if not blob:
        blob = b"\x00"
    needed = max(1, math.ceil(len(blob) / max_chunk_bytes))
    count = min(hard_cap, max(min_chunks, needed + rng.randint(0, max_extra)))
    count = min(count, len(blob)) if len(blob) < count else count
    count = max(1, count)

    base = len(blob) // count
    rem = len(blob) % count
    sizes = [base + (1 if i < rem else 0) for i in range(count)]
    for _ in range(count * 2):
        i, j = rng.randrange(count), rng.randrange(count)
        room = max_chunk_bytes - sizes[j]
        movable = sizes[i] - 1
        delta = rng.randint(0, min(24, room, movable))
        if delta:
            sizes[i] -= delta
            sizes[j] += delta

    chunks: list[bytes] = []
    pos = 0
    for n in sizes:
        chunks.append(blob[pos:pos + n])
        pos += n
    if pos < len(blob):
        chunks[-1] += blob[pos:]

    key_a = _coprime(rng, count)
    key_b = rng.randrange(count)
    key_base = rng.randrange(10000, 99000)
    keys = [key_base + ((j * key_a + key_b) % count) for j in range(count)]
    assignment_order = list(range(count))
    rng.shuffle(assignment_order)

    return ChunkPlan(
        chunks=chunks,
        chunk_literals=[lua_bytes_literal(c) for c in chunks],
        count=count,
        key_base=key_base,
        key_a=key_a,
        key_b=key_b,
        keys=keys,
        assignment_order=assignment_order,
        assembly=assembly,
        strategy=strategy,
        digest=hashlib.sha256(blob).hexdigest(),
    )


def emit_chunk_getter(add, ns, plan: ChunkPlan, indent: str = "  ") -> str:
    """Emit a lazy getter and return its generated Luau identifier."""
    table_name = ns.fresh_runtime()
    blob_name = ns.fresh_runtime()
    get_name = ns.fresh_runtime()
    loop_name = ns.fresh_runtime()
    key_name = ns.fresh_runtime()
    out_name = ns.fresh_runtime()

    add(f"{indent}local {table_name} = {{}}")
    for j in plan.assignment_order:
        add(
            f"{indent}{table_name}[{plan.keys[j]}] = "
            f"function() return {plan.chunk_literals[j]} end"
        )
    add(f"{indent}local {blob_name} = nil")
    add(f"{indent}local {get_name} = function()")
    add(f"{indent}  if {blob_name} then return {blob_name} end")
    if plan.assembly == "concat":
        add(f"{indent}  local {out_name} = {{}}")
        add(f"{indent}  for {loop_name} = 1, {plan.count} do")
        add(
            f"{indent}    local {key_name} = {plan.key_base} + "
            f"((({loop_name} - 1) * {plan.key_a} + {plan.key_b}) % {plan.count})"
        )
        add(f"{indent}    {out_name}[{loop_name}] = {table_name}[{key_name}]()")
        add(f"{indent}  end")
        add(f"{indent}  {blob_name} = table.concat({out_name})")
    else:
        add(f'{indent}  local {out_name} = ""')
        add(f"{indent}  for {loop_name} = 1, {plan.count} do")
        add(
            f"{indent}    local {key_name} = {plan.key_base} + "
            f"((({loop_name} - 1) * {plan.key_a} + {plan.key_b}) % {plan.count})"
        )
        add(
            f"{indent}    {out_name} = {out_name} .. "
            f"{table_name}[{key_name}]()"
        )
        add(f"{indent}  end")
        add(f"{indent}  {blob_name} = {out_name}")
    add(f"{indent}  return {blob_name}")
    add(f"{indent}end")
    return get_name
