"""Lazily assembled, ticketed instruction-stream byte groups.

There is no central `DEC` decoder table. Each fragment owns its own chunk
getters and byte reader inside a lexical scope; byte functions live in a
per-build table but require a capability ticket from the word decoder.
"""
from __future__ import annotations

import hashlib
import random

from ..checksum import emit_group_integrity_lines, emit_verify_lines
from ..chunks import emit_chunk_getter, make_chunk_plan
from ..layout import Layout
from ..names import Names
from .compiler import Program


def _plan_rng(seed: int, idx: int, tag: str) -> random.Random:
    d = hashlib.sha256(f"{seed}|{idx}|{tag}".encode("ascii")).digest()
    return random.Random(int.from_bytes(d[:8], "big"))


def init_dispatch(add, ns: Names, table: str, layout: Layout) -> None:
    """Legacy helper retained for source-mode experiments."""
    for line in layout.init_dispatch_lines(table, ns.fresh_runtime()):
        add(line)


def emit_fragments(add, ns: Names, program: Program, ctx, R: dict, layout: Layout) -> None:
    """Emit sharded fragment getters and ticketed byte-decoder matrices."""
    program.chunk_plans = []
    vb = ns.group_tables["vm_byte"]
    vs = ns.fresh_runtime()
    ok_byte = ns.fresh_runtime()
    add(f"local {ok_byte} = true")
    for line in layout.init_group_table_lines(
        vb, "vm_byte", ns, slice_count=program.fragment_count
    ):
        add(line)
    add(f"local {vs} = {{}}")
    R["VBTABLE"] = vs
    cfg = layout.chunk_settings
    extra = cfg["max_extra"] + (2 if layout.chunk_strategy == "jitter" else 0)

    for frag in program.fragments:
        qplan = make_chunk_plan(
            frag.blob,
            _plan_rng(ctx.opts.seed, frag.index, "blob"),
            assembly=layout.chunk_assembly,
            strategy=layout.chunk_strategy,
            max_chunk_bytes=cfg["max_chunk_bytes"],
            min_chunks=cfg["min_chunks"],
            max_extra=extra,
            hard_cap=cfg["hard_cap"],
        )
        kplan = make_chunk_plan(
            frag.key,
            _plan_rng(ctx.opts.seed, frag.index, "key"),
            assembly=layout.chunk_assembly,
            strategy=layout.chunk_strategy,
            max_chunk_bytes=cfg["max_chunk_bytes"],
            min_chunks=cfg["min_chunks"],
            max_extra=extra,
            hard_cap=cfg["hard_cap"],
        )
        program.chunk_plans.append({
            "fragment": frag.index,
            "blob": qplan.summary(),
            "key": kplan.summary(),
        })
        add("do")
        qget = emit_chunk_getter(add, ns, qplan, "  ")
        kget = emit_chunk_getter(add, ns, kplan, "  ")
        q, kq, ok = ns.fresh_runtime(), ns.fresh_runtime(), ns.fresh_runtime()
        ensure = ns.fresh_runtime()
        db = ns.fresh_runtime()
        add(f"  local {q}, {kq}, {ok}")
        add(f"  local {ensure} = function()")
        add(f"    if {q} then return end")
        add(f"    {q} = {qget}()")
        add(f"    {kq} = {kget}()")
        add(f"    {ok} = true")
        add("\n".join(emit_verify_lines(
            ns, q, kq, frag.hash_params, ok_var=ok, indent="    "
        )))
        add("  end")
        add(f"  local {db} = function(j)")
        add(f"    {ensure}()")
        add(f"    if not {ok} then return 0 end")
        add(f"    local c = string.byte({q}, j + 1)")
        add(f"    local k = string.byte({kq}, ((j + {frag.salt}) % #{kq}) + 1)")
        add(
            f"    return (c - k - j * {frag.delta} - "
            f"math.floor(j / 8) * {frag.gamma}) % 256"
        )
        add("  end")

        matrix = ns.group_matrix("vm_byte", frag.index)
        for bank, row in enumerate(matrix):
            for g, expr in enumerate(row, 1):
                add(f"  {expr} = function(j, t, f)")
                add(f"    if not {ok_byte} then return 0 end")
                add(
                    "    " + layout.guard_line(
                        "vm_byte", "j", bank, g, "0", ticket_var="t"
                    )
                )
                add(f"    return {db}(j)")
                add("  end")
        add(f"  {vs}[{frag.index}] = function(j, t, f)")
        add(
            f"    if t ~= {layout.chain_ticket_expr('fragment', 'j')} "
            "then return 0 end"
        )
        add(
            "    return " + layout.function_selector(
                "vm_byte", "j", ["f"], ns, matrix=matrix
            )
        )
        add("  end")
        add("end")

    integrity_names = ns.all_slice_names("vm_byte") + [
        f"{vs}[{f}]" for f in range(1, program.fragment_count + 1)
    ]
    for line in emit_group_integrity_lines(ns, integrity_names, ok_byte):
        add(line)
