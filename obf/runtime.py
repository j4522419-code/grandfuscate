"""Generates the distributed, lazily assembled constant-pool prelude.

Normal builds emit no anti-environment poisoning.  Each pool slice has its own
sharded literal store, byte decoder, metadata parser, cache and per-build
checksum.  A slice's encoded blob/key are assembled only when one of its
constants is first requested.  Checksums use randomized coefficients, not a
fixed FNV pair, and failure only makes that slice return nil constants.

Normal builds are obfuscation encodings. The opt-in V7 layer whitens these
byte payloads with ChaCha20 and authenticates them with HMAC-SHA256, but its
derived key is embedded, so it is obfuscation, not confidentiality.
"""
from __future__ import annotations

import hashlib
import random

from . import hardening
from .checksum import emit_group_integrity_lines, emit_verify_lines
from .chunks import emit_chunk_getter, make_chunk_plan
from .crypto import CryptoPlan, crypto_chunk_bytes, emit_decrypt_lines
from .layout import Layout
from .names import Names
from .pool import PoolBuild
from .vm import crypto_runtime as CR
from .vm import stealth as V5S


def _plan_rng(build_id: str, sl_index: int, tag: str) -> random.Random:
    digest = hashlib.sha256(
        f"{build_id}|{sl_index}|{tag}".encode("ascii")
    ).digest()
    return random.Random(int.from_bytes(digest[:8], "big"))


def _init_dispatch(add, ns, name: str, layout: Layout) -> None:
    for line in layout.init_dispatch_lines(name, ns.fresh_runtime()):
        add(line)


def _router_body(
    add,
    ns,
    *,
    dec: str,
    layout: Layout,
    count: int,
    stride: int,
    shift: int,
    target: str,
    indent: str = "  ",
) -> None:
    p = ns.fresh_runtime()
    s = ns.fresh_runtime()
    l = ns.fresh_runtime()
    add(f"{indent}local {p} = ((i - 1) % {count}) + 1")
    add(
        f"{indent}local {s} = (({p} - 1) * {stride} + {shift}) "
        f"% {count} + 1"
    )
    add(f"{indent}local {l} = math.floor((i - 1) / {count}) + 1")
    add(f"{indent}return {layout.runtime_handler(dec, s)}({l})")


def _render_source_runtime(
    ns: Names,
    b: PoolBuild,
    *,
    layout: Layout,
    place_id: int | None = None,
    game_id: int | None = None,
    idx_game: int | None = None,
    idx_place: int | None = None,
    idx_gameid: int | None = None,
    idx_pid: int | None = None,
    idx_gid: int | None = None,
    integrity: bool = True,
    anti_env: bool = False,
    anti_tamper: bool = False,
    extra_hash: int | None = None,
    extra_hash_seed: int = 0x9E3779B9,
    runtime_consts: dict[str, int] | None = None,
    stealth_plan: object | None = None,
    crypto_plan: CryptoPlan | None = None,
) -> str:
    if runtime_consts is None:
        raise ValueError("runtime_consts are required")
    N = ns.N
    L: list[str] = []
    add = L.append
    if crypto_plan is not None:
        for line in CR.emit_crypto_lines(crypto_plan, ns):
            add(line)

    E = N("E")
    B = N("B")
    K = N("K")
    D = N("D")
    DEC = ns.fresh_runtime()

    add(f"local {E} = (getfenv and getfenv()) or _G")
    _init_dispatch(add, ns, DEC, layout)

    # Legacy explicit experiments need one combined blob/key expression for the
    # optional checksum. Normal builds never emit this central concatenation.
    if anti_tamper or anti_env:
        add(f"local {B} = " + " .. ".join(s.blob_literal for s in b.slices))
        add(f"local {K} = " + " .. ".join(s.key_literal for s in b.slices))
    if anti_env:
        for line in hardening.anti_env_capture(ns):
            add(line)
        for line in hardening.anti_env_check(ns):
            add(line)

    b.chunk_plans = []
    for sl in b.slices:
        cfg = layout.chunk_settings
        extra = cfg["max_extra"] + (2 if layout.chunk_strategy == "jitter" else 0)
        q_bytes, k_bytes, dec_payloads = crypto_chunk_bytes(
            crypto_plan, "pool", sl.index, sl.blob, sl.key
        )
        qplan = make_chunk_plan(
            q_bytes,
            _plan_rng(b.build_id, sl.index, "blob"),
            assembly=layout.chunk_assembly,
            strategy=layout.chunk_strategy,
            max_chunk_bytes=cfg["max_chunk_bytes"],
            min_chunks=cfg["min_chunks"],
            max_extra=extra,
            hard_cap=cfg["hard_cap"],
        )
        kplan = make_chunk_plan(
            k_bytes,
            _plan_rng(b.build_id, sl.index, "key"),
            assembly=layout.chunk_assembly,
            strategy=layout.chunk_strategy,
            max_chunk_bytes=cfg["max_chunk_bytes"],
            min_chunks=cfg["min_chunks"],
            max_extra=extra,
            hard_cap=cfg["hard_cap"],
        )
        b.chunk_plans.append({
            "slice": sl.index,
            "blob": qplan.summary(),
            "key": kplan.summary(),
        })

        qget = emit_chunk_getter(add, ns, qplan, "  ")
        kget = emit_chunk_getter(add, ns, kplan, "  ")
        q = ns.fresh_runtime()
        kq = ns.fresh_runtime()
        ok = ns.fresh_runtime()
        ensure = ns.fresh_runtime()
        db = ns.fresh_runtime()
        meta = ns.fresh_runtime()
        cache = ns.fresh_runtime()
        seen = ns.fresh_runtime()
        prep = ns.fresh_runtime()
        jvar = ns.fresh_runtime()
        nums = ns.fresh_runtime()
        kvar = ns.fresh_runtime()
        cvar = ns.fresh_runtime()
        perm = [sl.order.index(i) for i in range(3)]
        add("do")
        add(f"  local {q}, {kq}, {ok}")
        add(f"  local {ensure} = function()")
        add(f"    if {q} then return end")
        add(f"    {q} = {qget}()")
        add(f"    {kq} = {kget}()")
        for line in emit_decrypt_lines(
            crypto_plan, dec_payloads, q, kq, ok, indent="    "
        ):
            add(line)
        add(f"    {ok} = true")
        if integrity:
            add(
                "\n".join(
                    emit_verify_lines(
                        ns, q, kq, sl.hash_params, ok_var=ok, indent="    "
                    )
                )
            )
        add(f"  end")
        add(f"  local {db} = function(j)")
        add(f"    {ensure}()")
        add(f"    if not {ok} then return 0 end")
        add(f"    local c = string.byte({q}, j + 1)")
        add(
            f"    local k = string.byte({kq}, "
            f"((j + {sl.salt}) % #{kq}) + 1)"
        )
        add(
            f"    return (c - k - j * {sl.delta} - "
            f"math.floor(j / 8) * {sl.gamma}) % 256"
        )
        add(f"  end")
        add(f"  local {meta}, {cache}, {seen} = nil, {{}}, {{}}")
        add(f"  local {prep} = function()")
        add(f"    if {meta} then return end")
        add(f"    {ensure}()")
        add(f"    if not {ok} then {meta} = {{}} return end")
        add(
            f"    local ml = {db}(0) * 16777216 + {db}(1) * 65536 + "
            f"{db}(2) * 256 + {db}(3)"
        )
        add(f"    {meta} = {{}}")
        add(f"    local {jvar} = 4")
        add(f"    while {jvar} < ml + 4 do")
        add(f"      local {nums}, {kvar} = {{ 0, 0, 0 }}, 1")
        add("      while true do")
        add(f"        local {cvar} = {db}({jvar})")
        add(f"        {jvar} = {jvar} + 1")
        add(f"        if {cvar} == 44 then {kvar} = {kvar} + 1")
        add(f"        elseif {cvar} == 59 then break")
        add(
            f"        elseif {cvar} >= 48 and {cvar} <= 57 then "
            f"{nums}[{kvar}] = {nums}[{kvar}] * 10 + {cvar} - 48"
        )
        add("        end")
        add("      end")
        add(
            f"      {meta}[#{meta} + 1] = "
            f"{{ {nums}[{perm[0] + 1}], {nums}[{perm[1] + 1}], "
            f"({nums}[{perm[2] + 1}] - {sl.tag_rot}) % 4 }}"
        )
        add("    end")
        add(f"  end")
        add(f"  {layout.assign_slot(DEC, sl.index)} = function(i)")
        add(f"    local c = {cache}[i]")
        add(f"    if c ~= nil then return c end")
        add(f"    if {seen}[i] then return nil end")
        add(f"    {prep}()")
        add(f"    local e = {meta}[i]")
        add(f"    if not e then return nil end")
        # Decode bytes in a rotated reverse order. A simple `string.char`
        # hook sees reversed individual bytes, never a contiguous source
        # string; the original order is restored with `..`, not `table.concat`.
        parts = ns.fresh_runtime()
        order_b = ns.fresh_runtime()
        kvar2 = ns.fresh_runtime()
        ci = ns.fresh_runtime()
        svar = ns.fresh_runtime()
        add(f"    local {parts} = {{}}")
        add(
            f"    local {order_b} = e[2] - 1 + "
            f"2 * ({layout.const_bias} + {layout.const_span})"
        )
        add(f"    for {kvar2} = 1, e[2] do")
        add(
            f"      local {ci} = (({kvar2} - 1) * -1 "
            f"+ {order_b}) % e[2] + 1"
        )
        add(
            f"      {parts}[{ci}] = "
            f"string.char({db}(e[1] + {ci} - 1))"
        )
        add("    end")
        add(f'    local {svar} = ""')
        add(
            f"    for {kvar2} = 1, e[2] do "
            f"{svar} = {svar} .. {parts}[{kvar2}] end"
        )
        add(f"    local s = {svar}")
        add(f"    local r")
        add(f"    if e[3] == 1 then r = s")
        add(f"    elseif e[3] == 2 then r = tonumber(s)")
        add(f"    elseif e[3] == 3 then r = ({db}(e[1]) == 49)")
        add(f"    else r = nil end")
        add(f"    {cache}[i] = r")
        add(f"    {seen}[i] = true")
        add(f"    return r")
        add(f"  end")
        add("end")

    if layout.router_style == "direct":
        add(f"local {D} = function(i)")
        _router_body(
            add, ns, dec=DEC, layout=layout, count=b.slice_count,
            stride=b.slice_stride, shift=b.slice_shift, target=D,
        )
        add("end")
    elif layout.router_style == "split":
        d0, d1 = ns.fresh_runtime(), ns.fresh_runtime()
        for fn in (d0, d1):
            add(f"local {fn} = function(i)")
            _router_body(
                add, ns, dec=DEC, layout=layout, count=b.slice_count,
                stride=b.slice_stride, shift=b.slice_shift, target=fn,
            )
            add("end")
        add(f"local {D} = function(i)")
        add(f"  if (i % 2) == 0 then return {d1}(i) end")
        add(f"  return {d0}(i)")
        add("end")
    else:
        a, c, e = ns.fresh_runtime(), ns.fresh_runtime(), ns.fresh_runtime()
        add(f"local {a} = function(i) return ((i - 1) % {b.slice_count}) + 1 end")
        add(
            f"local {c} = function(p) return ((p - 1) * {b.slice_stride} "
            f"+ {b.slice_shift}) % {b.slice_count} + 1 end"
        )
        add(
            f"local {e} = function(i) return "
            f"math.floor((i - 1) / {b.slice_count}) + 1 end"
        )
        add(f"local {D} = function(i)")
        add(f"  local p = {a}(i)")
        add(f"  local s = {c}(p)")
        add(f"  local l = {e}(i)")
        add(f"  return {layout.runtime_handler(DEC, 's')}(l)")
        add("end")

    if anti_tamper and extra_hash is not None:
        for line in hardening.fnv_lines(
            ns, f"{B} .. {K}", extra_hash, extra_hash_seed
        ):
            add(line)

    if place_id is not None or game_id is not None:
        conds = []
        if place_id is not None:
            conds.append(f"g[{D}({idx_place})] ~= {D}({idx_pid})")
        if game_id is not None:
            conds.append(f"g[{D}({idx_gameid})] ~= {D}({idx_gid})")
        add("do")
        add(f"  local g = {E}[{D}({idx_game})]")
        add(f"  if g and (" + " or ".join(conds) + ") then return end")
        add("end")

    return "\n".join(L) + "\n"


def _render_vm_runtime(
    ns: Names,
    b: PoolBuild,
    *,
    layout: Layout,
    place_id: int | None = None,
    game_id: int | None = None,
    idx_game: int | None = None,
    idx_place: int | None = None,
    idx_gameid: int | None = None,
    idx_pid: int | None = None,
    idx_gid: int | None = None,
    integrity: bool = True,
    anti_env: bool = False,
    anti_tamper: bool = False,
    extra_hash: int | None = None,
    extra_hash_seed: int = 0x9E3779B9,
    runtime_consts: dict[str, int] | None = None,
    stealth_plan: object | None = None,
    crypto_plan: CryptoPlan | None = None,
) -> str:
    """Third-pass, ticketed and group-scattered constant runtime.

    There is no `D(i)` decoder that returns an arbitrary constant, no single
    decoded-string table, no provenance header and no central rebuild routine.
    Group functions require capability tickets produced by fresh call-site
    closures; integrity failures only produce nil/default values.
    """
    if runtime_consts is None:
        raise ValueError("runtime_consts are required")
    N = ns.N
    L: list[str] = []
    add = L.append
    if crypto_plan is not None:
        for line in CR.emit_crypto_lines(crypto_plan, ns):
            add(line)
    if stealth_plan is not None:
        # Define the active-decoy reactor/T/P locals once, before any guard
        # line in either the prelude or the VM body references them.
        object.__setattr__(layout, "stealth_plan", stealth_plan)
        for line in V5S.emit_stealth_lines(stealth_plan):
            add(line)
    E = N("E")
    ok_all = ns.fresh_runtime()
    cd = ns.group_tables["constant"]
    pb = ns.group_tables["pool_byte"]
    ps = ns.fresh_runtime()
    add(f"local {E} = (getfenv and getfenv()) or _G")
    add(f"local {ok_all} = true")
    for line in layout.init_group_table_lines(cd, "constant", ns):
        add(line)
    for line in layout.init_group_table_lines(
        pb, "pool_byte", ns, slice_count=b.slice_count
    ):
        add(line)
    add(f"local {ps} = {{}}")

    def C(expr: str | int) -> str:
        return layout.function_selector("constant", str(expr), [], ns)

    b.chunk_plans = []
    for sl in b.slices:
        cfg = layout.chunk_settings
        extra = cfg["max_extra"] + (2 if layout.chunk_strategy == "jitter" else 0)
        q_bytes, k_bytes, dec_payloads = crypto_chunk_bytes(
            crypto_plan, "pool", sl.index, sl.blob, sl.key
        )
        qplan = make_chunk_plan(
            q_bytes,
            _plan_rng(b.build_id, sl.index, "blob"),
            assembly=layout.chunk_assembly,
            strategy=layout.chunk_strategy,
            max_chunk_bytes=cfg["max_chunk_bytes"],
            min_chunks=cfg["min_chunks"],
            max_extra=extra,
            hard_cap=cfg["hard_cap"],
        )
        kplan = make_chunk_plan(
            k_bytes,
            _plan_rng(b.build_id, sl.index, "key"),
            assembly=layout.chunk_assembly,
            strategy=layout.chunk_strategy,
            max_chunk_bytes=cfg["max_chunk_bytes"],
            min_chunks=cfg["min_chunks"],
            max_extra=extra,
            hard_cap=cfg["hard_cap"],
        )
        b.chunk_plans.append({
            "slice": sl.index,
            "blob": qplan.summary(),
            "key": kplan.summary(),
        })
        add("do")
        qget = emit_chunk_getter(add, ns, qplan, "  ")
        kget = emit_chunk_getter(add, ns, kplan, "  ")
        q, kq, ok = ns.fresh_runtime(), ns.fresh_runtime(), ns.fresh_runtime()
        ensure = ns.fresh_runtime()
        db = ns.fresh_runtime()
        meta = ns.fresh_runtime()
        cache = ns.fresh_runtime()
        seen = ns.fresh_runtime()
        prep = ns.fresh_runtime()
        jvar = ns.fresh_runtime()
        nums = ns.fresh_runtime()
        kvar = ns.fresh_runtime()
        cvar = ns.fresh_runtime()
        decode = ns.fresh_runtime()
        perm = [sl.order.index(i) for i in range(3)]

        add(f"  local {q}, {kq}, {ok}")
        add(f"  local {ensure} = function()")
        add(f"    if {q} then return end")
        add(f"    {q} = {qget}()")
        add(f"    {kq} = {kget}()")
        for line in emit_decrypt_lines(
            crypto_plan, dec_payloads, q, kq, ok, indent="    "
        ):
            add(line)
        add(f"    {ok} = true")
        if integrity:
            add("\n".join(emit_verify_lines(
                ns, q, kq, sl.hash_params, ok_var=ok, indent="    "
            )))
        add("  end")
        add(f"  local {db} = function(j)")
        add(f"    {ensure}()")
        add(f"    if not {ok} then return 0 end")
        add(f"    local c = string.byte({q}, j + 1)")
        add(f"    local k = string.byte({kq}, ((j + {sl.salt}) % #{kq}) + 1)")
        add(
            f"    return (c - k - j * {sl.delta} - "
            f"math.floor(j / 8) * {sl.gamma}) % 256"
        )
        add("  end")
        add(f"  local {meta}, {cache}, {seen} = nil, {{}}, {{}}")
        add(f"  local {prep} = function()")
        add(f"    if {meta} then return end")
        add(f"    {ensure}()")
        add(f"    if not {ok} then {meta} = {{}} return end")
        add(
            f"    local ml = {db}(0) * 16777216 + {db}(1) * 65536 + "
            f"{db}(2) * 256 + {db}(3)"
        )
        add(f"    {meta} = {{}}")
        add(f"    local {jvar} = 4")
        add(f"    while {jvar} < ml + 4 do")
        add(f"      local {nums}, {kvar} = {{ 0, 0, 0 }}, 1")
        add("      while true do")
        add(f"        local {cvar} = {db}({jvar})")
        add(f"        {jvar} = {jvar} + 1")
        add(f"        if {cvar} == 44 then {kvar} = {kvar} + 1")
        add(f"        elseif {cvar} == 59 then break")
        add(
            f"        elseif {cvar} >= 48 and {cvar} <= 57 then "
            f"{nums}[{kvar}] = {nums}[{kvar}] * 10 + {cvar} - 48"
        )
        add("        end")
        add("      end")
        add(
            f"      {meta}[#{meta} + 1] = "
            f"{{ {nums}[{perm[0] + 1}], {nums}[{perm[1] + 1}], "
            f"({nums}[{perm[2] + 1}] - {sl.tag_rot}) % 4 }}"
        )
        add("    end")
        add("  end")
        add(f"  local {decode} = function(l)")
        add(f"    {ensure}()")
        add(f"    if not {ok_all} or not {ok} then return nil end")
        add(f"    local c = {cache}[l]")
        add("    if c ~= nil then return c end")
        add(f"    if {seen}[l] then return nil end")
        add(f"    {prep}()")
        add(f"    local e = {meta}[l]")
        add("    if not e then return nil end")
        parts = ns.fresh_runtime()
        order_b = ns.fresh_runtime()
        kvar2 = ns.fresh_runtime()
        ci = ns.fresh_runtime()
        svar = ns.fresh_runtime()
        add(f"    local {parts} = {{}}")
        add(
            f"    local {order_b} = e[2] - 1 + "
            f"2 * ({layout.const_bias} + {layout.const_span})"
        )
        add(f"    for {kvar2} = 1, e[2] do")
        add(
            f"      local {ci} = (({kvar2} - 1) * -1 "
            f"+ {order_b}) % e[2] + 1"
        )
        add(
            f"      {parts}[{ci}] = "
            f"string.char({db}(e[1] + {ci} - 1))"
        )
        add("    end")
        add(f'    local {svar} = ""')
        add(
            f"    for {kvar2} = 1, e[2] do "
            f"{svar} = {svar} .. {parts}[{kvar2}] end"
        )
        add(f"    local s = {svar}")
        add("    local r")
        add("    if e[3] == 1 then r = s")
        add("    elseif e[3] == 2 then r = tonumber(s)")
        add(f"    elseif e[3] == 3 then r = ({db}(e[1]) == 49)")
        add("    else r = nil end")
        add(f"    {cache}[l] = r")
        add(f"    {seen}[l] = true")
        add("    return r")
        add("  end")

        matrix = ns.group_matrix("pool_byte", sl.index)
        for bank, row in enumerate(matrix):
            for g, expr in enumerate(row, 1):
                add(f"  {expr} = function(i, t, s, l)")
                add(f"    if not {ok_all} then return nil end")
                add(
                    "    " + layout.guard_line(
                        "pool_byte", "i", bank, g, "nil", ticket_var="t"
                    )
                )
                add(f"    return {decode}(l)")
                add("  end")
        add(f"  {ps}[{sl.index}] = function(i, t, s, l)")
        add(
            f"    if t ~= {layout.chain_ticket_expr('slice', 'i')} "
            "then return nil end"
        )
        add(
            "    return " + layout.function_selector(
                "pool_byte", "i", ["s", "l"], ns, matrix=matrix
            )
        )
        add("  end")
        add("end")

    S, A, Bv = b.slice_count, b.slice_stride, b.slice_shift
    d_matrix = ns.group_matrix("constant")
    for bank, row in enumerate(d_matrix):
        for g, expr in enumerate(row, 1):
            add(f"{expr} = function(i, t)")
            add(f"  if not {ok_all} then return nil end")
            add(
                "  " + layout.guard_line(
                    "constant", "i", bank, g, "nil", ticket_var="t"
                )
            )
            add(f"  local p = ((i - 1) % {S}) + 1")
            add(f"  local s = ((p - 1) * {A} + {Bv}) % {S} + 1")
            add(f"  local l = math.floor((i - 1) / {S}) + 1")
            add(f"  local t1 = {layout.chain_ticket_expr('slice', 'i')}")
            add(f"  return {ps}[s](i, t1, s, l)")
            add("end")

    integrity_names = (
        ns.group_names("constant")
        + ns.all_slice_names("pool_byte")
        + [f"{ps}[{s}]" for s in range(1, b.slice_count + 1)]
    )
    for line in emit_group_integrity_lines(ns, integrity_names, ok_all):
        add(line)

    if place_id is not None or game_id is not None:
        conds = []
        if place_id is not None:
            conds.append(f"g[{C(idx_place)}] ~= {C(idx_pid)}")
        if game_id is not None:
            conds.append(f"g[{C(idx_gameid)}] ~= {C(idx_gid)}")
        add("do")
        add(f"  local g = {E}[{C(idx_game)}]")
        add("  if g and (" + " or ".join(conds) + ") then return end")
        add("end")
    return "\n".join(L) + "\n"


def render_runtime(
    ns: Names,
    b: PoolBuild,
    *,
    layout: Layout,
    place_id: int | None = None,
    game_id: int | None = None,
    idx_game: int | None = None,
    idx_place: int | None = None,
    idx_gameid: int | None = None,
    idx_pid: int | None = None,
    idx_gid: int | None = None,
    integrity: bool = True,
    anti_env: bool = False,
    anti_tamper: bool = False,
    extra_hash: int | None = None,
    extra_hash_seed: int = 0x9E3779B9,
    runtime_consts: dict[str, int] | None = None,
    vm: bool = False,
    stealth_plan: object | None = None,
    crypto_plan: CryptoPlan | None = None,
) -> str:
    if vm:
        return _render_vm_runtime(
            ns, b, layout=layout,
            place_id=place_id, game_id=game_id,
            idx_game=idx_game, idx_place=idx_place,
            idx_gameid=idx_gameid, idx_pid=idx_pid, idx_gid=idx_gid,
            integrity=integrity, anti_env=anti_env,
            anti_tamper=anti_tamper, extra_hash=extra_hash,
            extra_hash_seed=extra_hash_seed,
            runtime_consts=runtime_consts,
            stealth_plan=stealth_plan,
            crypto_plan=crypto_plan,
        )
    return _render_source_runtime(
        ns, b, layout=layout,
        place_id=place_id, game_id=game_id,
        idx_game=idx_game, idx_place=idx_place,
        idx_gameid=idx_gameid, idx_pid=idx_pid, idx_gid=idx_gid,
        integrity=integrity, anti_env=anti_env,
        anti_tamper=anti_tamper, extra_hash=extra_hash,
        extra_hash_seed=extra_hash_seed,
        runtime_consts=runtime_consts,
        stealth_plan=stealth_plan,
        crypto_plan=crypto_plan,
    )
