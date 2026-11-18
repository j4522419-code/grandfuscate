"""Generates the distributed Luau constant-pool prelude.

Normal builds do not emit anti-environment poisoning checks.  Each pool slice
has its own encrypted blob, key, byte decoder, metadata parser, cache and
lightweight integrity check; the public `D(i)` name is only a small arithmetic
router.  Decoding is late: a slice's metadata and values are materialised on
the first request for one of its constants.
"""
from __future__ import annotations

from . import hardening
from .names import Names
from .pool import PoolBuild


def render_runtime(
    ns: Names,
    b: PoolBuild,
    *,
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
) -> str:
    if runtime_consts is None:
        raise ValueError("runtime_consts are required")
    N = ns.N
    L: list[str] = []
    add = L.append

    E = N("E")
    B = N("B")
    K = N("K")
    BAD = N("BAD")
    D = N("D")
    DEC = ns.fresh_runtime()

    # Declared before the slice closures so they capture these upvalues.
    add(f"local {D}")
    add(f"local {BAD} = false")
    add(f"local {E} = (getfenv and getfenv()) or _G")
    add(f"local {DEC} = {{}}")

    # Legacy explicit experiments need one combined blob/key expression for the
    # optional FNV helper.  Normal builds never emit this central concatenation.
    if anti_tamper or anti_env:
        add(f"local {B} = " + " .. ".join(s.blob_literal for s in b.slices))
        add(f"local {K} = " + " .. ".join(s.key_literal for s in b.slices))

    if anti_env:
        for line in hardening.anti_env_capture(ns):
            add(line)
        for line in hardening.anti_env_check(ns):
            add(line)

    # Metadata is parsed byte by byte.  Its field order and type tags rotate
    # per slice, so there is no fixed `o:08d,l:06d,t` record signature and the
    # bootstrap cannot recurse through D() looking for a decoder pattern.
    for sl in b.slices:
        q = ns.fresh_runtime()
        kq = ns.fresh_runtime()
        db = ns.fresh_runtime()
        meta = ns.fresh_runtime()
        cache = ns.fresh_runtime()
        seen = ns.fresh_runtime()
        ok = ns.fresh_runtime()
        prep = ns.fresh_runtime()
        jvar = ns.fresh_runtime()
        nums = ns.fresh_runtime()
        kvar = ns.fresh_runtime()
        cvar = ns.fresh_runtime()
        perm = [sl.order.index(i) for i in range(3)]
        add("do")
        add(f"  local {q} = {sl.blob_literal}")
        add(f"  local {kq} = {sl.key_literal}")
        add(f"  local {db} = function(j)")
        add(f"    local c = string.byte({q}, j + 1)")
        add(
            f"    local k = string.byte({kq}, ((j + {sl.salt}) % #{kq}) + 1)"
        )
        add(
            f"    return (c - k - j * {sl.delta} - "
            f"math.floor(j / 8) * {sl.gamma}) % 256"
        )
        add("  end")
        add(f"  local {meta}, {cache}, {seen} = nil, {{}}, {{}}")
        add(f"  local {ok} = true")
        if integrity:
            add("  do")
            add(f"    local z = {q} .. {kq}")
            add("    local h = 2166136261")
            add("    for j = 1, #z do")
            add("      h = bit32.bxor(h, string.byte(z, j))")
            add("      h = bit32.band(h + (j % 256) * 16777619, 4294967295)")
            add("    end")
            add(f"    if h ~= {sl.expected_hash} then {ok} = false end")
            add("  end")
        add(f"  local {prep} = function()")
        add(f"    if {meta} then return end")
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
        add(f"  {DEC}[{sl.index}] = function(i)")
        add(f"    if {BAD} or not {ok} then return nil end")
        add(f"    local c = {cache}[i]")
        add("    if c ~= nil then return c end")
        add(f"    if {seen}[i] then return nil end")
        add(f"    {prep}()")
        add(f"    local e = {meta}[i]")
        add("    if not e then return nil end")
        add("    local t = {}")
        add(
            f"    for j = e[1], e[1] + e[2] - 1 do "
            f"t[#t + 1] = string.char({db}(j)) end"
        )
        add("    local s = table.concat(t)")
        add("    local r")
        add("    if e[3] == 1 then r = s")
        add("    elseif e[3] == 2 then r = tonumber(s)")
        add(f"    elseif e[3] == 3 then r = ({db}(e[1]) == 49)")
        add("    else r = nil end")
        add(f"    {cache}[i] = r")
        add(f"    {seen}[i] = true")
        add("    return r")
        add("  end")
        add("end")

    add(f"{D} = function(i)")
    add(f"  local p = ((i - 1) % {b.slice_count}) + 1")
    add(
        f"  local s = ((p - 1) * {b.slice_stride} + {b.slice_shift}) "
        f"% {b.slice_count} + 1"
    )
    add(f"  local l = math.floor((i - 1) / {b.slice_count}) + 1")
    add(f"  return {DEC}[s](l)")
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
