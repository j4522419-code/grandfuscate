"""Generates the fragmented, split-dispatch Luau interpreter for the VM IR.

There is no sequential `CODE` array, no `NODES` array and no central `EVAL` /
`EXEC` `if` chain.  Words are decoded lazily from independent encrypted
fragments; nodes are rebuilt as sparse tables on demand; expression and
statement semantics live in shuffled handler tables keyed by random 32-bit
opcodes.
"""
from __future__ import annotations

from ..pool import PoolBuild
from ..render import Context
from .compiler import Program, BIN_OPS, UN_OPS


_BIN_EXPR = {
    "Add": "a + b", "Sub": "a - b", "Mul": "a * b", "Div": "a / b",
    "FloorDiv": "a // b", "Mod": "a % b", "Pow": "a ^ b", "Concat": "a .. b",
    "CompareEq": "a == b", "CompareNe": "a ~= b", "CompareLt": "a < b",
    "CompareLe": "a <= b", "CompareGt": "a > b", "CompareGe": "a >= b",
}
_UN_EXPR = {"Not": "not a", "Minus": "-a", "Len": "#a"}


def fnv(data: bytes) -> int:
    h = 0x811C9DC5
    for j, c in enumerate(data):
        i = j + 1
        h ^= c
        h = (h + (i % 256) * 16777619) & 0xFFFFFFFF
    return h


def render(
    program: Program,
    ctx: Context,
    built: PoolBuild,
    *,
    runtime_consts: dict[str, int],
) -> str:
    ns = ctx.names
    rng = ctx.rng
    N = ns.N
    keys = (
        "DEC", "W", "NODE", "ARG", "EH", "SH", "BH", "UH", "LH", "GH",
        "EVAL", "EXEC", "INVOKE", "SETLV", "GETLV", "DOCALL",
        "CLOSURE", "CMAP", "VAR", "SETVAR", "DECL", "SNAP",
        "APPLYBIN", "APPLYUN", "fr", "sig",
    )
    R = {k: ns.fresh_runtime(k) for k in keys}
    O = program.opcodes
    add = (L := []).append

    # Forward declarations for mutually recursive helpers.  Handler closures
    # below capture these upvalues; they are assigned after the tables are full.
    add(
        "local " + ", ".join(
            R[k] for k in (
                "EVAL", "EXEC", "INVOKE", "SETLV", "GETLV", "DOCALL",
                "CLOSURE", "CMAP", "VAR", "SETVAR", "DECL", "SNAP",
                "APPLYBIN", "APPLYUN",
            )
        )
    )

    # Independent stream fragments.  Each has its own byte decoder and a small
    # distributed integrity check; no single `Q`/`KQ`/`DQ` signature remains.
    add(f"local {R['DEC']} = {{}}")
    for frag in program.fragments:
        q = ns.fresh_runtime()
        kq = ns.fresh_runtime()
        db = ns.fresh_runtime()
        ok = ns.fresh_runtime()
        add("do")
        add(f"  local {q} = {frag.blob_literal}")
        add(f"  local {kq} = {frag.key_literal}")
        add(f"  local {db} = function(j)")
        add(f"    local c = string.byte({q}, j + 1)")
        add(f"    local k = string.byte({kq}, ((j + {frag.salt}) % #{kq}) + 1)")
        add(
            f"    return (c - k - j * {frag.delta} - "
            f"math.floor(j / 8) * {frag.gamma}) % 256"
        )
        add("  end")
        add(f"  local {ok} = true")
        add("  do")
        add(f"    local z = {q} .. {kq}")
        add("    local h = 2166136261")
        add("    for j = 1, #z do")
        add("      h = bit32.bxor(h, string.byte(z, j))")
        add("      h = bit32.band(h + (j % 256) * 16777619, 4294967295)")
        add("    end")
        add(f"    if h ~= {frag.expected_hash} then {ok} = false end")
        add("  end")
        add(f"  {R['DEC']}[{frag.index}] = function(j)")
        add(f"    if not {ok} then return 0 end")
        add(f"    return {db}(j)")
        add("  end")
        add("end")

    add(f"local {R['W']} = function(i)")
    add(f"  local f = math.floor(i / {program.words_per_fragment}) + 1")
    add(f"  local o = (i % {program.words_per_fragment}) * 4")
    add(
        f"  return {R['DEC']}[f](o) * 16777216 + {R['DEC']}[f](o + 1) * 65536 + "
        f"{R['DEC']}[f](o + 2) * 256 + {R['DEC']}[f](o + 3)"
    )
    add("end")

    # Scrambled offset region -> sparse node table.  No central sequential array.
    add(f"local {R['NODE']} = function(n)")
    add(
        f"  local slot = ((n - 1) * {program.offset_stride} + "
        f"{program.offset_shift}) % {program.offset_count} + 1"
    )
    add(f"  local s = {R['W']}({program.offset_base} + slot - 1)")
    add(f"  local op = {R['W']}(s)")
    add(f"  local m = {R['W']}(s + 1)")
    add("  local a = {}")
    add(f"  for p = 1, m do a[p] = {R['W']}(s + 1 + p) end")
    add(
        f"  return {{ [{program.op_key}] = op, [{program.len_key}] = m, "
        f"[{program.arg_key}] = a }}"
    )
    add("end")

    # Logical operand i lives at a per-build affine position.  Decoy slots are
    # filled by the compiler; this helper is not a dispatch function.
    add(f"local {R['ARG']} = function(nd, i)")
    add(f"  local m = nd[{program.len_key}]")
    add(f"  local a = nd[{program.arg_key}]")
    add(
        f"  return a[((i - 1) * {program.operand_stride} + "
        f"{program.operand_shift}) % m + 1]"
    )
    add("end")

    add(
        f"local {R['EH']}, {R['SH']}, {R['BH']}, {R['UH']}, "
        f"{R['LH']}, {R['GH']} = {{}}, {{}}, {{}}, {{}}, {{}}, {{}}"
    )

    # Core variable/upvalue helpers.
    add(f"{R['VAR']} = function(fr, id)")
    add("  local b = fr.V[id] or fr.UP[id]")
    add("  return b and b.v")
    add("end")
    add(f"{R['SETVAR']} = function(fr, id, v)")
    add("  local b = fr.V[id] or fr.UP[id]")
    add("  if b then b.v = v else fr.V[id] = { v = v } end")
    add("end")
    add(f"{R['DECL']} = function(fr, id, v) fr.V[id] = {{ v = v }} end")
    add(f"{R['SNAP']} = function(fr)")
    add("  local up = {}")
    add("  for k, v in pairs(fr.UP) do up[k] = v end")
    add("  for k, v in pairs(fr.V) do up[k] = v end")
    add("  return up")
    add("end")
    add(
        f"{R['CMAP']} = setmetatable({{}}, "
        f"{{ __mode = {N('D')}({runtime_consts['weak_k']}) }})"
    )
    add(f"{R['CLOSURE']} = function(pi, fr)")
    add(f"  local up = {R['SNAP']}(fr)")
    add("  local fn = function(...)")
    add(f"    local r = {R['INVOKE']}({{ proto = pi, up = up }}, table.pack(...))")
    add("    return table.unpack(r, 1, r.n)")
    add("  end")
    add(f"  {R['CMAP']}[fn] = {{ proto = pi, up = up }}")
    add("  return fn")
    add("end")

    # Operator handlers are tables keyed by random 32-bit values, not `if` chains.
    bin_lines = [
        f"{R['BH']}[{program.binmap[name]}] = function(a, b) "
        f"return {_BIN_EXPR[name]} end"
        for name in BIN_OPS
    ]
    for _ in range(3):
        bin_lines.append(
            f"{R['BH']}[{rng.randrange(1, 1 << 32)}] = "
            "function(a, b) return a - b end"
        )
    rng.shuffle(bin_lines)
    add("\n".join(bin_lines))
    add(f"{R['APPLYBIN']} = function(c, a, b)")
    add(f"  local h = {R['BH']}[c]")
    add("  if h then return h(a, b) end")
    add("  return nil")
    add("end")

    un_lines = [
        f"{R['UH']}[{program.unmap[name]}] = function(a) "
        f"return {_UN_EXPR[name]} end"
        for name in UN_OPS
    ]
    rng.shuffle(un_lines)
    add("\n".join(un_lines))
    add(f"{R['APPLYUN']} = function(c, a)")
    add(f"  local h = {R['UH']}[c]")
    add("  if h then return h(a) end")
    add("  return nil")
    add("end")

    add(f"{R['DOCALL']} = function(f, args)")
    add(f"  local m = {R['CMAP']}[f]")
    add(f"  if m then return {R['INVOKE']}(m, args) end")
    add("  return table.pack(f(table.unpack(args, 1, args.n)))")
    add("end")

    def E(i: int) -> str:
        return f"{R['ARG']}(nd, {i})"

    set_lines = [
        (
            O["VAR"],
            f"{R['LH']}[{O['VAR']}] = function(nd, v, fr) "
            f"{R['SETVAR']}(fr, {E(1)}, v) end",
        ),
        (
            O["GLOBAL"],
            f"{R['LH']}[{O['GLOBAL']}] = function(nd, v, fr) "
            f"{N('E')}[{N('D')}({E(1)})] = v end",
        ),
        (
            O["INDEX"],
            f"{R['LH']}[{O['INDEX']}] = function(nd, v, fr) "
            f"local t = {R['EVAL']}({E(1)}, fr)[1]; "
            f"local k = {R['EVAL']}({E(2)}, fr)[1]; t[k] = v end",
        ),
        (
            O["INDEXNAME"],
            f"{R['LH']}[{O['INDEXNAME']}] = function(nd, v, fr) "
            f"local t = {R['EVAL']}({E(1)}, fr)[1]; "
            f"t[{N('D')}({E(2)})] = v end",
        ),
    ]
    for d in program.decoy_opcodes[:2]:
        set_lines.append((d, f"{R['LH']}[{d}] = function() end"))
    rng.shuffle(set_lines)
    for _code, line in set_lines:
        add(line)
    add(f"{R['SETLV']} = function(n, v, fr)")
    add(f"  local nd = {R['NODE']}(n)")
    add(f"  local h = {R['LH']}[nd[{program.op_key}]]")
    add("  if h then h(nd, v, fr) end")
    add("end")

    get_lines = [
        (
            O["VAR"],
            f"{R['GH']}[{O['VAR']}] = function(nd, fr) "
            f"return {R['VAR']}(fr, {E(1)}) end",
        ),
        (
            O["GLOBAL"],
            f"{R['GH']}[{O['GLOBAL']}] = function(nd, fr) "
            f"return {N('E')}[{N('D')}({E(1)})] end",
        ),
        (
            O["INDEX"],
            f"{R['GH']}[{O['INDEX']}] = function(nd, fr) "
            f"local t = {R['EVAL']}({E(1)}, fr)[1]; "
            f"local k = {R['EVAL']}({E(2)}, fr)[1]; return t[k] end",
        ),
        (
            O["INDEXNAME"],
            f"{R['GH']}[{O['INDEXNAME']}] = function(nd, fr) "
            f"local t = {R['EVAL']}({E(1)}, fr)[1]; "
            f"return t[{N('D')}({E(2)})] end",
        ),
    ]
    for d in program.decoy_opcodes[2:4]:
        get_lines.append((d, f"{R['GH']}[{d}] = function() return nil end"))
    rng.shuffle(get_lines)
    for _code, line in get_lines:
        add(line)
    add(f"{R['GETLV']} = function(n, fr)")
    add(f"  local nd = {R['NODE']}(n)")
    add(f"  local h = {R['GH']}[nd[{program.op_key}]]")
    add("  if h then return h(nd, fr) end")
    add("  return nil")
    add("end")

    add(f"{R['INVOKE']} = function(f, args)")
    add(f"  local nd = {R['NODE']}(f.proto)")
    add(f"  local np = {E(1)}")
    add("  local fr2 = { V = {}, UP = f.up, VA = { n = 0 } }")
    add(f"  for i = 1, np do fr2.V[{R['ARG']}(nd, 1 + i)] = {{ v = args[i] }} end")
    add(f"  if {R['ARG']}(nd, 2 + np) == 1 then")
    add("    fr2.VA = { n = 0 }")
    add(
        "    for i = np + 1, args.n do fr2.VA.n = fr2.VA.n + 1; "
        "fr2.VA[fr2.VA.n] = args[i] end"
    )
    add("  end")
    add(f"  local s = {R['EXEC']}({R['ARG']}(nd, 3 + np), fr2)")
    add("  if s and s[1] == 3 then return s[2] end")
    add("  return { n = 0 }")
    add("end")

    # ------------------------------------------------------------------ EVAL
    eval_branches: list[tuple[int, str]] = []
    eval_branches.append((O["CONST"], f"  return table.pack({N('D')}({E(1)}))"))
    eval_branches.append((O["NIL"], "  return table.pack(nil)"))
    eval_branches.append((O["VAR"], f"  return table.pack({R['VAR']}(fr, {E(1)}))"))
    eval_branches.append((O["GLOBAL"], f"  return table.pack({N('E')}[{N('D')}({E(1)})])"))
    eval_branches.append((O["BIN"], f"  return table.pack({R['APPLYBIN']}({E(1)}, {R['EVAL']}({E(2)}, fr)[1], {R['EVAL']}({E(3)}, fr)[1]))"))
    eval_branches.append((O["UN"], f"  return table.pack({R['APPLYUN']}({E(1)}, {R['EVAL']}({E(2)}, fr)[1]))"))
    eval_branches.append((O["AND"], "\n".join([
        f"  local l = {R['EVAL']}({E(1)}, fr)",
        "  if not l[1] then return l end",
        f"  return {R['EVAL']}({E(2)}, fr)",
    ])))
    eval_branches.append((O["OR"], "\n".join([
        f"  local l = {R['EVAL']}({E(1)}, fr)",
        "  if l[1] then return l end",
        f"  return {R['EVAL']}({E(2)}, fr)",
    ])))
    eval_branches.append((O["CALL"], "\n".join([
        f"  local f = {R['EVAL']}({E(1)}, fr)[1]",
        f"  local na = {E(2)}",
        "  local args = { n = 0 }",
        "  for i = 1, na - 1 do",
        f"    local r = {R['EVAL']}({R['ARG']}(nd, 2 + i), fr)",
        "    args.n = args.n + 1; args[args.n] = r[1]",
        "  end",
        "  if na > 0 then",
        f"    local r = {R['EVAL']}({R['ARG']}(nd, 2 + na), fr)",
        "    for j = 1, r.n do args.n = args.n + 1; args[args.n] = r[j] end",
        "  end",
        f"  return {R['DOCALL']}(f, args)",
    ])))
    eval_branches.append((O["SELFCALL"], "\n".join([
        f"  local obj = {R['EVAL']}({E(1)}, fr)[1]",
        f"  local f = obj[{N('D')}({E(2)})]",
        f"  local na = {E(3)}",
        "  local args = { n = 1, obj }",
        "  for i = 1, na - 1 do",
        f"    args.n = args.n + 1; args[args.n] = {R['EVAL']}({R['ARG']}(nd, 3 + i), fr)[1]",
        "  end",
        "  if na > 0 then",
        f"    local r = {R['EVAL']}({R['ARG']}(nd, 3 + na), fr)",
        "    for j = 1, r.n do args.n = args.n + 1; args[args.n] = r[j] end",
        "  end",
        f"  return {R['DOCALL']}(f, args)",
    ])))
    eval_branches.append((O["INDEX"], "\n".join([
        f"  local t = {R['EVAL']}({E(1)}, fr)[1]",
        f"  local k = {R['EVAL']}({E(2)}, fr)[1]",
        "  return table.pack(t[k])",
    ])))
    eval_branches.append((O["INDEXNAME"], "\n".join([
        f"  local t = {R['EVAL']}({E(1)}, fr)[1]",
        f"  return table.pack(t[{N('D')}({E(2)})])",
    ])))
    eval_branches.append((O["TABLE"], "\n".join([
        "  local t = {}",
        f"  local n = {E(1)}",
        "  local li = 0",
        "  for i = 1, n do",
        f"    local kind = {R['ARG']}(nd, 2 + (i - 1) * 3)",
        f"    local kv = {R['ARG']}(nd, 3 + (i - 1) * 3)",
        f"    local vi = {R['ARG']}(nd, 4 + (i - 1) * 3)",
        f"    local r = {R['EVAL']}(vi, fr)",
        "    if kind == 0 then",
        "      if i == n then",
        "        for j = 1, r.n do li = li + 1; t[li] = r[j] end",
        "      else",
        "        li = li + 1; t[li] = r[1]",
        "      end",
        f"    elseif kind == 1 then t[{N('D')}(kv)] = r[1]",
        "    else",
        f"      local k = {R['EVAL']}(kv, fr)[1]",
        "      t[k] = r[1]",
        "    end",
        "  end",
        "  return table.pack(t)",
    ])))
    eval_branches.append((O["FUNCTION"], f"  return table.pack({R['CLOSURE']}({E(1)}, fr))"))
    eval_branches.append((O["VARARGS"], "  return fr.VA"))
    eval_branches.append((O["INTERP"], "\n".join([
        f"  local n = {E(1)}",
        f"  local parts = {{ {N('D')}({E(2)}) }}",
        "  for i = 1, n do",
        f"    parts[#parts + 1] = tostring({R['EVAL']}({R['ARG']}(nd, 2 * i + 1), fr)[1])",
        f"    parts[#parts + 1] = {N('D')}({R['ARG']}(nd, 2 * i + 2))",
        "  end",
        "  return table.pack(table.concat(parts))",
    ])))
    eval_branches.append((O["IFELSE"], "\n".join([
        f"  if {R['EVAL']}({E(1)}, fr)[1] then return {R['EVAL']}({E(2)}, fr) end",
        f"  return {R['EVAL']}({E(3)}, fr)",
    ])))
    eval_branches.append((O["PROTO"], "  return table.pack(nil)"))
    for d in program.decoy_opcodes[:4]:
        eval_branches.append((d, "  return table.pack(nil)"))
    rng.shuffle(eval_branches)
    for code, body in eval_branches:
        add(f"{R['EH']}[{code}] = function(nd, fr)")
        add(body)
        add("end")

    # ------------------------------------------------------------------ EXEC
    exec_branches: list[tuple[int, str]] = []
    exec_branches.append((O["BLOCK"], "\n".join([
        f"  for i = 1, {E(1)} do",
        f"    local s = {R['EXEC']}({R['ARG']}(nd, 1 + i), fr)",
        "    if s then return s end",
        "  end",
        "  return nil",
    ])))
    exec_branches.append((O["NOP"], "  return nil"))
    exec_branches.append((O["BREAK"], "  return { 1 }"))
    exec_branches.append((O["CONTINUE"], "  return { 2 }"))
    exec_branches.append((O["EXPR"], f"  {R['EVAL']}({E(1)}, fr); return nil"))
    exec_branches.append((O["RETURN"], "\n".join([
        f"  local m = {E(1)}",
        "  local vals = { n = 0 }",
        "  for j = 1, m do",
        f"    local r = {R['EVAL']}({R['ARG']}(nd, 1 + j), fr)",
        "    if j == m then",
        "      for k = 1, r.n do vals.n = vals.n + 1; vals[vals.n] = r[k] end",
        "    else",
        "      vals.n = vals.n + 1; vals[vals.n] = r[1]",
        "    end",
        "  end",
        "  return { 3, vals }",
    ])))
    local_body = "\n".join([
        f"  local nv = {E(1)}",
        f"  for i = 1, nv do {R['DECL']}(fr, {R['ARG']}(nd, 1 + i), nil) end",
        f"  local m = {R['ARG']}(nd, 2 + nv)",
        "  local vals = { n = 0 }",
        "  for j = 1, m do",
        f"    local r = {R['EVAL']}({R['ARG']}(nd, 2 + nv + j), fr)",
        "    if j == m then",
        "      for k = 1, r.n do vals.n = vals.n + 1; vals[vals.n] = r[k] end",
        "    else",
        "      vals.n = vals.n + 1; vals[vals.n] = r[1]",
        "    end",
        "  end",
        f"  for i = 1, nv do {R['SETVAR']}(fr, {R['ARG']}(nd, 1 + i), vals[i]) end",
        "  return nil",
    ])
    exec_branches.append((O["LOCAL"], local_body))
    assign_body = "\n".join(
        line for line in local_body.split("\n")
        if f"{R['DECL']}(fr," not in line
    ).replace(
        f"{R['SETVAR']}(fr, {R['ARG']}(nd, 1 + i), vals[i])",
        f"{R['SETLV']}({R['ARG']}(nd, 1 + i), vals[i], fr)",
    )
    exec_branches.append((O["ASSIGN"], assign_body))
    exec_branches.append((O["LOCALFUNC"], "\n".join([
        f"  {R['DECL']}(fr, {E(1)}, nil)",
        f"  {R['SETVAR']}(fr, {E(1)}, {R['CLOSURE']}({E(2)}, fr))",
        "  return nil",
    ])))
    exec_branches.append((O["FUNCSTMT"], f"  {R['SETLV']}({E(1)}, {R['CLOSURE']}({E(2)}, fr), fr); return nil"))
    exec_branches.append((O["COMPOUND"], "\n".join([
        f"  {R['SETLV']}({E(1)}, {R['APPLYBIN']}({E(2)}, {R['GETLV']}({E(1)}, fr), {R['EVAL']}({E(3)}, fr)[1]), fr)",
        "  return nil",
    ])))
    exec_branches.append((O["IF"], "\n".join([
        f"  if {R['EVAL']}({E(1)}, fr)[1] then return {R['EXEC']}({E(2)}, fr) end",
        f"  if {E(3)} ~= 0 then return {R['EXEC']}({E(3)}, fr) end",
        "  return nil",
    ])))
    exec_branches.append((O["WHILE"], "\n".join([
        f"  while {R['EVAL']}({E(1)}, fr)[1] do",
        f"    local s = {R['EXEC']}({E(2)}, fr)",
        "    if s then",
        "      if s[1] == 1 then break end",
        "      if s[1] == 3 then return s end",
        "    end",
        "  end",
        "  return nil",
    ])))
    exec_branches.append((O["REPEAT"], "\n".join([
        "  while true do",
        f"    local s = {R['EXEC']}({E(1)}, fr)",
        "    if s then",
        "      if s[1] == 1 then break end",
        "      if s[1] == 3 then return s end",
        "    end",
        f"    if {R['EVAL']}({E(2)}, fr)[1] then break end",
        "  end",
        "  return nil",
    ])))
    exec_branches.append((O["FOR"], "\n".join([
        f"  local a = {R['EVAL']}({E(2)}, fr)[1]",
        f"  local b = {R['EVAL']}({E(3)}, fr)[1]",
        "  local st = 1",
        f"  if {E(4)} ~= 0 then st = {R['EVAL']}({E(4)}, fr)[1] end",
        f"  if st == 0 then error({N('D')}({runtime_consts['for_error']})) end",
        "  local i = a",
        "  while (st > 0 and i <= b) or (st < 0 and i >= b) do",
        f"    {R['DECL']}(fr, {E(1)}, i)",
        f"    local s = {R['EXEC']}({E(5)}, fr)",
        "    if s then",
        "      if s[1] == 1 then break end",
        "      if s[1] == 3 then return s end",
        "    end",
        "    i = i + st",
        "  end",
        "  return nil",
    ])))
    exec_branches.append((O["FORIN"], "\n".join([
        f"  local nv = {E(1)}",
        f"  local m = {R['ARG']}(nd, 2 + nv)",
        "  local init = { n = 0 }",
        "  for j = 1, m do",
        f"    local r = {R['EVAL']}({R['ARG']}(nd, 2 + nv + j), fr)",
        "    if j == m then",
        "      for k = 1, r.n do init.n = init.n + 1; init[init.n] = r[k] end",
        "    else",
        "      init.n = init.n + 1; init[init.n] = r[1]",
        "    end",
        "  end",
        "  local f = init[1]",
        "  local st = init[2]",
        "  local ctrl = init[3]",
        "  while true do",
        f"    local r = {R['DOCALL']}(f, {{ n = 2, st, ctrl }})",
        "    local v1 = r[1]",
        "    if v1 == nil then break end",
        "    ctrl = v1",
        f"    for i = 1, nv do {R['DECL']}(fr, {R['ARG']}(nd, 1 + i), r[i]) end",
        f"    local s = {R['EXEC']}({R['ARG']}(nd, 3 + nv + m), fr)",
        "    if s then",
        "      if s[1] == 1 then break end",
        "      if s[1] == 3 then return s end",
        "    end",
        "  end",
        "  return nil",
    ])))
    exec_branches.append((O["PROTO"], "  return nil"))
    for d in program.decoy_opcodes[4:]:
        exec_branches.append((d, "  return nil"))
    rng.shuffle(exec_branches)
    for code, body in exec_branches:
        add(f"{R['SH']}[{code}] = function(nd, fr)")
        add(body)
        add("end")

    # Thin routers: no giant `if op == ...` chain remains.
    add(f"{R['EVAL']} = function(n, fr)")
    add(f"  local nd = {R['NODE']}(n)")
    add(f"  local h = {R['EH']}[nd[{program.op_key}]]")
    add("  if h then return h(nd, fr) end")
    add("  return table.pack(nil)")
    add("end")
    add(f"{R['EXEC']} = function(n, fr)")
    add(f"  local nd = {R['NODE']}(n)")
    add(f"  local h = {R['SH']}[nd[{program.op_key}]]")
    add("  if h then return h(nd, fr) end")
    add("  return nil")
    add("end")

    add(f"local {R['fr']} = {{ V = {{}}, UP = {{}}, VA = {{ n = 0 }} }}")
    add(f"local {R['sig']} = {R['EXEC']}({program.entry}, {R['fr']})")
    add(
        f"if {R['sig']} and {R['sig']}[1] == 3 then "
        f"return table.unpack({R['sig']}[2], 1, {R['sig']}[2].n) end"
    )
    return "\n".join(L) + "\n"
