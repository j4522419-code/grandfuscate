"""Generates the third-pass, group-scattered Luau interpreter for the VM IR.

There is no sequential `CODE`/`NODES` table, no central `EVAL`/`EXEC` router,
no central `W`/`NODE`/`D` decoder and no stable frame-field names. Words,
nodes, constants and byte fragments are decoded by independently guarded
generated routines; handlers live in per-build groups keyed by random opcodes.
These are obfuscation encodings, not encryption.
"""
from __future__ import annotations

from ..checksum import emit_group_integrity_lines
from ..layout import Layout
from ..pool import PoolBuild
from ..render import Context
from .compiler import Program, BIN_OPS, UN_OPS
from .fragments import emit_fragments
from .nodes import emit_nodes


_BIN_EXPR = {
    "Add": "a + b", "Sub": "a - b", "Mul": "a * b", "Div": "a / b",
    "FloorDiv": "a // b", "Mod": "a % b", "Pow": "a ^ b", "Concat": "a .. b",
    "CompareEq": "a == b", "CompareNe": "a ~= b", "CompareLt": "a < b",
    "CompareLe": "a <= b", "CompareGt": "a > b", "CompareGe": "a >= b",
}
_UN_EXPR = {"Not": "not a", "Minus": "-a", "Len": "#a"}


def render(
    program: Program,
    ctx: Context,
    built: PoolBuild,
    *,
    layout: Layout,
    runtime_consts: dict[str, int],
) -> str:
    ns = ctx.names
    rng = ctx.rng
    N = ns.N
    keys = (
        "EH", "SH", "BH", "UH", "LH", "GH", "VAR", "SETVAR", "DECL",
        "SNAP", "APPLYBIN", "APPLYUN", "INVOKE", "DOCALL", "CLOSURE",
        "CMAP", "PACK", "fr", "sig", "OPOF", "LENOFD", "ARGOF", "ARG",
    )
    R = {k: ns.fresh_runtime(k) for k in keys}
    O = program.opcodes
    add = (L := []).append
    ev_table = ns.group_tables["eval"]
    ex_table = ns.group_tables["exec"]
    eval_names = ns.group_names("eval")
    exec_names = ns.group_names("exec")
    ok_eval, ok_exec = ns.fresh_runtime(), ns.fresh_runtime()

    def C(expr: str | int) -> str:
        return layout.function_selector("constant", str(expr), [], ns)

    def ND(expr: str | int) -> str:
        return layout.function_selector("node", str(expr), [], ns)

    def EV(expr: str | int, fr: str = "fr") -> str:
        return layout.function_selector("eval", str(expr), [fr], ns)

    def EX(expr: str | int, fr: str = "fr") -> str:
        return layout.function_selector("exec", str(expr), [fr], ns)

    def slot(table: str, code: int) -> str:
        return layout.vm_assign(R[table], code)

    def handler(table: str, var: str) -> str:
        return layout.vm_handler(R[table], var)

    def E(i: int) -> str:
        return f"{R['ARG']}(nd, {i})"

    # Forward declarations for mutually recursive helpers. Group functions are
    # assigned after handler tables; handler closures capture these upvalues.
    forward = [
        R[k] for k in (
            "INVOKE", "DOCALL", "CLOSURE", "CMAP", "VAR", "SETVAR",
            "DECL", "SNAP", "APPLYBIN", "APPLYUN",
        )
    ]
    add(f"local {ok_eval}, {ok_exec} = true, true")
    for line in layout.init_group_table_lines(ev_table, "eval", ns):
        add(line)
    for line in layout.init_group_table_lines(ex_table, "exec", ns):
        add(line)
    add("local " + ", ".join(forward))

    add(f"local {R['PACK']} = function(...)")
    add("  local r = table.pack(...)")
    add(f"  r[{layout.field('n')}] = select(\"#\", ...)")
    add("  return r")
    add("end")

    # Independent, lazily assembled stream fragments and guarded byte groups.
    emit_fragments(add, ns, program, ctx, R, layout)
    # Guarded word/node groups and per-node operand reconstruction.
    emit_nodes(add, ns, program, R, layout)

    for table_key in ("EH", "SH", "BH", "UH", "LH", "GH"):
        for line in layout.init_vm_handler_lines(
            R[table_key], ns.fresh_runtime(), ns.fresh_runtime()
        ):
            add(line)

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
        f"{{ __mode = {C(runtime_consts['weak_k'])} }})"
    )
    add(f"{R['CLOSURE']} = function(pi, fr)")
    add(f"  local up = {R['SNAP']}(fr)")
    add("  local fn = function(...)")
    add(f"    local r = {R['INVOKE']}({{ proto = pi, up = up }}, {R['PACK']}(...))")
    add("    return table.unpack(r, 1, r.n)")
    add("  end")
    add(f"  {R['CMAP']}[fn] = {{ proto = pi, up = up }}")
    add("  return fn")
    add("end")

    bin_lines = [
        f"{slot('BH', program.binmap[name])} = function(a, b) "
        f"return {_BIN_EXPR[name]} end"
        for name in BIN_OPS
    ]
    for _ in range(3):
        bin_lines.append(
            f"{slot('BH', rng.randrange(1, 1 << 32))} = "
            "function(a, b) return a - b end"
        )
    rng.shuffle(bin_lines)
    add("\n".join(bin_lines))
    add(f"{R['APPLYBIN']} = function(c, a, b)")
    add(f"  local h = {handler('BH', 'c')}")
    add("  if h then return h(a, b) end")
    add("  return nil")
    add("end")

    un_lines = [
        f"{slot('UH', program.unmap[name])} = function(a) "
        f"return {_UN_EXPR[name]} end"
        for name in UN_OPS
    ]
    rng.shuffle(un_lines)
    add("\n".join(un_lines))
    add(f"{R['APPLYUN']} = function(c, a)")
    add(f"  local h = {handler('UH', 'c')}")
    add("  if h then return h(a) end")
    add("  return nil")
    add("end")

    add(f"{R['DOCALL']} = function(f, args)")
    add(f"  local m = {R['CMAP']}[f]")
    add(f"  if m then return {R['INVOKE']}(m, args) end")
    add(f"  return {R['PACK']}(f(table.unpack(args, 1, args.n)))")
    add("end")

    set_lines = [
        (
            O["VAR"],
            f"{slot('LH', O['VAR'])} = function(nd, v, fr) "
            f"{R['SETVAR']}(fr, {E(1)}, v) end",
        ),
        (
            O["GLOBAL"],
            f"{slot('LH', O['GLOBAL'])} = function(nd, v, fr) "
            f"{N('E')}[{C(E(1))}] = v end",
        ),
        (
            O["INDEX"],
            f"{slot('LH', O['INDEX'])} = function(nd, v, fr) "
            f"local t = {EV(E(1))}[1]; "
            f"local k = {EV(E(2))}[1]; t[k] = v end",
        ),
        (
            O["INDEXNAME"],
            f"{slot('LH', O['INDEXNAME'])} = function(nd, v, fr) "
            f"local t = {EV(E(1))}[1]; "
            f"t[{C(E(2))}] = v end",
        ),
    ]
    for d in program.decoy_opcodes[:2]:
        set_lines.append((d, f"{slot('LH', d)} = function() end"))
    rng.shuffle(set_lines)
    for _code, line in set_lines:
        add(line)

    get_lines = [
        (
            O["VAR"],
            f"{slot('GH', O['VAR'])} = function(nd, fr) "
            f"return {R['VAR']}(fr, {E(1)}) end",
        ),
        (
            O["GLOBAL"],
            f"{slot('GH', O['GLOBAL'])} = function(nd, fr) "
            f"return {N('E')}[{C(E(1))}] end",
        ),
        (
            O["INDEX"],
            f"{slot('GH', O['INDEX'])} = function(nd, fr) "
            f"local t = {EV(E(1))}[1]; "
            f"local k = {EV(E(2))}[1]; return t[k] end",
        ),
        (
            O["INDEXNAME"],
            f"{slot('GH', O['INDEXNAME'])} = function(nd, fr) "
            f"local t = {EV(E(1))}[1]; "
            f"return t[{C(E(2))}] end",
        ),
    ]
    for d in program.decoy_opcodes[2:4]:
        get_lines.append((d, f"{slot('GH', d)} = function() return nil end"))
    rng.shuffle(get_lines)
    for _code, line in get_lines:
        add(line)

    add(f"{R['INVOKE']} = function(f, args)")
    add(f"  local nd = {ND('f.proto')}")
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
    add(f"  local s = {EX(f'{R['ARG']}(nd, 3 + np)', 'fr2')}")
    add("  if s and s[1] == 3 then return s[2] end")
    add("  return { n = 0 }")
    add("end")

    # ------------------------------------------------------------------ EVAL
    eval_branches: list[tuple[int, str]] = []
    eval_branches.append((O["CONST"], f"  return {R['PACK']}({C(E(1))})"))
    eval_branches.append((O["NIL"], f"  return {R['PACK']}(nil)"))
    eval_branches.append((O["VAR"], f"  return {R['PACK']}({R['VAR']}(fr, {E(1)}))"))
    eval_branches.append((O["GLOBAL"], f"  return {R['PACK']}({N('E')}[{C(E(1))}])"))
    eval_branches.append((O["BIN"], f"  return {R['PACK']}({R['APPLYBIN']}({E(1)}, {EV(E(2))}[1], {EV(E(3))}[1]))"))
    eval_branches.append((O["UN"], f"  return {R['PACK']}({R['APPLYUN']}({E(1)}, {EV(E(2))}[1]))"))
    eval_branches.append((O["AND"], "\n".join([
        f"  local l = {EV(E(1))}",
        "  if not l[1] then return l end",
        f"  return {EV(E(2))}",
    ])))
    eval_branches.append((O["OR"], "\n".join([
        f"  local l = {EV(E(1))}",
        "  if l[1] then return l end",
        f"  return {EV(E(2))}",
    ])))
    eval_branches.append((O["CALL"], "\n".join([
        f"  local f = {EV(E(1))}[1]",
        f"  local na = {E(2)}",
        "  local args = { n = 0 }",
        "  for i = 1, na - 1 do",
        f"    local r = {EV(f'{R['ARG']}(nd, 2 + i)')}",
        "    args.n = args.n + 1; args[args.n] = r[1]",
        "  end",
        "  if na > 0 then",
        f"    local r = {EV(f'{R['ARG']}(nd, 2 + na)')}",
        "    for j = 1, r.n do args.n = args.n + 1; args[args.n] = r[j] end",
        "  end",
        f"  return {R['DOCALL']}(f, args)",
    ])))
    eval_branches.append((O["SELFCALL"], "\n".join([
        f"  local obj = {EV(E(1))}[1]",
        f"  local f = obj[{C(E(2))}]",
        f"  local na = {E(3)}",
        "  local args = { n = 1, obj }",
        "  for i = 1, na - 1 do",
        f"    args.n = args.n + 1; args[args.n] = {EV(f'{R['ARG']}(nd, 3 + i)')}[1]",
        "  end",
        "  if na > 0 then",
        f"    local r = {EV(f'{R['ARG']}(nd, 3 + na)')}",
        "    for j = 1, r.n do args.n = args.n + 1; args[args.n] = r[j] end",
        "  end",
        f"  return {R['DOCALL']}(f, args)",
    ])))
    eval_branches.append((O["INDEX"], "\n".join([
        f"  local t = {EV(E(1))}[1]",
        f"  local k = {EV(E(2))}[1]",
        f"  return {R['PACK']}(t[k])",
    ])))
    eval_branches.append((O["INDEXNAME"], "\n".join([
        f"  local t = {EV(E(1))}[1]",
        f"  return {R['PACK']}(t[{C(E(2))}])",
    ])))
    eval_branches.append((O["TABLE"], "\n".join([
        "  local t = {}",
        f"  local n = {E(1)}",
        "  local li = 0",
        "  for i = 1, n do",
        f"    local kind = {R['ARG']}(nd, 2 + (i - 1) * 3)",
        f"    local kv = {R['ARG']}(nd, 3 + (i - 1) * 3)",
        f"    local vi = {R['ARG']}(nd, 4 + (i - 1) * 3)",
        f"    local r = {EV('vi')}",
        "    if kind == 0 then",
        "      if i == n then",
        "        for j = 1, r.n do li = li + 1; t[li] = r[j] end",
        "      else",
        "        li = li + 1; t[li] = r[1]",
        "      end",
        f"    elseif kind == 1 then t[{C('kv')}] = r[1]",
        "    else",
        f"      local k = {EV('kv')}[1]",
        "      t[k] = r[1]",
        "    end",
        "  end",
        f"  return {R['PACK']}(t)",
    ])))
    eval_branches.append((O["FUNCTION"], f"  return {R['PACK']}({R['CLOSURE']}({E(1)}, fr))"))
    eval_branches.append((O["VARARGS"], "  return fr.VA"))
    eval_branches.append((O["INTERP"], "\n".join([
        f"  local n = {E(1)}",
        f"  local parts = {{ {C(E(2))} }}",
        "  for i = 1, n do",
        f"    parts[#parts + 1] = tostring({EV(f'{R['ARG']}(nd, 2 * i + 1)')}[1])",
        f"    parts[#parts + 1] = {C(f'{R['ARG']}(nd, 2 * i + 2)')}",
        "  end",
        f"  local s = \"\"",
        f"  for j = 1, #parts do s = s .. parts[j] end",
        f"  return {R['PACK']}(s)",
    ])))
    eval_branches.append((O["IFELSE"], "\n".join([
        f"  if {EV(E(1))}[1] then return {EV(E(2))} end",
        f"  return {EV(E(3))}",
    ])))
    eval_branches.append((O["PROTO"], f"  return {R['PACK']}(nil)"))
    for d in program.decoy_opcodes[:4]:
        eval_branches.append((d, f"  return {R['PACK']}(nil)"))
    rng.shuffle(eval_branches)
    for code, body in eval_branches:
        add(f"{slot('EH', code)} = function(nd, fr)")
        add(body)
        add("end")

    # ------------------------------------------------------------------ EXEC
    exec_branches: list[tuple[int, str]] = []
    exec_branches.append((O["BLOCK"], "\n".join([
        f"  for i = 1, {E(1)} do",
        f"    local s = {EX(f'{R['ARG']}(nd, 1 + i)')}",
        "    if s then return s end",
        "  end",
        "  return nil",
    ])))
    exec_branches.append((O["NOP"], "  return nil"))
    exec_branches.append((O["BREAK"], "  return { 1 }"))
    exec_branches.append((O["CONTINUE"], "  return { 2 }"))
    exec_branches.append((O["EXPR"], f"  {EV(E(1))}; return nil"))
    exec_branches.append((O["RETURN"], "\n".join([
        f"  local m = {E(1)}",
        "  local vals = { n = 0 }",
        "  for j = 1, m do",
        f"    local r = {EV(f'{R['ARG']}(nd, 1 + j)')}",
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
        f"    local r = {EV(f'{R['ARG']}(nd, 2 + nv + j)')}",
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
    assign_body = "\n".join([
        f"  local nv = {E(1)}",
        f"  local m = {R['ARG']}(nd, 2 + nv)",
        "  local vals = { n = 0 }",
        "  for j = 1, m do",
        f"    local r = {EV(f'{R['ARG']}(nd, 2 + nv + j)')}",
        "    if j == m then",
        "      for k = 1, r.n do vals.n = vals.n + 1; vals[vals.n] = r[k] end",
        "    else",
        "      vals.n = vals.n + 1; vals[vals.n] = r[1]",
        "    end",
        "  end",
        "  for i = 1, nv do",
        f"    local lv = {ND(f'{R['ARG']}(nd, 1 + i)')}",
        f"    local op = {R['OPOF']}(lv)",
        f"    local h = {handler('LH', 'op')}",
        "    if h then h(lv, vals[i], fr) end",
        "  end",
        "  return nil",
    ])
    exec_branches.append((O["ASSIGN"], assign_body))
    exec_branches.append((O["LOCALFUNC"], "\n".join([
        f"  {R['DECL']}(fr, {E(1)}, nil)",
        f"  {R['SETVAR']}(fr, {E(1)}, {R['CLOSURE']}({E(2)}, fr))",
        "  return nil",
    ])))
    exec_branches.append((O["FUNCSTMT"], "\n".join([
        f"  local lv = {ND(E(1))}",
        f"  local op = {R['OPOF']}(lv)",
        f"  local h = {handler('LH', 'op')}",
        f"  if h then h(lv, {R['CLOSURE']}({E(2)}, fr), fr) end",
        "  return nil",
    ])))
    exec_branches.append((O["COMPOUND"], "\n".join([
        f"  local lv = {ND(E(1))}",
        f"  local op = {R['OPOF']}(lv)",
        f"  local gh = {handler('GH', 'op')}",
        "  local cur = nil",
        "  if gh then cur = gh(lv, fr) end",
        f"  local lh = {handler('LH', 'op')}",
        f"  local v = {R['APPLYBIN']}({E(2)}, cur, {EV(E(3))}[1])",
        "  if lh then lh(lv, v, fr) end",
        "  return nil",
    ])))
    exec_branches.append((O["IF"], "\n".join([
        f"  if {EV(E(1))}[1] then return {EX(E(2))} end",
        f"  if {E(3)} ~= 0 then return {EX(E(3))} end",
        "  return nil",
    ])))
    exec_branches.append((O["WHILE"], "\n".join([
        f"  while {EV(E(1))}[1] do",
        f"    local s = {EX(E(2))}",
        "    if s then",
        "      if s[1] == 1 then break end",
        "      if s[1] == 3 then return s end",
        "    end",
        "  end",
        "  return nil",
    ])))
    exec_branches.append((O["REPEAT"], "\n".join([
        "  while true do",
        f"    local s = {EX(E(1))}",
        "    if s then",
        "      if s[1] == 1 then break end",
        "      if s[1] == 3 then return s end",
        "    end",
        f"    if {EV(E(2))}[1] then break end",
        "  end",
        "  return nil",
    ])))
    exec_branches.append((O["FOR"], "\n".join([
        f"  local a = {EV(E(2))}[1]",
        f"  local b = {EV(E(3))}[1]",
        "  local st = 1",
        f"  if {E(4)} ~= 0 then st = {EV(E(4))}[1] end",
        f"  if st == 0 then error({C(runtime_consts['for_error'])}) end",
        "  local i = a",
        "  while (st > 0 and i <= b) or (st < 0 and i >= b) do",
        f"    {R['DECL']}(fr, {E(1)}, i)",
        f"    local s = {EX(E(5))}",
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
        f"    local r = {EV(f'{R['ARG']}(nd, 2 + nv + j)')}",
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
        f"    local s = {EX(f'{R['ARG']}(nd, 3 + nv + m)')}",
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
        add(f"{slot('SH', code)} = function(nd, fr)")
        add(body)
        add("end")

    eval_matrix = ns.group_matrix("eval")
    for bank, row in enumerate(eval_matrix):
        for g, expr in enumerate(row, 1):
            add(f"{expr} = function(n, t, fr)")
            add(f"  if not {ok_eval} then return {R['PACK']}(nil) end")
            add(
                "  " + layout.guard_line(
                    "eval", "n", bank, g, f"{R['PACK']}(nil)",
                    ticket_var="t",
                )
            )
            add(f"  local nd = {ND('n')}")
            add(f"  local op = {R['OPOF']}(nd)")
            add(f"  local h = {handler('EH', 'op')}")
            add("  if h then return h(nd, fr) end")
            add(f"  return {R['PACK']}(nil)")
            add("end")

    exec_matrix = ns.group_matrix("exec")
    for bank, row in enumerate(exec_matrix):
        for g, expr in enumerate(row, 1):
            add(f"{expr} = function(n, t, fr)")
            add(f"  if not {ok_exec} then return nil end")
            add(
                "  " + layout.guard_line(
                    "exec", "n", bank, g, "nil", ticket_var="t"
                )
            )
            add(f"  local nd = {ND('n')}")
            add(f"  local op = {R['OPOF']}(nd)")
            add(f"  local h = {handler('SH', 'op')}")
            add("  if h then return h(nd, fr) end")
            add("  return nil")
            add("end")

    for line in emit_group_integrity_lines(ns, eval_names, ok_eval):
        add(line)
    for line in emit_group_integrity_lines(ns, exec_names, ok_exec):
        add(line)

    add(f"local {R['fr']} = {{ V = {{}}, UP = {{}}, VA = {{ n = 0 }} }}")
    add(f"local {R['sig']} = {EX(program.entry, R['fr'])}")
    add(
        f"if {R['sig']} and {R['sig']}[1] == 3 then "
        f"return table.unpack({R['sig']}[2], 1, {R['sig']}[2].n) end"
    )
    return "\n".join(L) + "\n"
