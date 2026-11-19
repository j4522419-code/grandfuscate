"""Per-build node representation and distributed operand reconstruction.

Words are read through ticketed word-group functions; logical nodes are
rebuilt by ticketed node-group functions. Operand permutations are derived
from the logical node index, so no global operand expression describes the
whole instruction stream.
"""
from __future__ import annotations

from ..checksum import emit_group_integrity_lines
from ..layout import Layout
from ..names import Names
from .compiler import Program


def emit_nodes(add, ns: Names, program: Program, R: dict, layout: Layout, *, v4=None) -> None:
    op_off = 0 if program.word_order == "op_len" else 1
    len_off = 1 if program.word_order == "op_len" else 0
    style = program.node_style
    O, L, A, ARG = R["OPOF"], R["LENOFD"], R["ARGOF"], R["ARG"]
    vb = R["VBTABLE"]
    wd = ns.group_tables["word"]
    nd = ns.group_tables["node"]
    ok_word, ok_node = ns.fresh_runtime(), ns.fresh_runtime()
    add(f"local {ok_word}, {ok_node} = true, true")
    for line in layout.init_group_table_lines(wd, "word", ns):
        add(line)
    for line in layout.init_group_table_lines(nd, "node", ns):
        add(line)

    def word(expr: str) -> str:
        return layout.function_selector("word", expr, [], ns)

    def byte(expr: str) -> str:
        ticket = layout.chain_ticket_expr("fragment", expr)
        return f"{vb}[f]({expr}, {ticket}, f)"

    word_matrix = ns.group_matrix("word")
    for bank, row in enumerate(word_matrix):
        for g, expr in enumerate(row, 1):
            add(f"{expr} = function(i, t)")
            add(f"  if not {ok_word} then return 0 end")
            add(
                "  " + layout.guard_line(
                    "word", "i", bank, g, "0", ticket_var="t"
                )
            )
            add(f"  local f = math.floor(i / {program.words_per_fragment}) + 1")
            add(f"  local o = (i % {program.words_per_fragment}) * 4")
            add(
                f"  return {byte('o')} * 16777216 + "
                f"{byte('o + 1')} * 65536 + "
                f"{byte('o + 2')} * 256 + {byte('o + 3')}"
            )
            add("end")

    node_matrix = ns.group_matrix("node")
    for bank, row in enumerate(node_matrix):
        for g, expr in enumerate(row, 1):
            add(f"{expr} = function(n, t)")
            add(f"  if not {ok_node} then return nil end")
            add(
                "  " + layout.guard_line(
                    "node", "n", bank, g, "nil", ticket_var="t"
                )
            )
            add(
                f"  local slot = ((n - 1) * {program.offset_stride} + "
                f"{program.offset_shift}) % {program.offset_count} + 1"
            )
            add(f"  local s = {word(f'{program.offset_base} + slot - 1')}")
            if style == "cursor":
                add("  return {")
                add("    NODE_N = n,")
                add(
                    f"    [{program.node_op_selector}] = function() "
                    f"return {word(f's + {op_off}')} end,"
                )
                add(
                    f"    [{program.node_len_selector}] = function() "
                    f"return {word(f's + {len_off}')} end,"
                )
                add(
                    f"    [{program.node_arg_selector}] = function(p) "
                    f"return {word('s + 2 + p - 1')} end"
                )
                add("  }")
            else:
                add(f"  local op = {word(f's + {op_off}')}")
                add(f"  local m = {word(f's + {len_off}')}")
                add("  local a = {}")
                add(
                    f"  for p = 1, m do a[p] = "
                    f"{word('s + 2 + p - 1')} end"
                )
                inner = (
                    f"{{ NODE_N = n, [{program.op_key}] = op, "
                    f"[{program.len_key}] = m, "
                    f"[{program.arg_key}] = a }}"
                )
                if style == "nested":
                    add(
                        f"  return {{ NODE_N = n, "
                        f"[{program.node_outer_key}] = {inner} }}"
                    )
                else:
                    add(f"  return {inner}")
            add("end")

    if style == "sparse":
        add(f"local {O} = function(nd) return nd[{program.op_key}] end")
        add(f"local {L} = function(nd) return nd[{program.len_key}] end")
        add(
            f"local {A} = function(nd, p) "
            f"return nd[{program.arg_key}][p] end"
        )
    elif style == "nested":
        add(
            f"local {O} = function(nd) "
            f"return nd[{program.node_outer_key}][{program.op_key}] end"
        )
        add(
            f"local {L} = function(nd) "
            f"return nd[{program.node_outer_key}][{program.len_key}] end"
        )
        add(
            f"local {A} = function(nd, p) "
            f"return nd[{program.node_outer_key}][{program.arg_key}][p] end"
        )
    else:
        add(
            f"local {O} = function(nd) "
            f"return nd[{program.node_op_selector}]() end"
        )
        add(
            f"local {L} = function(nd) "
            f"return nd[{program.node_len_selector}]() end"
        )
        add(
            f"local {A} = function(nd, p) "
            f"return nd[{program.node_arg_selector}](p) end"
        )

    c = layout.per_node_operand_c
    d = layout.per_node_operand_d
    add(f"local {ARG} = function(nd, i)")
    add(f"  local m = {L}(nd)")
    add(f"  if m == 1 then return {A}(nd, 1) end")
    add("  local n = nd.NODE_N")
    add(f"  local a = ((n * {c} + {d}) % (m - 1)) + 1")
    add(f"  local b = (n * {d} + {c}) % m")
    if program.operand_mode == "xor":
        add(
            "  local p = bit32.band(bit32.bxor(i - 1, "
            "bit32.bor(a, 1)), m - 1) + 1"
        )
    elif program.operand_mode == "reverse":
        add("  local p = ((m - i) * a + b) % m + 1")
    else:
        add("  local p = ((i - 1) * a + b) % m + 1")
    add(f"  return {A}(nd, p)")
    add("end")

    for line in emit_group_integrity_lines(
        ns, ns.group_names("word"), ok_word
    ):
        add(line)
    for line in emit_group_integrity_lines(
        ns, ns.group_names("node"), ok_node
    ):
        add(line)
    if v4 is not None:
        for line in v4.emit_verify_lines(["word"], ok_word):
            add(line)
        for line in v4.emit_verify_lines(["node"], ok_node):
            add(line)
