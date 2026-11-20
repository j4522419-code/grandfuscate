"""V5 opt-in stealth / fail-closed active decoys.

Unlike the V4 ``obf/vm/traps.py`` decoys (a separate inert table that the real
VM never calls), these decoys are **embedded in the real call path**:

* they are assigned into the same real VM handler tables via
  :func:`obf.layout.Layout.vm_assign`, using keys outside the real opcode set;
* :func:`obf.layout.Layout.guard_line` calls ``R(key, ticket)`` on a wrong
  capability ticket instead of returning a harmless default, so a guessed /
  enumerated decoy invocation reaches a reaction immediately;
* the selector ``R`` is itself referenced from every guarded decoder path.

Hard boundary: this cannot crash a third-party env logger / dumper / debugger
process. It can only make the *protected script* fail closed (opaque error or
yield), return garbage, or expose malformed/cyclic bait tables to an
enumerating logger. An analyst can still ``pcall`` errors, patch checks, step
past them, or execute the real path. These are obfuscation decoys, not a
security boundary. No 100% dumper/env-logger defeat claim is made.

All emitted globals are rewritten through the opaque alias table by
``obf/format.py``; the standalone probe script is test-only and uses plain
globals. No dynamic loader, no ``loadstring``, no comments beyond the required
top banner, and no raw symbol soup
outside string literals.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field

# Reaction kinds. An uncaught error unwinds the stack, so all four are
# distributed across the decoy set rather than chained inside one function.
REACTIONS: tuple[str, ...] = ("error", "yield", "garbage", "hybrid")
HANDLER_TABLES: tuple[str, ...] = ("EH", "SH", "BH", "UH", "LH", "GH")


@dataclass
class StealthDecoy:
    index: int
    key: int
    reaction: str
    err: int
    table_key: str


@dataclass
class StealthPlan:
    decoys: list[StealthDecoy] = field(default_factory=list)
    table_var: str = "T"
    bait_var: str = "P"
    react_var: str = "R"
    selector_salt: int = 0
    error_constant: int = 0
    global_digest: int = 0

    @property
    def count(self) -> int:
        return len(self.decoys)

    @property
    def reaction_counts(self) -> dict[str, int]:
        out = {k: 0 for k in REACTIONS}
        for d in self.decoys:
            out[d.reaction] += 1
        return out

    def react_call(self, key_expr: str, ticket_var: str) -> str:
        """Expression used by :func:`Layout.guard_line` on a wrong ticket."""
        return f"{self.react_var}({key_expr}, {ticket_var})"


def _u31(x: int) -> int:
    return x & 0x7FFFFFFF


def make_stealth_plan(
    rng: random.Random,
    ns,
    count: int,
    global_digest: int,
    excluded_keys: set[int],
) -> StealthPlan:
    """Build a deterministic, preset-scaled active-decoy plan."""
    table_var = ns.fresh_runtime("T")
    bait_var = ns.fresh_runtime("P")
    react_var = ns.fresh_runtime("R")
    selector_salt = _u31((global_digest ^ 0x51EA7B12) * 2246822519) or 0x5EED
    error_constant = _u31(global_digest ^ 0x3C6EF372) or 0x5EED
    used: set[int] = set(excluded_keys)
    decoys: list[StealthDecoy] = []
    for i in range(max(0, count)):
        key = rng.randrange(1 << 20, 1 << 31)
        while key in used:
            key = rng.randrange(1 << 20, 1 << 31)
        used.add(key)
        reaction = REACTIONS[i % len(REACTIONS)]
        table_key = HANDLER_TABLES[i % len(HANDLER_TABLES)]
        decoys.append(StealthDecoy(
            index=i + 1,
            key=key,
            reaction=reaction,
            err=error_constant ^ _u31(i * 0x45D9F3B),
            table_key=table_key,
        ))
    return StealthPlan(
        decoys=decoys,
        table_var=table_var,
        bait_var=bait_var,
        react_var=react_var,
        selector_salt=selector_salt,
        error_constant=error_constant,
        global_digest=global_digest,
    )


def emit_stealth_lines(plan: StealthPlan) -> list[str]:
    """Luau lines defining the active decoy table, bait helper and selector.

    Bare globals below (``setmetatable``, ``rawset``, ``error``, ``pcall``,
    ``tostring``, ``bit32.bxor``, ``coroutine.yield``) are rewritten into the
    opaque alias handler table by ``obf/format.py`` before shipping.
    """
    T, P, R = plan.table_var, plan.bait_var, plan.react_var
    N = plan.count
    S = plan.selector_salt
    L: list[str] = []
    L.append(f"local {T} = {{}}")
    # Bait helper: cyclic, huge-length table with error/yield metamethods.
    L.append(f"local {P} = function(e)")
    L.append("  local b = setmetatable({}, {")
    L.append("    __index = function() return b end,")
    L.append("    __len = function() return 2147483647 end,")
    L.append("    __tostring = function() error(e) end,")
    L.append("    __call = function() while true do coroutine.yield() end end")
    L.append("  })")
    L.append("  rawset(b, b, b)")
    L.append("  return b")
    L.append("end")
    for d in plan.decoys:
        e = d.err
        L.append(f"{T}[{d.index}] = function(k, t, ...)")
        if d.reaction == "error":
            L.append(f"  error({e})")
        elif d.reaction == "yield":
            L.append("  while true do coroutine.yield() end")
        elif d.reaction == "garbage":
            L.append(f"  local b = {P}({e})")
            L.append("  return b")
        else:  # hybrid: error + poison; actively emit malformed log bait.
            L.append(f"  local b = {P}({e})")
            L.append("  pcall(tostring, b)")
            L.append("  return b")
        L.append("end")
    L.append(
        f"local {R} = function(k, t, ...) "
        f"local d = {T}[(bit32.bxor(t, {S}) % {N}) + 1] "
        f"if d then return d(k, t, ...) end return nil end"
    )
    return L


def emit_handler_assignments(plan: StealthPlan, layout, table_vars: dict[str, str]) -> list[str]:
    """Assign every decoy into a real VM handler table (not an inert table)."""
    L: list[str] = []
    for d in plan.decoys:
        tv = table_vars[d.table_key]
        slot = layout.vm_assign(tv, d.key)
        L.append(f"{slot} = {plan.table_var}[{d.index}]")
    return L


def make_probe_script(plan: StealthPlan) -> str:
    """Standalone, test-only Luau exercising every decoy under a coroutine.

    Plain globals are fine: this script never goes through the obfuscator.
    Each decoy runs in its own coroutine and is resumed exactly once, so the
    ``yield`` reaction suspends instead of hanging the probe. Error decoys are
    caught by ``pcall``; garbage/hybrid decoys return a table. The script prints
    counts for all four reaction kinds plus ``HANG=0``.
    """
    T, P, R = "T", "P", "R"
    N = plan.count
    S = plan.selector_salt
    lines: list[str] = [
        "local T = {}",
        "local P = function(e)",
        "  local b = setmetatable({}, {",
        "    __index = function() return b end,",
        "    __len = function() return 2147483647 end,",
        "    __tostring = function() error(e) end,",
        "    __call = function() while true do coroutine.yield() end end",
        "  })",
        "  rawset(b, b, b)",
        "  return b",
        "end",
    ]
    for d in plan.decoys:
        e = d.err
        lines.append(f"T[{d.index}] = function(k, t, ...)")
        if d.reaction == "error":
            lines.append(f"  error({e})")
        elif d.reaction == "yield":
            lines.append("  while true do coroutine.yield() end")
        elif d.reaction == "garbage":
            lines.append(f"  local b = P({e})")
            lines.append("  return b")
        else:
            lines.append(f"  local b = P({e})")
            lines.append("  pcall(tostring, b)")
            lines.append("  return b")
        lines.append("end")
    lines.append(
        f"local R = function(k, t, ...) "
        f"local d = T[(bit32.bxor(t, {S}) % {N}) + 1] "
        f"if d then return d(k, t, ...) end return nil end"
    )
    lines.append("local kinds = {" + ", ".join(
        f'"{d.reaction}"' for d in plan.decoys
    ) + "}")
    lines.append("local seen = { error = 0, yield = 0, garbage = 0, hybrid = 0 }")
    lines.append("local checked = 0")
    lines.append(f"for i = 1, {N} do")
    lines.append("  local co = coroutine.create(function()")
    lines.append("    local ok, res = pcall(T[i], 0, 123456789, 0)")
    lines.append("    if not ok then return 'error' end")
    lines.append("    if type(res) == 'table' then return 'table' end")
    lines.append("    return 'other'")
    lines.append("  end)")
    lines.append("  local ok, res = coroutine.resume(co)")
    lines.append("  if coroutine.status(co) == 'suspended' then")
    lines.append("    seen[kinds[i]] = seen[kinds[i]] + 1")
    lines.append("    checked = checked + 1")
    lines.append("  elseif not ok then")
    lines.append("    seen[kinds[i]] = seen[kinds[i]] + 1")
    lines.append("    checked = checked + 1")
    lines.append("  elseif res == 'error' or res == 'table' then")
    lines.append("    seen[kinds[i]] = seen[kinds[i]] + 1")
    lines.append("    checked = checked + 1")
    lines.append("  end")
    lines.append("end")
    lines.append(
        'print("DECOYS=" .. ' + str(N) +
        ' .. " CHECKED=" .. checked'
        ' .. " ERROR=" .. seen.error'
        ' .. " YIELD=" .. seen.yield'
        ' .. " GARBAGE=" .. seen.garbage'
        ' .. " HYBRID=" .. seen.hybrid'
        ' .. " HANG=0")'
    )
    return "\n".join(lines) + "\n"


def stealth_lines_have_loader(lines: list[str]) -> bool:
    """Static guard: no dynamic loader in stealth-emitted code."""
    joined = "\n".join(lines)
    return "loadstring" in joined or "load(" in joined
