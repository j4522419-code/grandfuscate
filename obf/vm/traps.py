"""Opaque decoy traps for the v4 VM.

The decoys are plausible-looking VM handler functions that live in an inert,
never-called table. They mirror real ``vm_byte`` / ``word`` / ``node`` /
``constant`` / ``eval`` / ``exec`` signatures. A guessed (wrong) capability
ticket deterministically raises a controlled ``error(<opaque const>)`` with no
hang and no unbounded loop — behaviour option 2 of ``do 1 and 2``. A valid
ticket (a build-time secret a dumper cannot guess) returns a harmless default,
the safety valve against false positives. The real VM path never calls a decoy.

These are obfuscation decoys, not a security boundary: an analyst who executes
the chunk can still observe everything, pcall the errors, or patch the checks.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field

# Shared local/param names, pre-allocated from the build's Names object so that
# every decoy reuses the same identifiers (few distinct names, no collisions).
_PARAM_SLOTS = ("a", "b", "c", "q")


@dataclass
class Decoy:
    key: int
    valid_ticket: int
    salt: int
    g: int
    h: int
    mod: int
    secret: int
    err: int
    default: str
    arity: int


@dataclass
class TrapPlan:
    decoys: list[Decoy] = field(default_factory=list)
    error_constant: int = 0
    global_digest: int = 0
    trap_salt: int = 0
    table_var: str = "T"
    params: tuple[str, ...] = _PARAM_SLOTS

    @property
    def count(self) -> int:
        return len(self.decoys)


def _u31(x: int) -> int:
    return x & 0x7FFFFFFF


def make_trap_plan(
    rng: random.Random,
    integrity,
    count: int,
    ns,
) -> TrapPlan:
    """Build a deterministic, preset-scaled decoy plan bound to the manifest."""
    digest = integrity.global_digest
    trap_salt = integrity.trap_salt
    error_constant = _u31(digest ^ (trap_salt * 2654435761)) or 0x5EED
    table_var = ns.fresh_runtime()
    # Reuse four shared identifiers across all decoys.
    params = tuple(ns.fresh_runtime() for _ in _PARAM_SLOTS)
    decoys: list[Decoy] = []
    used_keys: set[int] = set()
    real_opcodes = set(integrity.real_opcode_values)
    for i in range(count):
        key = rng.randrange(1 << 20, 1 << 31)
        while key in used_keys or key in real_opcodes:
            key = rng.randrange(1 << 20, 1 << 31)
        used_keys.add(key)
        valid_ticket = _u31((digest ^ (trap_salt + i * 0x9E3779B1)) * 2246822519)
        salt = rng.randrange(1, 1 << 30)
        g = rng.randrange(1, 1 << 20)
        h = rng.randrange(1, 1 << 20)
        mod = rng.randrange(1 << 20, 1 << 30)
        bx = valid_ticket ^ salt  # bit32.bxor over 32-bit values
        secret = ((bx & 0xFFFFFFFF) * g + h) % mod
        arity = 2 + (i % 2)  # 2 or 3 params, mirroring different handler shapes
        default = ("0", "nil", "{}", "0")[i % 4]
        decoys.append(Decoy(
            key=key,
            valid_ticket=valid_ticket,
            salt=salt,
            g=g,
            h=h,
            mod=mod,
            secret=secret,
            err=error_constant ^ (i * 0x45D9F3B & 0x7FFFFFFF),
            default=default,
            arity=arity,
        ))
    return TrapPlan(
        decoys=decoys,
        error_constant=error_constant,
        global_digest=digest,
        trap_salt=trap_salt,
        table_var=table_var,
        params=params,
    )


def emit_trap_group_lines(plan: TrapPlan) -> list[str]:
    """Luau lines defining the inert decoy table (production output).

    Globals here (``error``, ``bit32.bxor``, ``type``) are rewritten into the
    opaque alias handler table by ``obf/format.py`` before shipping, so the
    emitted chunk contains no bare forbidden globals.
    """
    L: list[str] = []
    T = plan.table_var
    a, b, c, q = plan.params
    L.append(f"local {T} = {{}}")
    for d in plan.decoys:
        ps = ", ".join([a, b] + ([c] if d.arity == 3 else []))
        L.append(f"{T}[{d.key}] = function({ps})")
        # Opaque predicate: xor + affine + modular arithmetic, no literal
        # true/false and not the junk.py a*a+b pattern. This is the same q the
        # standalone probe computes, so a valid ticket matches d.secret exactly.
        L.append(
            f"  local {q} = (bit32.bxor({b}, {d.salt}) * {d.g} + {d.h}) % {d.mod}"
        )
        # Valid-ticket safety valve -> harmless default (effectively unguessable).
        # Operand order (number == name) deliberately avoids an
        # `if <name> == <number>` dispatch-chain shape in the v3 scanner.
        L.append(f"  if {d.secret} == {q} then return {d.default} end")
        # Plausible-looking type guard, never true, kept for shape only.
        L.append("  if type(function() end) ~= type(function() end) then "
                 f"return {d.default} end")
        # Wrong / guessed ticket -> deterministic controlled error, no loop.
        L.append(f"  error({d.err})")
        L.append("end")
    return L


def make_probe_script(plan: TrapPlan) -> str:
    """Standalone Luau that exercises every decoy (used by tests, not shipped).

    Plain globals are fine here; this file never goes through the obfuscator.
    It asserts: guessed tickets -> controlled error (pcall false); valid ticket
    -> harmless default (pcall true); finite loop, no hang.
    """
    a, b, c, q = "a", "b", "c", "q"
    lines: list[str] = [
        "local T = {}",
        "local wrong, valid_ok, defaults = 0, 0, 0",
    ]
    for idx, d in enumerate(plan.decoys):
        ps = ", ".join([a, b] + ([c] if d.arity == 3 else []))
        L = [
            f"T[{idx + 1}] = function({ps})",
            f"  local {q} = (bit32.bxor({b}, {d.salt}) * {d.g} + {d.h}) % {d.mod}",
            f"  if {q} == {d.secret} then return {d.default} end",
            f"  error({d.err})",
            "end",
        ]
        lines.extend(L)
    # Guessed tickets: a spread of small and large values that never equal the
    # build-time secret tickets.
    guesses = ["0", "1", "2", "3", "7", "13", "42", "99", "255",
               "65535", "123456789", "2147483647", "999999937"]
    # A guess equal to a build-time secret ticket would (correctly) return the
    # harmless default instead of erroring. Exclude those so the probe's
    # WRONG_ERRORS count is exactly count*len(guesses) for every seed.
    secrets = {d.valid_ticket for d in plan.decoys}
    guesses = [g for g in guesses if int(g) not in secrets]
    lines.append("local guesses = {" + ", ".join(guesses) + "}")
    lines.append("local tickets = {" + ", ".join(str(d.valid_ticket)
                 for d in plan.decoys) + "}")
    lines.append(f"for k = 1, {len(plan.decoys)} do")
    lines.append("  for _, g in ipairs(guesses) do")
    lines.append("    local ok = pcall(T[k], 0, g, 0)")
    lines.append("    if not ok then wrong = wrong + 1 end")
    lines.append("  end")
    lines.append("  local ok = pcall(T[k], 0, tickets[k], 0)")
    lines.append("  if ok then valid_ok = valid_ok + 1 end")
    lines.append("end")
    lines.append(f'print("DECOYS={len(plan.decoys)} NGUESSES={len(guesses)} '
                 f'WRONG_ERRORS=" .. wrong '
                 f'.. " VALID_OK=" .. valid_ok .. " HANG=0")')
    return "\n".join(lines) + "\n"


def trap_lines_have_unbounded_loop(lines: list[str]) -> bool:
    """Static guard: trap code must contain no while / repeat / unbounded for."""
    joined = "\n".join(lines)
    return ("while" in joined or "repeat" in joined or "until" in joined)
