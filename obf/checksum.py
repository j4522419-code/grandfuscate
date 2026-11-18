"""Per-build rolling checksums for lightweight, non-destructive integrity checks.

These are obfuscation checksums, not encryption and not a cryptographic MAC.
The coefficients are randomized for every slice/fragment, so the emitted code
does not contain a fixed FNV seed/prime pair.  A mismatch makes that decoder
return a harmless default value; it never deletes files, collects credentials,
poisons the environment, or harms a Roblox user.
"""
from __future__ import annotations

import random
from dataclasses import dataclass


@dataclass(frozen=True)
class ChecksumParams:
    seed: int
    add: int
    k: int
    j_mod: int
    expected: int

    def as_dict(self) -> dict:
        return {
            "seed": self.seed,
            "add": self.add,
            "k": self.k,
            "j_mod": self.j_mod,
            "expected": self.expected,
        }


def checksum(data: bytes, p: ChecksumParams) -> int:
    h = p.seed
    for j, c in enumerate(data, 1):
        h = ((h ^ c) + p.add + (j % p.j_mod) * p.k) % (1 << 32)
    return h


def make_params(rng: random.Random, data: bytes) -> ChecksumParams:
    seed = rng.randrange(1, 1 << 32)
    add = rng.randrange(1, 1 << 20)
    k = rng.randrange(1, 1 << 20)
    j_mod = rng.randrange(97, 251)
    p = ChecksumParams(seed, add, k, j_mod, 0)
    expected = checksum(data, p)
    return ChecksumParams(seed, add, k, j_mod, expected)


def emit_group_integrity_lines(
    ns,
    names: list[str],
    ok_var: str,
    *,
    indent: str = "",
) -> list[str]:
    """Non-destructive check that generated helper functions remain functions.

    A mismatch only makes guarded decoder groups return harmless defaults. No
    environment poisoning, persistence, credential access or debug output.
    """
    if not names:
        return []
    t = ns.fresh_runtime()
    conds = " or ".join(f"type({n}) ~= {t}" for n in names)
    return [
        f"{indent}local {t} = type(function() end)",
        f"{indent}if {conds} then {ok_var} = false end",
    ]


def emit_verify_lines(
    ns,
    blob_expr: str,
    key_expr: str,
    p: ChecksumParams,
    *,
    ok_var: str,
    indent: str = "    ",
) -> list[str]:
    """Generate Luau lines that set `ok_var` false on a checksum mismatch."""
    z = ns.fresh_runtime()
    h = ns.fresh_runtime()
    j = ns.fresh_runtime()
    return [
        f"{indent}local {z} = {blob_expr} .. {key_expr}",
        f"{indent}local {h} = {p.seed}",
        f"{indent}for {j} = 1, #{z} do",
        f"{indent}  {h} = (bit32.bxor({h}, string.byte({z}, {j})) + {p.add} "
        f"+ ({j} % {p.j_mod}) * {p.k}) % (2 ^ 32)",
        f"{indent}end",
        f"{indent}if {h} ~= {p.expected} then {ok_var} = false end",
    ]
