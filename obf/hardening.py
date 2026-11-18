"""Legacy anti-environment and layered integrity helpers.

Normal builds leave these off: the environment-hook checks could poison the
constant decoder in ordinary Luau/Roblox executors. The legacy FNV helper is
not used by any normal preset. These helpers remain for explicit library
experiments only; they are not a security boundary.
"""
from __future__ import annotations

from .names import Names


def fnv(data: bytes, seed: int = 0x811C9DC5) -> int:
    """32-bit FNV-1a variant used by both Python and generated Luau."""
    h = seed
    for j, c in enumerate(data):
        h ^= c
        h = (h + ((j + 1) % 256) * 16777619) & 0xFFFFFFFF
    return h


def anti_env_capture(ns: Names) -> list[str]:
    """Capture the environment and critical C-function identities once."""
    N = ns.N
    return [
        f"local {N('ENV')} = (getfenv and getfenv()) or _G",
        f"local {N('GETFENV')} = getfenv",
        f"local {N('SBYTE')} = string.byte",
        f"local {N('SCHAR')} = string.char",
        f"local {N('TCONCAT')} = table.concat",
        f"local {N('BXOR')} = bit32 and bit32.bxor",
        f"local {N('BAND')} = bit32 and bit32.band",
        f"local {N('PCALL')} = pcall",
        f"local {N('TYPE')} = type",
        f"local {N('TOSTR')} = tostring",
    ]


def anti_env_check(ns: Names) -> list[str]:
    """Re-check the captured identities; set BAD on a suspicious environment."""
    N = ns.N
    bad = N("BAD")
    return [
        "do",
        f"  local e = {N('ENV')}",
        f"  if {N('GETFENV')} then",
        f"    if {N('GETFENV')}(1) ~= e or {N('GETFENV')}(0) ~= e then {bad} = true end",
        f"    local ok, r = {N('PCALL')}(function() return {N('GETFENV')}(1) end)",
        f"    if not ok or r ~= e then {bad} = true end",
        "  end",
        f"  if string.byte ~= {N('SBYTE')} or string.char ~= {N('SCHAR')} or table.concat ~= {N('TCONCAT')} then {bad} = true end",
        "  if bit32 then",
        f"    if bit32.bxor ~= {N('BXOR')} or bit32.band ~= {N('BAND')} then {bad} = true end",
        "  end",
        f"  if pcall ~= {N('PCALL')} or type ~= {N('TYPE')} or tostring ~= {N('TOSTR')} then {bad} = true end",
        "  if e.getgenv or e.getrenv or e.hookfunction or e.repl or e.deobfuscate or e.__DEOB then",
        f"    {bad} = true",
        "  end",
        "  if debug and debug.gethook then",
        f"    local ok, h = {N('PCALL')}(debug.gethook)",
        f"    if ok and h then {bad} = true end",
        "  end",
        "end",
    ]


def fnv_lines(ns: Names, expr: str, expected: int, seed: int = 0x811C9DC5) -> list[str]:
    """Generate a Luau FNV check over `expr`."""
    N = ns.N
    bad = N("BAD")
    return [
        "do",
        f"  local z = {expr}",
        f"  local h = {seed}",
        "  for j = 1, #z do",
        "    h = bit32.bxor(h, string.byte(z, j))",
        "    h = bit32.band(h + (j % 256) * 16777619, 4294967295)",
        "  end",
        f"  if h ~= {expected} then {bad} = true end",
        "end",
    ]
