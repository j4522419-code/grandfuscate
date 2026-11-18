"""Randomised return-based entrypoint and token-level global alias rewrite.

Normal builds no longer emit top-level `local` declarations. The generated
chunk is one `return` expression whose value is a randomised function/table
entry, chosen from a Luraph-like final-return family and a literal return-IIFE
family. Inside that entry, a per-build handler table replaces fixed global
member chains (`string.byte`, `bit32.bxor`, `table.concat`, ...) with opaque
numeric/string keys. Four environment-boot templates are also randomized, with
direct `getfenv` / `type` fallbacks so executor environments that separate `_G`
from the real globals still work. This raises static-analysis cost without
changing VM semantics and without `loadstring`.
"""
from __future__ import annotations

import random
from dataclasses import dataclass

from . import minify

# Semantic alias -> path in the captured environment. A one-element path is a
# global function/table; a two-element path is a library member.
ALIAS_PATHS: dict[str, tuple[str, ...]] = {
    "SBYTE": ("string", "byte"),
    "SCHAR": ("string", "char"),
    "SGMATCH": ("string", "gmatch"),
    "SMATCH": ("string", "match"),
    "TCONCAT": ("table", "concat"),
    "TPACK": ("table", "pack"),
    "TUNPACK": ("table", "unpack"),
    "MFLOOR": ("math", "floor"),
    "BXOR": ("bit32", "bxor"),
    "BAND": ("bit32", "band"),
    "GETFENV": ("getfenv",),
    "SETMETA": ("setmetatable",),
    "TOSTRING": ("tostring",),
    "TYPE": ("type",),
    "PCALL": ("pcall",),
    "SELECT": ("select",),
    "RAWSET": ("rawset",),
    "TONUMBER": ("tonumber",),
    "PAIRS": ("pairs",),
    "ERROR": ("error",),
    "GETMETATABLE": ("getmetatable",),
    "G": ("_G",),
}

# Token rewrites for single-name globals and `lib.member` chains.
SINGLE_REWRITES: dict[str, str] = {
    "getfenv": "GETFENV",
    "_G": "G",
    "setmetatable": "SETMETA",
    "tostring": "TOSTRING",
    "type": "TYPE",
    "pcall": "PCALL",
    "select": "SELECT",
    "rawset": "RAWSET",
    "tonumber": "TONUMBER",
    "pairs": "PAIRS",
    "error": "ERROR",
    "getmetatable": "GETMETATABLE",
}
MEMBER_REWRITES: dict[tuple[str, str], str] = {
    ("string", "byte"): "SBYTE",
    ("string", "char"): "SCHAR",
    ("string", "gmatch"): "SGMATCH",
    ("string", "match"): "SMATCH",
    ("table", "concat"): "TCONCAT",
    ("table", "pack"): "TPACK",
    ("table", "unpack"): "TUNPACK",
    ("math", "floor"): "MFLOOR",
    ("bit32", "bxor"): "BXOR",
    ("bit32", "band"): "BAND",
}

# Keywords and globals are never treated as local identifiers by the
# token-level renamer below.  Fields reached through `.` / `:` and table keys
# are also preserved, so only locals/parameters get fresh random names.
_LUA_KEYWORDS = frozenset(
    """and break do else elseif end false for function if in local nil not or
    repeat return then true until while continue export type typeof""".split()
)
_GLOBAL_SKIP = frozenset(
    """_G getfenv setfenv loadstring load require print warn game workspace script
    Instance task coroutine debug shared Enum Vector3 CFrame UDim2 Color3
    BrickColor TweenInfo Ray Region3 NumberSequence ColorSequence NumberRange
    PhysicalProperties DateTime Random buffer utf8 os io math string table bit32
    tonumber tostring pairs ipairs select rawset rawget rawequal setmetatable
    getmetatable pcall xpcall error assert next unpack pack tick wait spawn delay
    elapsedTime time collectgarbage gcinfo self""".split()
)

# Two families: Luraph-like final-return chunks and literal return-IIFE shapes.
# The final-return family has a named VM entry `ST` and ends with `return ST(...)`.
SHAPES = ("final_return", "iife", "nested", "table_call", "method_call")


@dataclass
class FormatInfo:
    shape: str
    aliases: int
    decoys: int
    alias_name: str
    env_name: str
    boot_style: str


def _escaped(text: str, rng: random.Random) -> str:
    """Return a quoted Luau string made only of mixed numeric/hex/unicode escapes."""
    out: list[str] = []
    for b in text.encode("ascii"):
        style = rng.choice(("dec", "hex", "uni"))
        if style == "dec":
            out.append(f"\\{b:03d}")
        elif style == "hex":
            out.append(f"\\x{b:02x}")
        else:
            out.append(f"\\u{{{b:x}}}")
    return '"' + "".join(out) + '"'


def _key(rng: random.Random, used: set[str]) -> str:
    while True:
        if rng.random() < 0.72:
            k = str(rng.randrange(1, 10000))
        else:
            alphabet = "lIO_oJiLSjZ"
            s = "".join(rng.choice(alphabet) for _ in range(rng.randint(2, 6)))
            k = _escaped(s, rng)
        if k not in used:
            used.add(k)
            return k


def _tok(kind: str, text: bytes) -> minify.Tok:
    return minify.Tok(kind, text, 0, 0)


def _key_token(key: str) -> minify.Tok:
    if key.startswith('"'):
        return _tok("string", key.encode("latin-1"))
    return _tok("number", key.encode("ascii"))


def _tokens_to_source(tokens: list[minify.Tok]) -> str:
    parts: list[bytes] = []
    prev: minify.Tok | None = None
    for t in tokens:
        if t.kind in ("ws", "comment"):
            continue
        if prev is not None and minify._need_space(prev, t):
            parts.append(b" ")
        parts.append(t.text)
        prev = t
    return b"".join(parts).decode("latin-1")


def _rename_locals(source: str, names, reserved: set[str]) -> str:
    """Give every remaining local/parameter a fresh confusable name.

    This is deliberately token-based: string contents, numeric keys, table
    fields and globals stay untouched.  The alias table and captured env are
    reserved because the boot and rewritten body must keep referring to them.
    """
    tokens = [t for t in minify.tokenize(source.encode("utf-8"))
              if t.kind not in ("ws", "comment")]
    out: list[minify.Tok] = []
    mapping: dict[str, str] = {}
    curly = 0
    for i, t in enumerate(tokens):
        if t.kind == "symbol" and t.text == b"{":
            curly += 1
        elif t.kind == "symbol" and t.text == b"}":
            curly = max(0, curly - 1)
        if t.kind != "name":
            out.append(t)
            continue
        name = t.text.decode("latin-1")
        prev = tokens[i - 1] if i else None
        nxt = tokens[i + 1] if i + 1 < len(tokens) else None
        field = prev is not None and prev.text in (b".", b":")
        named_function = prev is not None and prev.text == b"function"
        table_key = (
            curly > 0
            and nxt is not None
            and nxt.text == b"="
            and prev is not None
            and prev.text in (b"{", b",", b";")
            and prev.text != b"local"
        )
        if (
            name in _LUA_KEYWORDS
            or name in _GLOBAL_SKIP
            or name in reserved
            or field
            or named_function
            or table_key
        ):
            out.append(t)
            continue
        if name not in mapping:
            mapping[name] = names.new()
        out.append(_tok("name", mapping[name].encode("ascii")))
    return _tokens_to_source(out)


def _rewrite(raw: str, alias_name: str, keymap: dict[str, str]) -> str:
    """Replace known global names/member chains with opaque handler-table reads."""
    tokens = minify.tokenize(raw.encode("utf-8"))
    out: list[minify.Tok] = []
    i = 0
    n = len(tokens)
    while i < n:
        t = tokens[i]
        if t.kind in ("ws", "comment"):
            i += 1
            continue
        if t.kind == "name":
            name = t.text.decode("latin-1")
            if name in SINGLE_REWRITES:
                key = keymap[SINGLE_REWRITES[name]]
                out.extend([
                    _tok("name", alias_name.encode()),
                    _tok("symbol", b"["),
                    _key_token(key),
                    _tok("symbol", b"]"),
                ])
                i += 1
                continue
            if (
                name in ("string", "table", "bit32", "math")
                and i + 2 < n
                and tokens[i + 1].kind == "symbol"
                and tokens[i + 1].text == b"."
                and tokens[i + 2].kind == "name"
            ):
                member = tokens[i + 2].text.decode("latin-1")
                semantic = MEMBER_REWRITES.get((name, member))
                if semantic is not None:
                    key = keymap[semantic]
                    out.extend([
                        _tok("name", alias_name.encode()),
                        _tok("symbol", b"["),
                        _key_token(key),
                        _tok("symbol", b"]"),
                    ])
                    i += 3
                    continue
        out.append(t)
        i += 1
    return _tokens_to_source(out)


def _value_expr(env: str, path: tuple[str, ...], rng: random.Random) -> str:
    if len(path) == 1:
        return f"{env}[{_escaped(path[0], rng)}]"
    return f"{env}[{_escaped(path[0], rng)}][{_escaped(path[1], rng)}]"


def _boot(
    env: str,
    alias: str,
    entries: list[str],
    decoy_locals: list[str],
    rng: random.Random,
    names,
) -> tuple[str, str]:
    """Capture globals through one of four per-build boot templates.

    Two templates keep the classic guarded `getfenv()` line; two look the
    function up via escaped `_G` keys and guard it with `type`. Every escaped
    lookup also falls back to the direct `getfenv` / `type` globals, because many
    Roblox executors keep real globals in the function environment while `_G` is
    a separate or empty table. All locals stay inside the returned wrapper,
    never at chunk top level.
    """
    gf = _escaped("getfenv", rng)
    tp = _escaped("type", rng)
    fn = _escaped("function", rng)
    style = rng.randrange(4)
    if style == 0:
        boot_style = "classic_getfenv"
        head = f"local {env}=(getfenv and getfenv())or _G;"
    elif style == 1:
        boot_style = "escaped_getfenv"
        g0 = names.fresh_runtime("G")
        f = names.fresh_runtime("F")
        head = (
            f"local {g0}=_G or{{}};"
            f"local {f}={g0}[{gf}] or getfenv;"
            f"local {env}=({f} and {f}())or {g0};"
        )
    elif style == 2:
        boot_style = "typed_escaped_getfenv"
        g0 = names.fresh_runtime("G")
        f = names.fresh_runtime("F")
        t = names.fresh_runtime("T")
        head = (
            f"local {g0}=_G or{{}};"
            f"local {f}={g0}[{gf}] or getfenv;"
            f"local {t}={g0}[{tp}] or type;"
            f"local {env}=({t} and {t}({f})=={fn} and {f}())or {g0};"
        )
    else:
        boot_style = "closure_typed_getfenv"
        g0 = names.fresh_runtime("G")
        f = names.fresh_runtime("F")
        t = names.fresh_runtime("T")
        head = (
            f"local {g0}=_G or{{}};"
            f"local {f}={g0}[{gf}] or getfenv;"
            f"local {t}={g0}[{tp}] or type;"
            f"local {env}=(function(v,q,z)"
            f"return(q and q(v)==z and v())or {g0} end)({f},{t},{fn});"
        )
    return (
        head
        + f"local {alias}={{{','.join(entries)}}};"
        + ";".join(decoy_locals)
        + ";",
        boot_style,
    )


def build_entry(raw: str, ctx) -> tuple[str, FormatInfo]:
    """Wrap a generated chunk in a random return-based entry with no top-level locals."""
    rng = random.Random(ctx.opts.seed ^ 0xF0A7C3)
    names = ctx.names
    env = names.fresh_runtime("Env")
    alias = names.fresh_runtime("N")

    used_keys: set[str] = set()
    keymap = {semantic: _key(rng, used_keys) for semantic in ALIAS_PATHS}

    entries: list[str] = []
    for semantic, path in ALIAS_PATHS.items():
        value = (
            env
            if semantic == "G"  # `_G` falls back to the captured environment
            else _value_expr(env, path, rng)
        )
        entries.append(f"[{keymap[semantic]}]={value}")

    decoy_count = rng.randint(6, 12)
    for j in range(decoy_count):
        key = _key(rng, used_keys)
        if rng.random() < 0.5:
            entries.append(f"[{key}]=function(a,b)return a end")
        else:
            entries.append(f"[{key}]=function(...)return ... end")
    rng.shuffle(entries)

    decoy_locals: list[str] = []
    for j in range(rng.randint(2, 5)):
        d = names.fresh_runtime("D")
        value = rng.choice((
            "{1,2,3}",
            "function(a)return a end",
            "function()return nil end",
            f"{alias}[{keymap['TYPE']}]",
        ))
        decoy_locals.append(f"local {d}={value}")

    rewritten = _rewrite(raw, alias, keymap)
    boot, boot_style = _boot(env, alias, entries, decoy_locals, rng, names)
    reserved = {alias, env}
    renamed_boot = _rename_locals(boot, names, reserved)
    renamed_rewritten = _rename_locals(rewritten, names, reserved)
    inner = renamed_boot + renamed_rewritten

    # Randomise between the Luraph-like final-return family and the literal
    # return-IIFE family. Both start with `return` and keep all locals inside.
    if rng.random() < 0.5:
        shape = "final_return"
    else:
        shape = rng.choice(("iife", "nested", "table_call", "method_call"))
    if shape == "final_return":
        st = names.fresh_runtime("ST")
        wrapped = (
            f"return (function(...) {renamed_boot}"
            f"local {st}=function(...) {renamed_rewritten} end;"
            f"return {st}(...) end)(...)"
        )
    elif shape == "iife":
        wrapped = f"return (function(...) {inner} end)(...)"
    elif shape == "nested":
        wrapped = f"return (function(...) return (function(...) {inner} end)(...) end)(...)"
    elif shape == "table_call":
        key = _key(rng, used_keys)
        wrapped = f"return ({{[{key}]=function(...) {inner} end}})[{key}](...)"
    else:  # method_call
        ident = names.fresh_runtime("M")
        wrapped = f"return ({{{ident}=function(...) {inner} end}}).{ident}(...)"

    return wrapped, FormatInfo(
        shape=shape,
        aliases=len(ALIAS_PATHS),
        decoys=decoy_count,
        alias_name=alias,
        env_name=env,
        boot_style=boot_style,
    )
