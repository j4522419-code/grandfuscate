"""Token-level frame/record field randomisation.

Generated Luau is first emitted with private placeholder field names (`V`,
`UP`, `VA`, `n`, `v`, `proto`, `up`).  This pass rewrites *only* field accesses
and table keys to per-build random numeric keys.  Local variables named `n` or
`v` are left for the normal identifier renamer, so semantics are unchanged.
"""
from __future__ import annotations

from . import minify


def _tok(kind: str, text: bytes) -> minify.Tok:
    return minify.Tok(kind, text, 0, 0)


def _source(tokens: list[minify.Tok]) -> str:
    out: list[bytes] = []
    prev: minify.Tok | None = None
    for t in tokens:
        if prev is not None and minify._need_space(prev, t):
            out.append(b" ")
        out.append(t.text)
        prev = t
    return b"".join(out).decode("latin-1")


def randomize_fields(source: str, keys: dict[str, int]) -> str:
    tokens = [
        t for t in minify.tokenize(source.encode("utf-8"))
        if t.kind not in ("ws", "comment")
    ]
    out: list[minify.Tok] = []
    curly = 0
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t.kind == "symbol" and t.text == b"{":
            curly += 1
        elif t.kind == "symbol" and t.text == b"}":
            curly = max(0, curly - 1)

        # `object.V` / `result.n` -> `object[<random key>]`
        if (
            t.kind == "symbol"
            and t.text == b"."
            and i + 1 < len(tokens)
            and tokens[i + 1].kind == "name"
            and tokens[i + 1].text.decode("latin-1") in keys
        ):
            name = tokens[i + 1].text.decode("latin-1")
            out.extend([
                _tok("symbol", b"["),
                _tok("number", str(keys[name]).encode("ascii")),
                _tok("symbol", b"]"),
            ])
            i += 2
            continue

        # `{ V = ..., n = 0, proto = ..., up = ... }` -> `[key] = ...`
        prev = tokens[i - 1] if i else None
        nxt = tokens[i + 1] if i + 1 < len(tokens) else None
        if (
            t.kind == "name"
            and t.text.decode("latin-1") in keys
            and curly > 0
            and nxt is not None
            and nxt.text == b"="
            and prev is not None
            and prev.text in (b"{", b",", b";")
        ):
            name = t.text.decode("latin-1")
            out.extend([
                _tok("symbol", b"["),
                _tok("number", str(keys[name]).encode("ascii")),
                _tok("symbol", b"]"),
            ])
            i += 1
            continue

        out.append(t)
        i += 1
    return _source(out)
