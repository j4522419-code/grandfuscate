"""
Token-preserving Luau minifier.

It never reserialises a string or number, it only removes comments/whitespace
and inserts the minimum separator needed between adjacent tokens.  That keeps
every Luau string escape (including `\\z`, `\\ddd`, `\\u{...}`, long brackets
and interpolated backticks) byte-exact.
"""
from __future__ import annotations

from dataclasses import dataclass

MULTI = [
    "...", "..=", "::", "->", "//", "<<", ">>", "==", "~=", "<=", ">=",
    "+=", "-=", "*=", "/=", "%=", "^=", "&=", "|=", "..",
]
SINGLE = set(".,;()[]{}+-*/%^#&|~<>=?:@")


@dataclass
class Tok:
    kind: str
    text: bytes
    start: int
    end: int


def _long_bracket(d: bytes, i: int) -> int | None:
    """Match [=*[ at i; return the equals count, or None."""
    if i >= len(d) or d[i] != 0x5B:  # [
        return None
    j = i + 1
    while j < len(d) and d[j] == 0x3D:  # =
        j += 1
    if j < len(d) and d[j] == 0x5B:
        return j - i - 1
    return None


def tokenize(d: bytes) -> list[Tok]:
    out: list[Tok] = []
    i, n = 0, len(d)

    # shebang
    if d.startswith(b"#!"):
        j = d.find(b"\n")
        j = n if j < 0 else j + 1
        out.append(Tok("comment", d[:j], 0, j))
        i = j

    while i < n:
        c = d[i]
        if c in b" \t\r\n\f\v":
            j = i + 1
            while j < n and d[j] in b" \t\r\n\f\v":
                j += 1
            out.append(Tok("ws", d[i:j], i, j))
            i = j
            continue

        # -- comments (line or long)
        if d.startswith(b"--", i):
            eq = _long_bracket(d, i + 2)
            if eq is not None:
                close = b"]" + b"=" * eq + b"]"
                k = d.find(close, i + 3 + eq)
                j = n if k < 0 else k + len(close)
            else:
                j = i + 2
                while j < n and d[j] not in b"\r\n":
                    j += 1
            out.append(Tok("comment", d[i:j], i, j))
            i = j
            continue

        # long string [=*[ ... ]=*]
        eq = _long_bracket(d, i)
        if eq is not None:
            close = b"]" + b"=" * eq + b"]"
            k = d.find(close, i + eq + 2)
            j = n if k < 0 else k + len(close)
            out.append(Tok("string", d[i:j], i, j))
            i = j
            continue

        # quoted string
        if c in (0x22, 0x27):  # " '
            q = c
            j = i + 1
            while j < n:
                if d[j] == 0x5C:  # backslash
                    j += 2
                    continue
                if d[j] == q:
                    j += 1
                    break
                if d[j] in b"\r\n":
                    break
                j += 1
            out.append(Tok("string", d[i:j], i, j))
            i = j
            continue

        # interpolated backtick string (Luau).  Preserve it verbatim, but
        # track braces so nested expressions and nested backticks do not end it.
        if c == 0x60:  # `
            j = i + 1
            depth = 0
            while j < n:
                x = d[j]
                if x == 0x5C:
                    j += 2
                    continue
                if x == 0x60 and depth == 0:
                    j += 1
                    break
                if x in (0x22, 0x27):
                    q = x
                    j += 1
                    while j < n:
                        if d[j] == 0x5C:
                            j += 2
                            continue
                        if d[j] == q:
                            j += 1
                            break
                        j += 1
                    continue
                if x == 0x7B:  # {
                    depth += 1
                elif x == 0x7D:  # }
                    depth = max(0, depth - 1)
                elif x == 0x60:
                    depth += 1  # nested backtick, treat as brace-like
                j += 1
            out.append(Tok("string", d[i:j], i, j))
            i = j
            continue

        # number
        if 0x30 <= c <= 0x39 or (c == 0x2E and i + 1 < n and 0x30 <= d[i + 1] <= 0x39):
            j = i
            if d.startswith(b"0x", i) or d.startswith(b"0X", i) or d.startswith(b"0b", i) or d.startswith(b"0B", i):
                j += 2
                while j < n and (chr(d[j]).isalnum() or d[j] in b"._"):
                    j += 1
                # hex exponent
                if j < n and d[j] in b"pP":
                    j += 1
                    if j < n and d[j] in b"+-":
                        j += 1
                    while j < n and (chr(d[j]).isalnum() or d[j] == 0x5F):
                        j += 1
            else:
                while j < n and (0x30 <= d[j] <= 0x39 or d[j] in b"._"):
                    j += 1
                if j < n and d[j] in b"eE":
                    j += 1
                    if j < n and d[j] in b"+-":
                        j += 1
                    while j < n and (0x30 <= d[j] <= 0x39 or d[j] == 0x5F):
                        j += 1
            out.append(Tok("number", d[i:j], i, j))
            i = j
            continue

        # identifier
        if 0x41 <= c <= 0x5A or 0x61 <= c <= 0x7A or c == 0x5F:
            j = i + 1
            while j < n and (0x41 <= d[j] <= 0x5A or 0x61 <= d[j] <= 0x7A or 0x30 <= d[j] <= 0x39 or d[j] == 0x5F):
                j += 1
            out.append(Tok("name", d[i:j], i, j))
            i = j
            continue

        # symbols, longest match
        matched = None
        for s in MULTI:
            if d.startswith(s.encode(), i):
                matched = s
                break
        if matched:
            out.append(Tok("symbol", matched.encode(), i, i + len(matched)))
            i += len(matched)
            continue
        ch = chr(c)
        if ch in SINGLE:
            out.append(Tok("symbol", bytes([c]), i, i + 1))
            i += 1
            continue

        # unknown byte: keep it as opaque punctuation
        out.append(Tok("symbol", bytes([c]), i, i + 1))
        i += 1

    return out


def _need_space(a: Tok, b: Tok) -> bool:
    word = {"name", "number", "string"}
    if a.kind in word and b.kind in word:
        return True
    # `1..2` must not become `1.` followed by `.2`
    if a.kind == "number" and b.kind == "symbol" and b.text.startswith(b"."):
        return True
    if a.kind == "symbol" and b.kind == "symbol":
        merged = (a.text + b.text).decode("latin-1")
        for s in MULTI + ["--", "--[[", "//"]:
            if s.startswith(merged) or merged.startswith(s):
                return True
    # A `word` followed by a symbol is normally safe, except when the word is
    # a number and the symbol is `-` followed by another `-` (handled above by
    # the symbol/symbol rule on the next pair).
    return False


def minify(data: bytes, *, one_line: bool = True) -> bytes:
    toks = [t for t in tokenize(data) if t.kind not in ("ws", "comment")]
    parts: list[bytes] = []
    prev: Tok | None = None
    for t in toks:
        if prev is not None and _need_space(prev, t):
            parts.append(b" ")
        parts.append(t.text)
        if not one_line and t.kind == "symbol" and t.text == b";":
            parts.append(b"\n")
        prev = t
    return b"".join(parts)
