"""High-entropy emitted-byte surface for the v4 build.

The protected chunk must stay valid Luau: raw ``!@^&#%...`` outside a string is
a parse error. All symbol soup therefore lives inside valid string literals —
long-bracket strings (``[==[...]==]``) and quoted strings with mixed escapes.
The literals are inert (never executed, never ``loadstring``-ed); a bounded
window of each is folded into the distributed integrity checksums, so editing
their bytes trips a harmless-default guard. This is obfuscation, not crypto.
"""
from __future__ import annotations

import random
from dataclasses import dataclass

from . import minify

# Byte alphabet for raw symbol soup inside long-bracket strings. It deliberately
# excludes ``]``, ``=``, ``[``, quotes, backslash and control characters, so it
# can never terminate or open a long bracket and never needs escaping. ASCII
# only, so a Latin-1 decode round-trips through the UTF-8 source byte-for-byte.
SYMBOL_ALPHABET: bytes = b"!@^&#%$*~?/;:,."


def symbol_soup(rng: random.Random, n: int, *, alphabet: bytes = SYMBOL_ALPHABET) -> bytes:
    """Return ``n`` high-entropy printable symbol bytes."""
    pick = rng.choice
    return bytes(pick(alphabet) for _ in range(n))


def lua_long_bracket(data: bytes, eq: int) -> str:
    """A valid Luau long-bracket string literal containing ``data`` verbatim.

    ``data`` must be ASCII printable and must not contain ``]`` or ``=``; the
    caller guarantees this by using :func:`symbol_soup`. ``eq`` randomises the
    equals level so builds do not share a fixed ``[==[`` marker.
    """
    opening = "[" + "=" * eq + "["
    closing = "]" + "=" * eq + "]"
    return opening + data.decode("latin-1") + closing


def lua_mixed_quoted(data: bytes, rng: random.Random) -> str:
    """A quoted Luau string mixing ``\\xNN``, ``\\ddd``, ``\\u{...}`` and raw bytes.

    Every escape decodes to exactly the original byte (``\\ddd`` is zero-padded
    to three digits so a following digit cannot be swallowed). ``\\u{...}`` is
    used only for bytes below 0x80, where it decodes to a single byte. Quotes,
    backslashes, control and high bytes always use ``\\xNN``/``\\ddd``.
    """
    out: list[str] = ['"']
    for x in data:
        raw_ok = 0x20 <= x <= 0x7E and x not in (0x22, 0x5C)
        form = rng.randrange(4)
        if raw_ok and form == 0:
            out.append(chr(x))
        elif x < 0x80 and form == 1:
            out.append("\\u{%X}" % x)
        elif form == 2:
            out.append("\\x%02X" % x)
        else:
            out.append("\\%03d" % x)
    out.append('"')
    return "".join(out)


def tokens(data: bytes):
    return [t for t in minify.tokenize(data) if t.kind not in ("ws", "comment")]


def string_literal_bytes(data: bytes) -> int:
    """Bytes inside quoted/long-bracket string tokens (canonical literal share)."""
    return sum(len(t.text) for t in tokens(data) if t.kind == "string")


def encoded_literal_bytes(data: bytes) -> int:
    """String-literal bytes plus numeric-literal bytes (broader literal share)."""
    return sum(len(t.text) for t in tokens(data) if t.kind in ("string", "number"))


def string_literals(data: bytes) -> list[bytes]:
    return [t.text for t in tokens(data) if t.kind == "string"]


def long_bracket_literals(data: bytes) -> list[bytes]:
    return [t.text for t in tokens(data)
            if t.kind == "string" and t.text.startswith(b"[")]


def measure(data: bytes) -> dict:
    """Tokenizer-aware entropy report used by both the build and the tests."""
    total = len(data)
    s = string_literal_bytes(data)
    e = encoded_literal_bytes(data)
    return {
        "total_bytes": total,
        "string_literal_bytes": s,
        "encoded_literal_bytes": e,
        "string_share": round(s / total, 4) if total else 0.0,
        "encoded_share": round(e / total, 4) if total else 0.0,
        "structural_bytes": total - e,
        "num_string_literals": len(string_literals(data)),
        "num_long_bracket": len(long_bracket_literals(data)),
    }


@dataclass
class LiteralBudget:
    """Refuse to emit padding once the ``<=15%`` output-size gate would break."""
    baseline_bytes: int          # v3 benchmark size for this preset
    base_bytes: int              # current v4 build size before entropy padding
    structural_estimate: int     # bytes added by decoys + verify lines
    max_increase: float = 0.15   # hard gate, from section 7 / lower_target
    safety: float = 0.06         # stay this fraction below the gate ceiling

    @property
    def gate_bytes(self) -> int:
        return int(self.baseline_bytes * (1.0 + self.max_increase))

    @property
    def target_bytes(self) -> int:
        return int(self.gate_bytes * (1.0 - self.safety))

    @property
    def padding_bytes(self) -> int:
        """Literal padding bytes that keep the final output under target."""
        room = self.target_bytes - self.base_bytes - self.structural_estimate
        return max(0, room)

    def within_gate(self, final_bytes: int) -> bool:
        return final_bytes <= self.gate_bytes


# Bounded integrity window: only this many bytes of each marker are hashed at
# runtime, so startup stays cheap regardless of how much symbol soup is emitted.
INTEGRITY_WINDOW = 96
