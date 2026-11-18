"""Identifier generation for the per-build runtime namespace.

Names are confusable but carry no semantic hint and no stable `__p` prefix.
Every runtime name is drawn from the same pool as renamed user locals, so a
static reader cannot isolate helper locals by prefix or by words such as
`EVAL`, `EXEC`, `NODES` or `BAD`.  `N(key)` is the private Python-side handle;
the emitted Luau identifier is random for every seed.
"""
from __future__ import annotations

import random
import re

# Luau identifiers are [A-Za-z_][A-Za-z0-9_]*.  These are maximally
# confusable in common monospace fonts, which is the point: a human reading a
# decompilation cannot tell them apart, but the compiler can.
FIRST = "lIO_oJiLSjZ"
REST = "lIO_oJiLSjZ08B52S7tTf"

KEYWORDS = frozenset(
    """and break do else elseif end false for function if in local nil not or
    repeat return then true until while continue export type typeof""".split()
)

IDENT_RE = re.compile(rb"^[A-Za-z_][A-Za-z0-9_]*$")

# Private Python keys.  Their values are replaced with random Luau names.
_RUNTIME_KEYS = (
    "E", "B", "K", "O", "C", "S", "D", "BAD", "H", "G",
    "db", "meta", "state", "brk", "cont",
    "ENV", "SBYTE", "SCHAR", "TCONCAT", "BXOR", "BAND",
    "PCALL", "TYPE", "TOSTR", "GETFENV",
)


class Names:
    def __init__(self, seed: int):
        self.rng = random.Random(seed ^ 0x5A17C0DE)
        self.used: set[str] = set()
        self.ns: dict[str, str] = {}
        for key in _RUNTIME_KEYS:
            self.ns[key] = self.new()

    def N(self, key: str) -> str:
        """Private semantic handle -> random emitted identifier."""
        if key not in self.ns:
            self.ns[key] = self.new()
        return self.ns[key]

    def fresh_runtime(self, hint: str = "r") -> str:
        """Return a fresh random identifier; `hint` is deliberately ignored."""
        return self.new()

    def new(self) -> str:
        while True:
            length = self.rng.randint(6, 14)
            s = self.rng.choice(FIRST) + "".join(
                self.rng.choice(REST) for _ in range(length - 1)
            )
            if s in KEYWORDS or s in self.used:
                continue
            self.used.add(s)
            return s

    def register_table(self) -> str:
        return self.new()
