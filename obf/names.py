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
        # Per-domain tables hold independently guarded decoder/dispatch
        # functions. Matrices contain table-slot expressions, not local names.
        self.group_tables: dict[str, str] = {}
        self.groups: dict[str, list[list[str]]] = {}
        self.slice_groups: dict[tuple[str, int], list[list[str]]] = {}

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

    def prepare_runtime_groups(
        self, layout, pool_slices: int, vm_fragments: int
    ) -> None:
        """Allocate one opaque table per decoder/dispatcher domain."""
        self.group_tables = {}
        self.groups = {}
        self.slice_groups = {}
        for domain in (
            "constant", "pool_byte", "vm_byte",
            "word", "node", "eval", "exec",
        ):
            table = self.new()
            self.group_tables[domain] = table
        for domain in ("constant", "word", "node", "eval", "exec"):
            self.groups[domain] = layout.group_table_matrix(
                self.group_tables[domain], domain
            )
        for s in range(1, pool_slices + 1):
            self.slice_groups[("pool_byte", s)] = (
                layout.group_table_matrix(
                    self.group_tables["pool_byte"],
                    "pool_byte",
                    slice_index=s,
                )
            )
        for f in range(1, max(1, vm_fragments) + 1):
            self.slice_groups[("vm_byte", f)] = (
                layout.group_table_matrix(
                    self.group_tables["vm_byte"],
                    "vm_byte",
                    slice_index=f,
                )
            )

    def group_matrix(
        self, domain: str, slice_index: int | None = None
    ) -> list[list[str]]:
        if domain in ("pool_byte", "vm_byte"):
            if slice_index is None:
                raise ValueError(f"{domain} requires a slice/fragment index")
            return self.slice_groups[(domain, slice_index)]
        return self.groups[domain]

    def group_names(
        self, domain: str, slice_index: int | None = None
    ) -> list[str]:
        return [
            expr
            for row in self.group_matrix(domain, slice_index)
            for expr in row
        ]

    def all_slice_names(self, domain: str) -> list[str]:
        keys = sorted(k for k in self.slice_groups if k[0] == domain)
        out: list[str] = []
        for key in keys:
            out.extend(self.group_names(domain, key[1]))
        return out
