"""Independent per-build structural layout decisions.

This generator is deliberately separate from the compiler/pool RNG: it selects
emitted control/data shapes without perturbing the deterministic byte stream.
Production builds differ in dispatch profiles, bank/group coefficients, opcode
maps, operand permutations, node layouts, chunk plans and payload placement.
"""
from __future__ import annotations

import random
import re
from dataclasses import dataclass, field


NODE_STYLES = ("sparse", "nested", "cursor")
DISPATCH_STYLES = ("direct", "split", "bucket")
ROUTER_STYLES = ("direct", "split", "chain")
CHUNK_ASSEMBLIES = ("concat", "sbyte")
CHUNK_STRATEGIES = ("balanced", "jitter")
VM_PROFILES = ("inline", "relay", "mirror")
FIELD_NAMES = ("V", "UP", "VA", "n", "v", "proto", "up", "NODE_N")
_GROUP_ALIAS = {
    "pool_byte": "byte",
    "vm_byte": "byte",
    "eval": "node",
    "exec": "node",
}

PRESET_CHUNKS = {
    "light": dict(max_chunk_bytes=1500, min_chunks=2, max_extra=2, hard_cap=512),
    "medium": dict(max_chunk_bytes=2200, min_chunks=3, max_extra=3, hard_cap=1024),
    "heavy": dict(max_chunk_bytes=4200, min_chunks=4, max_extra=4, hard_cap=1536),
}


@dataclass(frozen=True)
class Layout:
    seed: int
    preset: str
    node_style: str
    dispatch_style: str
    router_style: str
    chunk_assembly: str
    chunk_strategy: str
    dispatch_n: int
    dispatch_b: int
    slot_base: int
    const_span: int
    const_bias: int
    vm_profile: str
    bank_count: int
    bank_a: int
    bank_b: int
    handler_groups: int
    handler_a: int
    handler_b: int
    word_groups: int
    word_a: int
    word_b: int
    constant_groups: int
    constant_a: int
    constant_b: int
    node_groups: int
    node_a: int
    node_b: int
    byte_groups: int
    byte_a: int
    byte_b: int
    per_node_operand_c: int
    per_node_operand_d: int
    slice_stride: int = 1
    slice_shift: int = 0
    source_spread: dict = field(default_factory=dict)
    field_keys: dict[str, int] = field(default_factory=dict)
    chunk_settings: dict[str, int] = field(default_factory=dict)

    # -- classic dispatcher helpers ---------------------------------------
    def field(self, name: str) -> int:
        return self.field_keys[name]

    def slot_index(self, code: int) -> int:
        if self.dispatch_style == "direct":
            return self.slot_base + code
        if self.dispatch_style == "split":
            return self.slot_base + code % 2
        return self.slot_base + (code + self.dispatch_b) % self.dispatch_n

    def assign_slot(self, table: str, code: int) -> str:
        """Full left-hand side for installing the handler keyed by `code`."""
        if self.dispatch_style == "direct":
            return f"{table}[{self.slot_index(code)}]"
        return f"{table}[{self.slot_index(code)}][{code}]"

    def handler_key(self, key_expr: str) -> str:
        if self.dispatch_style == "direct":
            return f"{self.slot_base} + ({key_expr})"
        return key_expr

    def runtime_handler(self, table: str, key_expr: str) -> str:
        return (
            f"{self.runtime_slot(table, key_expr)}"
            f"[{self.handler_key(key_expr)}]"
        )

    def runtime_slot(self, table: str, key_expr: str) -> str:
        if self.dispatch_style == "direct":
            return table
        if self.dispatch_style == "split":
            return f"{table}[{self.slot_base} + (({key_expr} % 2))]"
        return (
            f"{table}[{self.slot_base} + "
            f"((({key_expr} + {self.dispatch_b}) % {self.dispatch_n}))]"
        )

    def init_dispatch_lines(self, table: str, loop: str) -> list[str]:
        n = self.table_count()
        lines = [f"local {table} = {{}}"]
        if n > 1:
            lines.append(
                f"for {loop} = 0, {n - 1} do "
                f"{table}[{self.slot_base} + {loop}] = {{}} end"
            )
        return lines

    def table_count(self) -> int:
        if self.dispatch_style == "direct":
            return 1
        if self.dispatch_style == "split":
            return 2
        return self.dispatch_n

    # -- third-pass grouped VM helpers -------------------------------------
    def _effective(self, domain: str) -> str:
        return _GROUP_ALIAS.get(domain, domain)

    def group_count(self, domain: str) -> int:
        eff = self._effective(domain)
        return getattr(self, f"{eff}_groups")

    def bank_index(self, i: int) -> int:
        return (i * self.bank_a + self.bank_b) % self.bank_count

    def bank_expr(self, key_expr: str) -> str:
        return (
            f"((({key_expr}) * {self.bank_a} + {self.bank_b}) "
            f"% {self.bank_count})"
        )

    def group_index(self, domain: str, i: int) -> int:
        eff = self._effective(domain)
        a = getattr(self, f"{eff}_a")
        b = getattr(self, f"{eff}_b")
        return ((i * a + b) % self.group_count(domain)) + 1

    def group_expr(self, domain: str, key_expr: str) -> str:
        eff = self._effective(domain)
        a = getattr(self, f"{eff}_a")
        b = getattr(self, f"{eff}_b")
        return (
            f"(((({key_expr}) * {a} + {b}) % {self.group_count(domain)}) + 1)"
        )

    def chain_ticket_expr(self, domain: str, key_expr: str) -> str:
        """A per-domain capability value for chained decoder selectors."""
        eff = {"slice": "constant", "fragment": "byte"}.get(
            domain, self._effective(domain)
        )
        a = getattr(self, f"{eff}_a")
        b = getattr(self, f"{eff}_b")
        c = self.per_node_operand_c
        d = self.per_node_operand_d
        return (
            f"(((({key_expr}) * {a} + {b} + "
            f"(({key_expr}) % 97) * {c} + {d}) % 1000000007))"
        )

    def guard_line(
        self,
        domain: str,
        key_expr: str,
        bank: int,
        group: int,
        default: str,
        *,
        ticket_var: str = "t",
    ) -> str:
        """Reject indices/tickets that do not belong to this decoder group."""
        checks = [
            f"{ticket_var} ~= {self.chain_ticket_expr(domain, key_expr)}",
            f"{self.bank_expr(key_expr)} ~= {bank}",
            f"{self.group_expr(domain, key_expr)} ~= {group}",
        ]
        return f"if {' or '.join(checks)} then return {default} end"

    def function_selector(
        self,
        domain: str,
        key_expr: str,
        extra_args: list[str] | tuple[str, ...],
        ns,
        *,
        matrix: list[list[str]] | None = None,
    ) -> str:
        """Return a call expression selecting one guarded group function.

        Group functions live in per-domain tables but require a capability
        ticket computed by this fresh closure. Enumerating one table does not
        provide the tickets needed to dump the whole payload.
        """
        matrix = matrix if matrix is not None else ns.group_matrix(domain)
        groups = self.group_count(domain)
        x = ns.fresh_runtime()
        b = ns.fresh_runtime()
        g = ns.fresh_runtime()
        t = ns.fresh_runtime()
        extra_sig = ", ..." if extra_args else ""
        call_args = f"{x}, {t}, ..." if extra_args else f"{x}, {t}"
        call_expr = f"{key_expr}" + "".join(f", {a}" for a in extra_args)
        head = (
            f"(function({x}{extra_sig}) "
            f"local {b} = {self.bank_expr(x)} "
            f"local {g} = {self.group_expr(domain, x)} "
            f"local {t} = {self.chain_ticket_expr(domain, x)} "
        )
        pairs = [
            (bank, group)
            for bank in range(self.bank_count)
            for group in range(groups)
        ]
        if self.vm_profile == "relay":
            pairs = [
                (bank, group)
                for group in range(groups)
                for bank in range(self.bank_count)
            ]
        elif self.vm_profile == "mirror":
            pairs = list(reversed(pairs))
        parts = [
            f"({b} == {bank} and {g} == {group + 1} "
            f"and {matrix[bank][group]})"
            for bank, group in pairs
        ]
        fallback = matrix[0][0]
        chain = parts[0]
        for part in parts[1:]:
            chain = f"({chain} or {part})"
        chain = f"({chain} or {fallback})"
        return head + f"return ({chain})({call_args}) end)({call_expr})"

    def init_group_table_lines(
        self,
        table: str,
        domain: str,
        ns,
        *,
        slice_count: int | None = None,
    ) -> list[str]:
        s = ns.fresh_runtime()
        b = ns.fresh_runtime()
        g = ns.fresh_runtime()
        groups = self.group_count(domain)
        lines = [f"local {table} = {{}}"]
        if slice_count is None:
            lines.append(f"for {b} = 1, {self.bank_count} do {table}[{b}] = {{}}")
            lines.append(
                f"  for {g} = 1, {groups} do {table}[{b}][{g}] = nil end end"
            )
            return lines
        lines.append(f"for {s} = 1, {slice_count} do {table}[{s}] = {{}}")
        lines.append(
            f"  for {b} = 1, {self.bank_count} do {table}[{s}][{b}] = {{}}"
        )
        lines.append(
            f"    for {g} = 1, {groups} do "
            f"{table}[{s}][{b}][{g}] = nil end end end"
        )
        return lines

    def group_table_matrix(
        self,
        table: str,
        domain: str,
        *,
        slice_index: int | None = None,
    ) -> list[list[str]]:
        if domain in ("pool_byte", "vm_byte"):
            if slice_index is None:
                raise ValueError(f"{domain} requires a slice/fragment index")
            prefix = f"{table}[{slice_index}]"
        else:
            prefix = table
        return [
            [
                f"{prefix}[{bank + 1}][{group + 1}]"
                for group in range(self.group_count(domain))
            ]
            for bank in range(self.bank_count)
        ]

    def handler_group(self, code: int) -> int:
        return ((code * self.handler_a + self.handler_b) % self.handler_groups) + 1

    def vm_handler_group_expr(self, key_expr: str) -> str:
        return (
            f"((({key_expr}) * {self.handler_a} + {self.handler_b}) "
            f"% {self.handler_groups}) + 1"
        )

    def vm_group_table(self, table: str, key_expr: str) -> str:
        return f"{table}[{self.vm_handler_group_expr(key_expr)}]"

    def vm_assign(self, table: str, code: int) -> str:
        group = self.handler_group(code)
        if self.dispatch_style == "direct":
            return f"{table}[{group}][{self.slot_base + code}]"
        return f"{table}[{group}][{self.slot_index(code)}][{code}]"

    def vm_handler(self, table: str, key_expr: str) -> str:
        group = self.vm_group_table(table, key_expr)
        if self.dispatch_style == "direct":
            return f"{group}[{self.slot_base} + ({key_expr})]"
        if self.dispatch_style == "split":
            return (
                f"{group}[{self.slot_base} + (({key_expr} % 2))]"
                f"[{key_expr}]"
            )
        return (
            f"{group}[{self.slot_base} + "
            f"((({key_expr} + {self.dispatch_b}) % {self.dispatch_n}))]"
            f"[{key_expr}]"
        )

    def init_vm_handler_lines(self, table: str, outer: str, inner: str) -> list[str]:
        lines = [f"local {table} = {{}}"]
        lines.append(f"for {outer} = 1, {self.handler_groups} do")
        lines.append(f"  {table}[{outer}] = {{}}")
        if self.dispatch_style != "direct":
            lines.append(
                f"  for {inner} = 0, {self.table_count() - 1} do "
                f"{table}[{outer}][{self.slot_base} + {inner}] = {{}} end"
            )
        lines.append("end")
        return lines

    # -- deterministic source-constant spread ------------------------------
    def tune_source_spread(self, entries, source: bytes, slice_count: int) -> None:
        """Choose coefficients that split source literals across slices/groups.

        The coefficients remain private source-map metadata. They make a single
        guarded decoder group or one pool slice an incomplete view of the
        protected program's strings. This is obfuscation, not encryption.
        """
        text = source.decode("utf-8", "replace")
        candidates: list[int] = []
        for i, e in enumerate(entries, 1):
            raw = getattr(e, "text", None)
            if not isinstance(raw, str) or len(raw) < 2:
                continue
            numeric = re.fullmatch(r"-?\d+\.0", raw)
            if raw in text or (numeric and raw[:-2] in text):
                candidates.append(i)
        if not candidates:
            candidates = [1]
        r = random.Random(self.seed ^ 0x7C0FFEE5)

        def choose(modulus: int, key=lambda i: i) -> tuple[int, int, int]:
            best: tuple[int, int, int] = (-1, -1, 0)
            for _ in range(3000):
                a = r.randrange(1, 1 << 20)
                b = r.randrange(0, 1 << 20)
                cover = len({((key(i) * a + b) % modulus) for i in candidates})
                if cover > best[0]:
                    best = (cover, a, b)
                if cover >= min(modulus, len(candidates)):
                    break
            return best

        bcover, ba, bb = choose(self.bank_count)
        ccover, ca, cb = choose(self.constant_groups)
        ycover, ya, yb = choose(self.byte_groups)
        wcover, wa, wb = choose(self.word_groups)
        ncover, na, nb = choose(self.node_groups)
        hcover, ha, hb = choose(self.handler_groups)

        scover, sa, sb = -1, 1, 0
        if slice_count > 1:
            for _ in range(3000):
                a = r.randrange(1, slice_count)
                b = r.randrange(0, slice_count)
                cover = len({(((i - 1) * a + b) % slice_count) for i in candidates})
                if cover > scover:
                    scover, sa, sb = cover, a, b
                if cover >= min(slice_count, len(candidates)):
                    break
        object.__setattr__(self, "bank_a", ba)
        object.__setattr__(self, "bank_b", bb)
        object.__setattr__(self, "constant_a", ca)
        object.__setattr__(self, "constant_b", cb)
        object.__setattr__(self, "byte_a", ya)
        object.__setattr__(self, "byte_b", yb)
        object.__setattr__(self, "word_a", wa)
        object.__setattr__(self, "word_b", wb)
        object.__setattr__(self, "node_a", na)
        object.__setattr__(self, "node_b", nb)
        object.__setattr__(self, "handler_a", ha)
        object.__setattr__(self, "handler_b", hb)
        object.__setattr__(self, "slice_stride", sa)
        object.__setattr__(self, "slice_shift", sb)
        object.__setattr__(self, "source_spread", {
            "source_constant_indices": candidates,
            "bank_coverage": bcover,
            "constant_group_coverage": ccover,
            "byte_group_coverage": ycover,
            "word_group_coverage": wcover,
            "node_group_coverage": ncover,
            "handler_group_coverage": hcover,
            "pool_slice_coverage": scover,
        })

    def summary(self) -> dict:
        return {
            "node_style": self.node_style,
            "dispatch_style": self.dispatch_style,
            "router_style": self.router_style,
            "chunk_assembly": self.chunk_assembly,
            "chunk_strategy": self.chunk_strategy,
            "dispatch_n": self.dispatch_n,
            "dispatch_b": self.dispatch_b,
            "slot_base": self.slot_base,
            "const_span": self.const_span,
            "const_bias": self.const_bias,
            "vm_profile": self.vm_profile,
            "bank_count": self.bank_count,
            "bank_a": self.bank_a,
            "bank_b": self.bank_b,
            "handler_groups": self.handler_groups,
            "handler_a": self.handler_a,
            "handler_b": self.handler_b,
            "word_groups": self.word_groups,
            "word_a": self.word_a,
            "word_b": self.word_b,
            "constant_groups": self.constant_groups,
            "constant_a": self.constant_a,
            "constant_b": self.constant_b,
            "node_groups": self.node_groups,
            "node_a": self.node_a,
            "node_b": self.node_b,
            "byte_groups": self.byte_groups,
            "byte_a": self.byte_a,
            "byte_b": self.byte_b,
            "per_node_operand_c": self.per_node_operand_c,
            "per_node_operand_d": self.per_node_operand_d,
            "slice_stride": self.slice_stride,
            "slice_shift": self.slice_shift,
            "source_spread": dict(self.source_spread),
            "field_keys": dict(self.field_keys),
            "chunk_settings": dict(self.chunk_settings),
        }


def make_layout(seed: int, preset: str) -> Layout:
    r = random.Random(seed ^ 0xA57C0DE5)
    used: set[int] = set()
    keys = {}
    for name in FIELD_NAMES:
        while True:
            v = r.randrange(1, 1 << 30)
            if v not in used:
                used.add(v)
                keys[name] = v
                break
    n = r.randrange(3, 7)
    b = r.randrange(0, n)
    slot_base = r.randrange(10000, 99000)
    const_span = r.choice((2, 3))
    const_bias = r.randrange(0, 5)
    vm_profile = r.choice(VM_PROFILES)
    bank_count = {"inline": 2, "relay": 3, "mirror": 4}[vm_profile]
    handler_groups = r.randrange(3, 7)
    word_groups = r.randrange(3, 6)
    constant_groups = r.randrange(3, 6)
    node_groups = r.randrange(3, 6)
    byte_groups = r.randrange(3, 6)
    return Layout(
        seed=seed,
        preset=preset,
        node_style=r.choice(NODE_STYLES),
        dispatch_style=r.choice(DISPATCH_STYLES),
        router_style=r.choice(ROUTER_STYLES),
        chunk_assembly=r.choice(CHUNK_ASSEMBLIES),
        chunk_strategy=r.choice(CHUNK_STRATEGIES),
        dispatch_n=n,
        dispatch_b=b,
        slot_base=slot_base,
        const_span=const_span,
        const_bias=const_bias,
        vm_profile=vm_profile,
        bank_count=bank_count,
        bank_a=r.randrange(1, 1 << 20),
        bank_b=r.randrange(0, 1 << 20),
        handler_groups=handler_groups,
        handler_a=r.randrange(1, 1 << 20),
        handler_b=r.randrange(0, 1 << 20),
        word_groups=word_groups,
        word_a=r.randrange(1, 1 << 20),
        word_b=r.randrange(0, 1 << 20),
        constant_groups=constant_groups,
        constant_a=r.randrange(1, 1 << 20),
        constant_b=r.randrange(0, 1 << 20),
        node_groups=node_groups,
        node_a=r.randrange(1, 1 << 20),
        node_b=r.randrange(0, 1 << 20),
        byte_groups=byte_groups,
        byte_a=r.randrange(1, 1 << 20),
        byte_b=r.randrange(0, 1 << 20),
        per_node_operand_c=r.randrange(1, 1 << 20),
        per_node_operand_d=r.randrange(0, 1 << 20),
        field_keys=keys,
        chunk_settings=dict(PRESET_CHUNKS.get(preset, PRESET_CHUNKS["medium"])),
    )
