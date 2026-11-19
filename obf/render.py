"""
Recursive source-surgery renderer.

Each hook returns the replacement text for exactly one AST node's byte span.
Untouched spans are copied verbatim from the original source.  Because edits
are nested (a hook renders its children itself), there are no overlapping
edits to reconcile. Source-mode rendering preserves untouched spans; the VM
compiler raises `Unsupported` instead of silently falling back.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any, Callable

from . import ast as A
from .names import Names
from .pool import ConstantPool

Hook = Callable[[dict, "Context", tuple[int, int]], bytes]


@dataclass
class Options:
    preset: str = "medium"
    seed: int = 0
    virtualize_globals: bool = True
    virtualize_properties: bool = True
    encode_constants: bool = True
    flatten: bool = True
    flatten_ratio: float = 0.75
    """0..1 probability of flattening an eligible source-mode block. Normal
    builds cap this at 1.0; values above 1 are no longer used by presets."""
    min_stmts: int = 3
    """Source-mode minimum block size; in VM mode lower values add modest chaff."""
    junk: int = 2
    """Source-mode decoy states; in VM mode also scales modest IR/meta chaff."""
    integrity: bool = True
    place_id: int | None = None
    game_id: int | None = None
    one_line: bool = True
    vm: bool = False
    """Use the single polymorphic VM runtime. `make_options()` turns this on
    for all three presets; direct `Options()` stays source-mode for library use."""
    nested_vm: bool = False
    """Deprecated. Normal builds never use the second encoded dispatch layer."""
    anti_env: bool = False
    """Deprecated. Normal builds never emit environment-hook poisoning checks."""
    anti_tamper: bool = True
    """Optional extra checksum; normal presets leave it off for compatibility."""
    blob_pad: int = 0
    """Bytes of unreferenced high-entropy constant-pool / IR padding."""
    pool_slices: int = 3
    """Number of independent, late-decoded constant-pool slices."""
    vm_fragments: int = 4
    """Number of independently encoded VM instruction-stream fragments."""
    decoy_traps: int = 24
    """Preset-scaled count of opaque decoy VM handlers."""
    entropy_budget: int = 60000
    """Maximum extra source bytes added by literal inflation/padding."""


@dataclass
class Context:
    source: A.Source
    names: Names
    pool: ConstantPool
    rng: random.Random
    opts: Options
    renderer: "Renderer" = None  # type: ignore[assignment]
    decl_map: dict[str, str] = field(default_factory=dict)
    flatten_info: dict[int, Any] = field(default_factory=dict)
    flat: Any = None
    in_type: bool = False
    hooks: dict[str, Hook] = field(default_factory=dict)
    layout: object | None = None

    def r(self, node: dict) -> bytes:
        return self.renderer.render(node, self)

    def constant(self, expr: str | int) -> bytes:
        """One guarded, distributed constant lookup for VM-mode renderers."""
        if (
            self.opts.vm
            and self.layout is not None
            and getattr(self.names, "groups", None)
            and "constant" in self.names.groups
        ):
            text = self.layout.function_selector(
                "constant", str(expr), [], self.names
            )
            return text.encode("ascii")
        return f"{self.names.N('D')}({expr})".encode("ascii")

    def D(self, idx: int) -> bytes:
        return self.constant(idx)

    def E(self, idx: int) -> bytes:
        return (
            f"{self.names.N('E')}[{self.constant(idx).decode('ascii')}]"
        ).encode("ascii")


def is_type_node(t: str) -> bool:
    return t.startswith(A.TYPE_PREFIXES) or t in (
        "AstStatTypeAlias",
        "AstStatTypeFunction",
        "AstStatDeclareFunction",
        "AstStatDeclareGlobal",
        "AstStatDeclareClass",
    )


class Renderer:
    def __init__(self):
        self.hooks: dict[str, Hook] = {}

    def register(self, typ: str, fn: Hook) -> None:
        self.hooks[typ] = fn

    def render(self, node: dict, ctx: Context) -> bytes:
        if not isinstance(node, dict) or "type" not in node:
            return b""
        t = node.get("type", "")
        span = ctx.source.span(node.get("location"))
        if span is not None and span[1] <= span[0]:
            span = None
        if span is None:
            span = self._derive(node, ctx)
        if span is None:
            return b""
        original = ctx.source.slice(span)
        if ctx.in_type or is_type_node(t):
            return original
        hook = self.hooks.get(t)
        if hook is not None:
            return hook(node, ctx, span)
        return self._generic(node, ctx, span)

    def _all_spans(self, node: Any, ctx: Context, out: list[tuple[int, int]]) -> None:
        if isinstance(node, dict):
            if node.get("_is_ref"):
                return
            if "type" in node:
                sp = ctx.source.span(node.get("location"))
                if sp and sp[1] > sp[0]:
                    out.append(sp)
            for k, v in node.items():
                if k.startswith("_") or k in A.IGNORED_KEYS:
                    continue
                self._all_spans(v, ctx, out)
        elif isinstance(node, list):
            for v in node:
                self._all_spans(v, ctx, out)

    def _derive(self, node: dict, ctx: Context) -> tuple[int, int] | None:
        spans: list[tuple[int, int]] = []
        for k, v in node.items():
            if k.startswith("_") or k in A.IGNORED_KEYS:
                continue
            self._all_spans(v, ctx, spans)
        if not spans:
            return None
        return min(s for s, _ in spans), max(e for _, e in spans)

    def _generic(self, node: dict, ctx: Context, span: tuple[int, int]) -> bytes:
        kids: list[tuple[int, int, dict]] = []

        def collect(v: Any) -> None:
            if isinstance(v, dict) and "type" in v:
                if v.get("_is_ref"):
                    return
                sp = ctx.source.span(v.get("location"))
                if sp is None or sp[1] <= sp[0]:
                    # Location-less wrappers (e.g. AstExprTableItem): descend.
                    for k2, v2 in v.items():
                        if k2.startswith("_") or k2 in A.IGNORED_KEYS:
                            continue
                        collect(v2)
                    return
                if sp[0] >= span[0] and sp[1] <= span[1]:
                    kids.append((sp[0], sp[1], v))
                    return
                # Child span outside the parent: it is a duplicate reference
                # copy (e.g. AstExprLocal.local).  Skip it entirely.
                return
            if isinstance(v, list):
                for item in v:
                    collect(item)

        for k, v in node.items():
            if k.startswith("_") or k in A.IGNORED_KEYS:
                continue
            collect(v)

        # Prefer the outermost node at a given start offset; skip overlaps.
        kids.sort(key=lambda x: (x[0], -x[1]))
        out: list[bytes] = [b""]
        pos = span[0]
        end = span[0]
        for s, e, child in kids:
            if s < end:
                continue
            out.append(ctx.source.data[pos:s])
            out.append(self.render(child, ctx))
            pos = e
            end = e
        out.append(ctx.source.data[pos:span[1]])
        return b"".join(out)
