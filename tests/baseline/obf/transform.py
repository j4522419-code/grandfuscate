"""AST hooks: constant encryption, name mangling, global/property virtualisation."""
from __future__ import annotations

import math

from .names import IDENT_RE
from .render import Context, Renderer


def _generic(node: dict, ctx: Context, span: tuple[int, int]) -> bytes:
    return ctx.renderer._generic(node, ctx, span)


def render_function(node: dict, ctx: Context, extra: list[bytes] | None = None) -> bytes:
    """Emit `function(params) body end` from the AST, dropping type syntax."""
    params: list[bytes] = list(extra or [])
    for a in node.get("args") or []:
        loc = a.get("location")
        mapped = ctx.decl_map.get(loc, a.get("name", "_"))
        params.append(mapped.encode("ascii"))
    if node.get("vararg"):
        params.append(b"...")
    body = ctx.r(node["body"])
    return b"function(" + b", ".join(params) + b") " + body + b" end"


# --------------------------------------------------------------------------
# constants
# --------------------------------------------------------------------------
def h_string(node: dict, ctx: Context, span: tuple[int, int]) -> bytes:
    if not ctx.opts.encrypt_constants:
        return ctx.source.slice(span)
    idx = ctx.pool.add_string(node.get("value", ""))
    if node.get("_record_key"):
        return b"[" + ctx.D(idx) + b"]"
    return ctx.D(idx)


def h_number(node: dict, ctx: Context, span: tuple[int, int]) -> bytes:
    if not ctx.opts.encrypt_constants:
        return ctx.source.slice(span)
    v = node.get("value", 0)
    if isinstance(v, str):  # defensive: JSON should give a number
        return ctx.source.slice(span)
    if math.isnan(v):
        return b"(0/0)"
    if math.isinf(v):
        return b"math.huge" if v > 0 else b"-math.huge"
    return ctx.D(ctx.pool.add_number(v))


def h_bool(node: dict, ctx: Context, span: tuple[int, int]) -> bytes:
    if not ctx.opts.encrypt_constants:
        return ctx.source.slice(span)
    return ctx.D(ctx.pool.add_bool(bool(node.get("value"))))


def h_nil(node: dict, ctx: Context, span: tuple[int, int]) -> bytes:
    if not ctx.opts.encrypt_constants:
        return ctx.source.slice(span)
    return ctx.D(ctx.pool.add_nil())


# --------------------------------------------------------------------------
# identifiers
# --------------------------------------------------------------------------
def h_local_decl(node: dict, ctx: Context, span: tuple[int, int]) -> bytes:
    loc = node.get("location")
    mapped = ctx.decl_map.get(loc)
    original = ctx.source.slice(span)
    if mapped is None or not IDENT_RE.match(original):
        return original
    return mapped.encode("ascii")


def h_local_ref(node: dict, ctx: Context, span: tuple[int, int]) -> bytes:
    ref = node.get("local") or {}
    loc = ref.get("location")
    mapped = ctx.decl_map.get(loc)
    if mapped is None:
        return ctx.source.slice(span)
    return mapped.encode("ascii")


def h_global(node: dict, ctx: Context, span: tuple[int, int]) -> bytes:
    if node.get("_decl_name") or not ctx.opts.virtualize_globals:
        return ctx.source.slice(span)
    idx = ctx.pool.add_string(node.get("global", ""))
    return ctx.E(idx)


def h_index_name(node: dict, ctx: Context, span: tuple[int, int]) -> bytes:
    expr = node.get("expr")
    keep = node.get("_skip_index") or node.get("_decl_name") or node.get("_self_call") or node.get("op") == ":"
    if keep or not ctx.opts.virtualize_properties or not isinstance(expr, dict):
        base = ctx.r(expr) if isinstance(expr, dict) else b""
        isp = ctx.source.span(node.get("indexLocation"))
        tail = ctx.source.slice(isp) if isp else node.get("index", "").encode()
        sep = b":" if node.get("op") == ":" else b"."
        return base + sep + tail
    idx = ctx.pool.add_string(node.get("index", ""))
    return ctx.r(expr) + b"[" + ctx.D(idx) + b"]"


def h_call(node: dict, ctx: Context, span: tuple[int, int]) -> bytes:
    if not node.get("self"):
        return _generic(node, ctx, span)
    func = node.get("func") or {}
    if func.get("type") != "AstExprIndexName" or func.get("op") != ":":
        return _generic(node, ctx, span)
    expr = func.get("expr") or {}
    if expr.get("type") not in ("AstExprLocal", "AstExprGlobal"):
        # Method call on a complex expression: keep `:name` syntax so we never
        # evaluate the receiver twice (metamethods / side effects).
        func["_skip_index"] = True
        return _generic(node, ctx, span)
    idx = ctx.pool.add_string(func.get("index", ""))
    e = ctx.r(expr)
    args = [ctx.r(a) for a in (node.get("args") or [])]
    inner = e + (b", " + b", ".join(args) if args else b"")
    return e + b"[" + ctx.D(idx) + b"](" + inner + b")"


# --------------------------------------------------------------------------
# statements whose shape must change
# --------------------------------------------------------------------------
def h_stat_local(node: dict, ctx: Context, span: tuple[int, int]) -> bytes:
    flat = ctx.flat
    target = flat.registered.get(id(node)) if flat is not None else None
    if target is None:
        return _generic(node, ctx, span)
    values = [ctx.r(v) for v in (node.get("values") or [])]
    lhs = target.encode("ascii")
    if not values:
        return lhs + b" = nil"
    return lhs + b" = " + b", ".join(values)


def h_stat_local_function(node: dict, ctx: Context, span: tuple[int, int]) -> bytes:
    flat = ctx.flat
    target = flat.registered.get(id(node)) if flat is not None else None
    func = node["func"]
    if target is None:
        # `local function f` puts f in scope inside its own body; the plain
        # `local f = function ...` form does NOT.  Emit the two-step form so
        # recursive and mutually-referencing locals keep working.
        name = ctx.decl_map.get(node["name"]["location"], node["name"]["name"]).encode("ascii")
        return b"local " + name + b"; " + name + b" = " + render_function(func, ctx)
    return target.encode("ascii") + b" = " + render_function(func, ctx)


def h_stat_function(node: dict, ctx: Context, span: tuple[int, int]) -> bytes:
    name = node.get("name") or {}
    func = node["func"]
    ntype = name.get("type")
    if ntype == "AstExprGlobal":
        idx = ctx.pool.add_string(name.get("global", ""))
        return ctx.E(idx) + b" = " + render_function(func, ctx)
    if ntype == "AstExprIndexName" and isinstance(name.get("expr"), dict):
        idx = ctx.pool.add_string(name.get("index", ""))
        base = ctx.r(name["expr"])
        if name.get("op") == ":":
            self_node = func.get("self") or {}
            self_name = ctx.decl_map.get(self_node.get("location"), self_node.get("name", "self"))
            return base + b"[" + ctx.D(idx) + b"] = " + render_function(func, ctx, [self_name.encode("ascii")])
        return base + b"[" + ctx.D(idx) + b"] = " + render_function(func, ctx)
    return _generic(node, ctx, span)


def h_expr_function(node: dict, ctx: Context, span: tuple[int, int]) -> bytes:
    return render_function(node, ctx)


def install(r: Renderer) -> None:
    for typ, fn in (
        ("AstExprConstantString", h_string),
        ("AstExprConstantNumber", h_number),
        ("AstExprConstantBool", h_bool),
        ("AstExprConstantNil", h_nil),
        ("AstLocal", h_local_decl),
        ("AstExprLocal", h_local_ref),
        ("AstExprGlobal", h_global),
        ("AstExprIndexName", h_index_name),
        ("AstExprCall", h_call),
        ("AstStatLocal", h_stat_local),
        ("AstStatLocalFunction", h_stat_local_function),
        ("AstStatFunction", h_stat_function),
        ("AstExprFunction", h_expr_function),
    ):
        r.register(typ, fn)
