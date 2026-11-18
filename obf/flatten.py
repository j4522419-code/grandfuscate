"""
Control-flow flattening (CFF) over statement blocks.

A block's straight-line statements become a randomised state machine in a
`while true` dispatcher.  Locals declared in the block are converted to slots
of a per-block register table, because a `local` inside an `if` branch would
otherwise go out of scope for later branches.  The AST resolves every
reference to its declaration, so this conversion is scope-correct (including
shadowing and closures that capture the block's locals).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import ast as A
from .junk import junk_stmt, opaque_false, opaque_true
from .render import Context, Renderer

LOOP_TYPES = frozenset({"AstStatWhile", "AstStatFor", "AstStatForIn", "AstStatRepeat"})


@dataclass
class FlattenInfo:
    reg: str
    state: str
    brk: str
    cont: str
    in_loop: bool
    has_break: bool
    has_continue: bool
    registered: dict[int, str] = field(default_factory=dict)


def _descendants(v):
    """Yield statement/expression nodes, but never cross a function boundary."""
    if isinstance(v, dict):
        if v.get("type") == "AstExprFunction":
            return
        if "type" in v:
            yield v
        for k, sub in v.items():
            if k.startswith("_") or k in A.IGNORED_KEYS:
                continue
            yield from _descendants(sub)
    elif isinstance(v, list):
        for x in v:
            yield from _descendants(x)


def _has_nested_break(body: list[dict]) -> bool:
    """A break/continue below the top level belongs to a different loop.

    Replacing an enclosing block with a `while true` dispatcher would make
    that break target our dispatcher instead of the original loop, so such
    blocks are left alone (their inner blocks can still be flattened).
    """
    for st in body:
        if st.get("type") in ("AstStatBreak", "AstStatContinue"):
            continue
        for d in _descendants(st):
            if d.get("type") in ("AstStatBreak", "AstStatContinue"):
                return True
    return False


def _in_loop(node: dict) -> bool:
    for ptype, _pkey in reversed(node.get("_ancestors", ())):
        if ptype == "AstExprFunction":
            return False
        if ptype in LOOP_TYPES:
            return True
    return False


def select_blocks(tree: dict, ctx: Context) -> int:
    opts = ctx.opts
    if not opts.flatten:
        return 0
    count = 0
    for node in A.iter_nodes(tree):
        if node.get("type") != "AstStatBlock":
            continue
        body = node.get("body") or []
        if len(body) < opts.min_stmts:
            continue
        # `repeat ... until cond`: cond is outside the body span and can see
        # body locals, so we must not hide them in a register table.
        if node.get("_ptype") == "AstStatRepeat" and node.get("_pkey") == "body":
            continue
        ret_positions = [i for i, s in enumerate(body) if s.get("type") == "AstStatReturn"]
        if any(i != len(body) - 1 for i in ret_positions):
            continue
        if _has_nested_break(body):
            continue
        has_break = any(s.get("type") == "AstStatBreak" for s in body)
        has_cont = any(s.get("type") == "AstStatContinue" for s in body)
        loop = _in_loop(node)
        if (has_break or has_cont) and not loop:
            continue
        # Source-mode flattening is a probability (0..1).  Values above 1 are
        # meaningful only to the VM layer as a decoy multiplier.
        if ctx.rng.random() > max(0.0, min(opts.flatten_ratio, 1.0)):
            continue

        ns = ctx.names
        info = FlattenInfo(
            reg=ns.register_table(),
            state=ns.fresh_runtime("s"),
            brk=ns.fresh_runtime("b"),
            cont=ns.fresh_runtime("c"),
            in_loop=loop,
            has_break=has_break,
            has_continue=has_cont,
        )
        slot = 1
        for st in body:
            t = st.get("type")
            decls: list[dict] = []
            if t == "AstStatLocal":
                decls = list(st.get("vars") or [])
            elif t == "AstStatLocalFunction":
                decls = [st["name"]]
            if not decls:
                continue
            targets = []
            for d in decls:
                loc = d.get("location")
                target = f"{info.reg}[{slot}]"
                slot += 1
                if loc:
                    ctx.decl_map[loc] = target
                targets.append(target)
            info.registered[id(st)] = ", ".join(targets) if t == "AstStatLocal" else targets[0]
        ctx.flatten_info[id(node)] = info
        count += 1
    return count


def render_block(node: dict, ctx: Context, span: tuple[int, int]) -> bytes:
    info = ctx.flatten_info.get(id(node))
    if info is None:
        return ctx.renderer._generic(node, ctx, span)

    r = ctx.rng
    state = info.state.encode()
    brk = info.brk.encode()
    cont = info.cont.encode()
    reg = info.reg.encode()
    body = node["body"]
    n = len(body)

    def fresh(exclude: set[int]) -> int:
        while True:
            v = r.randrange(1, 2 ** 48)
            if v not in exclude:
                exclude.add(v)
                return v

    used: set[int] = set()
    ids = [fresh(used) for _ in range(n)]
    exit_id = fresh(used)
    decoy_ids = [fresh(used) for _ in range(max(1, ctx.opts.junk * 2 + r.randrange(0, 3)))]

    old = ctx.flat
    ctx.flat = info
    try:
        branches: list[tuple[bytes, bytes]] = []
        for k, st in enumerate(body):
            rendered = ctx.r(st)
            typ = st.get("type")
            suffix = b""
            if typ not in ("AstStatReturn", "AstStatBreak", "AstStatContinue"):
                nxt = ids[k + 1] if k + 1 < n else exit_id
                suffix = b"; " + state + b" = " + str(nxt).encode()
            if ctx.opts.junk and r.random() < 0.35:
                dead = b"if " + opaque_false(ctx) + b" then " + junk_stmt(ctx, state, reg) + b" end; "
                rendered = dead + rendered
            cond = state + b" == " + str(ids[k]).encode() + b" and " + opaque_true(ctx)
            branches.append((cond, rendered + suffix))

        for d in decoy_ids:
            cond = state + b" == " + str(d).encode() + b" and " + opaque_false(ctx)
            code = junk_stmt(ctx, state, reg) + b"; " + state + b" = " + str(exit_id).encode()
            branches.append((cond, code))

        r.shuffle(branches)

        lines: list[bytes] = [
            b"local " + state + b" = " + str(ids[0]).encode()
            + b"; local " + brk + b" = false; local " + cont + b" = false; local " + reg + b" = {}",
            b"while true do",
        ]
        for i, (cond, code) in enumerate(branches):
            kw = b"if" if i == 0 else b"elseif"
            lines.append(kw + b" " + cond + b" then " + code)
        lines.append(b"else break end")
        lines.append(b"end")
        if info.in_loop:
            if info.has_break:
                lines.append(b"if " + brk + b" then break end")
            if info.has_continue:
                lines.append(b"if " + cont + b" then continue end")
        # A block span usually starts at the whitespace AFTER `do` / `then` and
        # ends at the whitespace BEFORE `end`.  Add explicit separation so the
        # minifier can never glue `do` to `local` (or `end` to `end`).
        return b" " + b" ".join(lines) + b" "
    finally:
        ctx.flat = old


def hook_break(node: dict, ctx: Context, span: tuple[int, int]) -> bytes:
    if ctx.flat is None:
        return ctx.source.slice(span)
    return ctx.flat.brk.encode() + b" = true; break"


def hook_continue(node: dict, ctx: Context, span: tuple[int, int]) -> bytes:
    if ctx.flat is None:
        return ctx.source.slice(span)
    return ctx.flat.cont.encode() + b" = true; break"


def install(r: Renderer) -> None:
    r.register("AstStatBlock", render_block)
    r.register("AstStatBreak", hook_break)
    r.register("AstStatContinue", hook_continue)
