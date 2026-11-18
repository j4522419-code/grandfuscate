"""
Luau AST -> custom IR -> sharded, randomly laid-out instruction stream.

Each build gets:
  * random 32-bit opcode / operator values instead of a small 1..N range;
  * one of three operand permutations, including a bit32.bxor/mask layout;
  * randomized physical node order, word order and offset-region placement;
  * several independently encoded, lazily assembled stream fragments;
  * safe nested-block and branch-inversion control-flow transformations;
  * private source spans and compile notes for the debug/source map.

No source text, identifier, string literal or number literal survives in the
emitted program; everything lives in the encoded constant pool or stream.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from functools import wraps

from .. import ast as A
from ..checksum import ChecksumParams, make_params
from ..pool import ConstantPool, lua_bytes_literal
from ..render import Context


class Unsupported(Exception):
    """A runtime construct cannot be represented safely by this VM.

    The caller reports this explicitly.  There is no silent source-mode
    fallback that would leave unprotected syntax in a production build.
    """


STMT_OPS = [
    "BLOCK", "NOP", "LOCAL", "LOCALFUNC", "ASSIGN", "COMPOUND", "EXPR",
    "IF", "WHILE", "REPEAT", "FOR", "FORIN", "RETURN", "BREAK", "CONTINUE",
    "FUNCSTMT", "PROTO",
]
EXPR_OPS = [
    "CONST", "NIL", "VAR", "GLOBAL", "BIN", "UN", "AND", "OR", "CALL",
    "SELFCALL", "INDEX", "INDEXNAME", "TABLE", "FUNCTION", "VARARGS",
    "INTERP", "IFELSE",
]
BIN_OPS = [
    "Add", "Sub", "Mul", "Div", "FloorDiv", "Mod", "Pow", "Concat",
    "CompareEq", "CompareNe", "CompareLt", "CompareLe", "CompareGt", "CompareGe",
]
UN_OPS = ["Not", "Minus", "Len"]
ALL_OPS = STMT_OPS + EXPR_OPS

# Type declarations have no runtime statement semantics.  They are recorded in
# the private compile notes and replaced by a runtime no-op, not silently lost.
IGNORED_STATEMENTS = frozenset(
    {"AstStatTypeAlias", "AstStatTypeFunction", "AstStatDeclareGlobal",
     "AstStatDeclareFunction", "AstStatDeclareClass"}
)


def _next_prime(n: int) -> int:
    n = max(2, int(n))
    while True:
        if all(n % d for d in range(2, int(n ** 0.5) + 1)):
            return n
        n += 1


@dataclass
class StreamFragment:
    index: int
    blob: bytes
    key: bytes
    delta: int
    gamma: int
    salt: int
    expected_hash: int
    hash_params: ChecksumParams
    blob_literal: str
    key_literal: str
    word_count: int


@dataclass
class Program:
    nodes: list[tuple[str, list[int]]] = field(default_factory=list)
    entry: int = 0
    decl_ids: dict[str, int] = field(default_factory=dict)
    opcodes: dict[str, int] = field(default_factory=dict)
    decoy_opcodes: list[int] = field(default_factory=list)
    binmap: dict[str, int] = field(default_factory=dict)
    unmap: dict[str, int] = field(default_factory=dict)
    stream: bytes = b""
    stream_key: bytes = b""
    delta: int = 0
    gamma: int = 0
    salt: int = 0
    stream_literal: str = ""
    key_literal: str = ""
    pad_words: int = 0
    locations: list[str | None] = field(default_factory=list)
    source_map: list[dict] = field(default_factory=list)
    operand_stride: int = 0
    operand_shift: int = 0
    op_key: int = 0
    len_key: int = 0
    arg_key: int = 0
    operand_info: dict = field(default_factory=dict)
    fragments: list[StreamFragment] = field(default_factory=list)
    fragment_count: int = 0
    words_per_fragment: int = 0
    offset_base: int = 0
    offset_count: int = 0
    offset_stride: int = 0
    offset_shift: int = 0
    node_style: str = "sparse"
    node_outer_key: int = 0
    node_op_selector: int = 0
    node_len_selector: int = 0
    node_arg_selector: int = 0
    word_order: str = "op_len"
    stream_order: str = "offset_prefix"
    operand_mode: str = "affine"
    operand_a: int = 0
    operand_b: int = 0
    operand_expr: str = ""
    hash_params: ChecksumParams | None = None
    control_flow: dict = field(default_factory=dict)
    compile_notes: list[str] = field(default_factory=list)
    chunk_plans: list = field(default_factory=list)


def _located(fn):
    """Record the current AST location for every IR node added inside `fn`."""
    @wraps(fn)
    def wrapper(self, n: dict, *args, **kwargs):
        prev = getattr(self, "_loc", None)
        self._loc = n.get("location") if isinstance(n, dict) else None
        try:
            return fn(self, n, *args, **kwargs)
        finally:
            self._loc = prev
    return wrapper


class Compiler:
    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.layout = ctx.layout
        self.pool: ConstantPool = ctx.pool
        self.rng: random.Random = ctx.rng
        self.p = Program()
        self._next_decl = 1
        self._loc: str | None = None

        r = self.rng
        used: set[int] = set()

        def fresh32() -> int:
            while True:
                v = r.randrange(1, 1 << 32)
                if v not in used:
                    used.add(v)
                    return v

        self.p.opcodes = {op: fresh32() for op in ALL_OPS}
        self.p.decoy_opcodes = [fresh32() for _ in range(8)]
        self.p.binmap = {op: fresh32() for op in BIN_OPS}
        self.p.unmap = {op: fresh32() for op in UN_OPS}

    # -- helpers -----------------------------------------------------------
    def add(self, op: str, *args: int) -> int:
        self.p.nodes.append((op, list(args)))
        self.p.locations.append(self._loc)
        return len(self.p.nodes)

    def did(self, node: dict) -> int:
        loc = node.get("location")
        if loc not in self.p.decl_ids:
            self.p.decl_ids[loc] = self._next_decl
            self._next_decl += 1
        return self.p.decl_ids[loc]

    def kstr(self, s: str) -> int:
        return self.pool.add_string(s)

    # -- statements --------------------------------------------------------
    def block(self, body: list[dict]) -> int:
        stmts = [self.stmt(s) for s in body]
        o = self.ctx.opts
        if self.ctx.opts.vm and len(stmts) >= 2:
            # NOP statements are pure control-flow padding: they preserve
            # execution order, lexical scope and all break/return signals.
            nop_prob = min(
                0.55, 0.04 + 0.18 * max(0.0, o.flatten_ratio)
                + 0.012 * max(0, o.junk)
            )
            if self.rng.random() < nop_prob:
                spaced: list[int] = []
                injected = 0
                for st in stmts:
                    if self.rng.random() < nop_prob:
                        spaced.append(self.add("NOP"))
                        injected += 1
                    spaced.append(st)
                if injected:
                    stmts = spaced
                    self.p.control_flow["injected_nops"] = (
                        self.p.control_flow.get("injected_nops", 0) + injected
                    )
        prob = min(0.85, 0.08 + 0.30 * max(0.0, o.flatten_ratio)
                   + 0.025 * max(0, o.junk))
        if len(stmts) >= 3 and self.rng.random() < prob:
            # Nested BLOCKs preserve statement order and propagate break,
            # continue and return signals unchanged.  This changes the IR
            # shape without changing evaluation order or lexical scope.
            parts = min(len(stmts), self.rng.randint(2, 3))
            cuts = sorted(self.rng.sample(range(1, len(stmts)), parts - 1))
            groups: list[list[int]] = []
            lo = 0
            for hi in cuts + [len(stmts)]:
                groups.append(stmts[lo:hi])
                lo = hi
            nested = [self.add("BLOCK", len(g), *g) for g in groups if g]
            self.p.control_flow["nested_blocks"] = (
                self.p.control_flow.get("nested_blocks", 0) + 1
            )
            return self.add("BLOCK", len(nested), *nested)
        return self.add("BLOCK", len(stmts), *stmts)

    @_located
    def stmt(self, n: dict) -> int:
        t = n.get("type")
        if t == "AstStatBlock":
            return self.block(n.get("body") or [])
        if t in IGNORED_STATEMENTS:
            self.p.compile_notes.append(
                f"runtime no-op: {t} is a type-only declaration"
            )
            return self.add("NOP")
        if t == "AstStatLocal":
            vars_ = n.get("vars") or []
            vals = n.get("values") or []
            ds = [self.did(v) for v in vars_]
            es = [self.expr(v) for v in vals]
            return self.add("LOCAL", len(vars_), *ds, len(vals), *es)
        if t == "AstStatLocalFunction":
            d = self.did(n["name"])
            proto = self.proto(n["func"])
            return self.add("LOCALFUNC", d, proto)
        if t == "AstStatFunction":
            name = n["name"]
            if name.get("type") == "AstExprGlobal":
                lv = self.add("GLOBAL", self.kstr(name["global"]))
            elif name.get("type") == "AstExprIndexName":
                lv = self.add("INDEXNAME", self.expr(name["expr"]), self.kstr(name["index"]))
            else:
                raise Unsupported(f"function declaration name {name.get('type')}")
            extra = None
            if n["func"].get("self"):
                extra = self.did(n["func"]["self"])
            proto = self.proto(n["func"], extra)
            return self.add("FUNCSTMT", lv, proto)
        if t == "AstStatAssign":
            lv = [self.lvalue(v) for v in (n.get("vars") or [])]
            vals = [self.expr(v) for v in (n.get("values") or [])]
            return self.add("ASSIGN", len(lv), *lv, len(vals), *vals)
        if t == "AstStatCompoundAssign":
            lv = self.lvalue(n["var"])
            op = self.p.binmap.get(n.get("op"))
            if op is None:
                raise Unsupported(f"compound op {n.get('op')}")
            return self.add("COMPOUND", lv, op, self.expr(n["value"]))
        if t == "AstStatExpr":
            return self.add("EXPR", self.expr(n["expr"]))
        if t == "AstStatIf":
            cond = self.expr(n["condition"])
            o = self.ctx.opts
            prob = min(0.75, 0.06 + 0.28 * max(0.0, o.flatten_ratio)
                       + 0.02 * max(0, o.junk))
            if self.rng.random() < prob:
                # `if c then A else B` -> `if not c then B else A`.  The
                # condition is still evaluated exactly once, first.
                cond = self.add("UN", self.p.unmap["Not"], cond)
                elsebody = n.get("elsebody")
                # `elsebody` can be an AstStatBlock or a nested AstStatIf for
                # an elseif chain. Compile it as a statement, not as a block
                # body, or the entire chain is silently dropped.
                then_part = (
                    self.stmt(elsebody)
                    if isinstance(elsebody, dict) else self.block([])
                )
                else_part = self.block(n["thenbody"].get("body") or [])
                self.p.control_flow["inverted_branches"] = (
                    self.p.control_flow.get("inverted_branches", 0) + 1
                )
                return self.add("IF", cond, then_part, else_part)
            elsebody = n.get("elsebody")
            els = self.stmt(elsebody) if isinstance(elsebody, dict) else 0
            return self.add(
                "IF", cond, self.block(n["thenbody"].get("body") or []), els
            )
        if t == "AstStatWhile":
            return self.add(
                "WHILE", self.expr(n["condition"]), self.block(n["body"].get("body") or [])
            )
        if t == "AstStatRepeat":
            return self.add(
                "REPEAT", self.block(n["body"].get("body") or []), self.expr(n["condition"])
            )
        if t == "AstStatFor":
            step = self.expr(n["step"]) if n.get("step") else 0
            return self.add(
                "FOR", self.did(n["var"]), self.expr(n["from"]),
                self.expr(n["to"]), step, self.block(n["body"].get("body") or []),
            )
        if t == "AstStatForIn":
            vs = n.get("vars") or []
            vals = n.get("values") or []
            ds = [self.did(v) for v in vs]
            es = [self.expr(v) for v in vals]
            body = self.block(n["body"].get("body") or [])
            return self.add("FORIN", len(vs), *ds, len(vals), *es, body)
        if t == "AstStatReturn":
            es = [self.expr(v) for v in (n.get("list") or [])]
            return self.add("RETURN", len(es), *es)
        if t == "AstStatBreak":
            return self.add("BREAK")
        if t == "AstStatContinue":
            return self.add("CONTINUE")
        raise Unsupported(f"statement {t}")

    # -- expressions -------------------------------------------------------
    @_located
    def lvalue(self, n: dict) -> int:
        t = n.get("type")
        if t == "AstExprLocal":
            return self.add("VAR", self.did(n["local"]))
        if t == "AstExprGlobal":
            return self.add("GLOBAL", self.kstr(n["global"]))
        if t == "AstExprIndexName":
            return self.add("INDEXNAME", self.expr(n["expr"]), self.kstr(n["index"]))
        if t == "AstExprIndexExpr":
            return self.add("INDEX", self.expr(n["expr"]), self.expr(n["index"]))
        if t == "AstExprGroup":
            return self.lvalue(n["expr"])
        raise Unsupported(f"lvalue {t}")

    @_located
    def expr(self, n: dict) -> int:
        t = n.get("type")
        if t == "AstExprConstantString":
            return self.add("CONST", self.kstr(n["value"]))
        if t == "AstExprConstantNumber":
            return self.add("CONST", self.pool.add_number(n["value"]))
        if t == "AstExprConstantBool":
            return self.add("CONST", self.pool.add_bool(bool(n["value"])))
        if t == "AstExprConstantNil":
            return self.add("CONST", self.pool.add_nil())
        if t == "AstExprLocal":
            return self.add("VAR", self.did(n["local"]))
        if t == "AstExprGlobal":
            return self.add("GLOBAL", self.kstr(n["global"]))
        if t == "AstExprGroup" or t == "AstExprTypeAssertion":
            return self.expr(n["expr"])
        if t == "AstExprBinary":
            op = n.get("op")
            if op == "And":
                return self.add("AND", self.expr(n["left"]), self.expr(n["right"]))
            if op == "Or":
                return self.add("OR", self.expr(n["left"]), self.expr(n["right"]))
            code = self.p.binmap.get(op)
            if code is None:
                raise Unsupported(f"binary op {op}")
            return self.add("BIN", code, self.expr(n["left"]), self.expr(n["right"]))
        if t == "AstExprUnary":
            code = self.p.unmap.get(n.get("op"))
            if code is None:
                raise Unsupported(f"unary op {n.get('op')}")
            return self.add("UN", code, self.expr(n["expr"]))
        if t == "AstExprCall":
            if n.get("self"):
                f = n["func"]
                if f.get("type") != "AstExprIndexName":
                    raise Unsupported("self-call on non-name")
                obj = self.expr(f["expr"])
                args = [self.expr(a) for a in (n.get("args") or [])]
                return self.add("SELFCALL", obj, self.kstr(f["index"]), len(args), *args)
            args = [self.expr(a) for a in (n.get("args") or [])]
            return self.add("CALL", self.expr(n["func"]), len(args), *args)
        if t == "AstExprIndexName":
            return self.add("INDEXNAME", self.expr(n["expr"]), self.kstr(n["index"]))
        if t == "AstExprIndexExpr":
            return self.add("INDEX", self.expr(n["expr"]), self.expr(n["index"]))
        if t == "AstExprTable":
            items = n.get("items") or []
            flat: list[int] = []
            for it in items:
                kind = it.get("kind")
                val = self.expr(it["value"])
                if kind == "item":
                    flat += [0, 0, val]
                elif kind == "record":
                    key = it["key"]
                    if key.get("type") != "AstExprConstantString":
                        raise Unsupported("record key is not a string")
                    flat += [1, self.kstr(key["value"]), val]
                elif kind == "general":
                    flat += [2, self.expr(it["key"]), val]
                else:
                    raise Unsupported(f"table item kind {kind}")
            return self.add("TABLE", len(items), *flat)
        if t == "AstExprFunction":
            return self.add("FUNCTION", self.proto(n))
        if t == "AstExprVarargs":
            return self.add("VARARGS")
        if t == "AstExprInterpString":
            segs = n.get("strings") or []
            exprs = n.get("expressions") or []
            if len(segs) != len(exprs) + 1:
                raise Unsupported("malformed interpolation")
            flat = [len(exprs)]
            for i, e in enumerate(exprs):
                flat += [self.kstr(segs[i]), self.expr(e)]
            flat += [self.kstr(segs[-1])]
            return self.add("INTERP", *flat)
        if t == "AstExprIfElse":
            cond = self.expr(n["condition"])
            tr = self.expr(n["trueExpr"]) if n.get("hasThen") else self.add("NIL")
            fa = self.expr(n["falseExpr"]) if n.get("hasElse") else self.add("NIL")
            return self.add("IFELSE", cond, tr, fa)
        raise Unsupported(f"expression {t}")

    # -- functions ---------------------------------------------------------
    @_located
    def proto(self, n: dict, extra_self: int | None = None) -> int:
        params: list[int] = []
        if extra_self is not None:
            params.append(extra_self)
        for a in n.get("args") or []:
            params.append(self.did(a))
        vararg = 1 if n.get("vararg") else 0
        body = self.block(n["body"].get("body") or [])
        return self.add("PROTO", len(params), *params, vararg, body)

    # -- serialisation -----------------------------------------------------
    def finish(self, root: dict) -> Program:
        self._loc = root.get("location")
        self.p.entry = self.block(root.get("body") or [])
        r = self.rng
        num_nodes = len(self.p.nodes)
        layout = self.ctx.layout

        keys: set[int] = set()

        def key16() -> int:
            while True:
                v = r.randrange(1, 1 << 16)
                if v not in keys:
                    keys.add(v)
                    return v

        self.p.op_key = key16()
        self.p.len_key = key16()
        self.p.arg_key = key16()
        self.p.node_outer_key = key16()
        self.p.node_op_selector = key16()
        self.p.node_len_selector = key16()
        self.p.node_arg_selector = key16()
        self.p.node_style = layout.node_style
        self.p.word_order = r.choice(("op_len", "len_op"))
        self.p.stream_order = r.choice(("offset_prefix", "offset_suffix"))
        self.p.operand_mode = r.choice(("affine", "xor", "reverse"))

        max_physical = max(
            1, max((len(args) for _op, args in self.p.nodes), default=0) + 3
        )
        if self.p.operand_mode == "xor":
            self.p.operand_a = r.randrange(1, 1 << 16)
            self.p.operand_b = 0
        elif self.p.operand_mode == "reverse":
            self.p.operand_a = _next_prime(max_physical + 1)
            self.p.operand_b = r.randrange(0, 1 << 20)
        else:
            self.p.operand_a = _next_prime(max_physical + 1)
            self.p.operand_b = r.randrange(0, 1 << 20)
        # The physical operand permutation is derived from the logical node
        # index and private layout coefficients, not one global expression.
        self.p.operand_expr = (
            f"per_node({self.p.operand_mode}, "
            f"c={self.layout.per_node_operand_c}, "
            f"d={self.layout.per_node_operand_d}, m)"
        )
        # Legacy key names stay for public build metadata/API compatibility.
        self.p.operand_stride = self.p.operand_a
        self.p.operand_shift = self.p.operand_b

        def arg_count(nargs: int) -> int:
            # A prime (or power of two for xor) makes the per-node affine
            # coefficients below invertible for every node operand count.
            if self.p.operand_mode == "xor":
                need = max(2, nargs + 1)
                return 1 << (need - 1).bit_length()
            return _next_prime(max(2, nargs + r.randint(0, 3) + 1))

        def perm(i: int, m: int, n: int) -> int:
            c = self.layout.per_node_operand_c
            d = self.layout.per_node_operand_d
            if m == 1:
                return 1
            a = ((n * c + d) % (m - 1)) + 1
            b = (n * d + c) % m
            if self.p.operand_mode == "affine":
                return ((i - 1) * a + b) % m + 1
            if self.p.operand_mode == "reverse":
                return ((m - i) * a + b) % m + 1
            a = (a | 1) & (m - 1)
            return (((i - 1) ^ a) & (m - 1)) + 1

        offset_count = _next_prime(num_nodes + r.randint(4, 16))
        offset_stride = r.randrange(1, offset_count)
        offset_shift = r.randrange(0, offset_count)
        self.p.offset_count = offset_count
        self.p.offset_stride = offset_stride
        self.p.offset_shift = offset_shift

        starts = [r.randrange(0, 1 << 20) for _ in range(offset_count)]
        records: list[list[int]] = []
        for logical, (op, args) in enumerate(self.p.nodes, 1):
            m = arg_count(len(args))
            phys = [0] * m
            for i in range(1, m + 1):
                p = perm(i, m, logical)
                if i <= len(args):
                    phys[p - 1] = args[i - 1] & 0xFFFFFFFF
                else:
                    phys[p - 1] = r.randrange(0, 1 << 32)
            if self.p.word_order == "op_len":
                head = [self.p.opcodes[op], m]
            else:
                head = [m, self.p.opcodes[op]]
            records.append(head + phys)

        # Physical node records are shuffled and interleaved with decoy words;
        # references remain logical node indices resolved through offset words.
        order = list(range(num_nodes))
        r.shuffle(order)
        node_words: list[int] = []
        physical_start = [0] * num_nodes
        self.p.control_flow["node_order_shuffled"] = True
        for idx in order:
            if r.random() < 0.55:
                node_words.append(r.choice(self.p.decoy_opcodes))
                node_words.append(0)
            physical_start[idx] = len(node_words)
            node_words.extend(records[idx])

        # trailing decoy words so the stream length is not a signature
        for _ in range(r.randint(2, 8)):
            node_words += [r.choice(self.p.decoy_opcodes), 0]

        o = self.ctx.opts
        base = min(max(0, o.blob_pad) // 16, 4096)
        factor = max(0.0, min(o.flatten_ratio, 4.0))
        junk_bonus = max(0, o.junk) * 32
        min_bonus = max(0, 64 - min(o.min_stmts, 64)) * 4
        pad_words = min(int(base * factor) + junk_bonus + min_bonus, 16384)
        self.p.pad_words = pad_words
        if pad_words:
            pr = random.Random(o.seed ^ 0xB10B5EED)
            for _ in range(pad_words):
                n = pr.randint(0, 4)
                node_words.append(pr.choice(self.p.decoy_opcodes))
                node_words.append(n)
                node_words.extend(pr.randrange(0, 1 << 20) for _ in range(n))

        if self.p.stream_order == "offset_prefix":
            region = offset_count
            self.p.offset_base = 0
            ints = starts + node_words
        else:
            region = 0
            self.p.offset_base = len(node_words)
            ints = node_words + starts
        for n in range(1, num_nodes + 1):
            slot = (
                (n - 1) * offset_stride + offset_shift
            ) % offset_count + 1
            starts[slot - 1] = region + physical_start[n - 1]

        if self.p.stream_order == "offset_prefix":
            ints = starts + node_words
        else:
            ints = node_words + starts

        plain = b"".join((v & 0xFFFFFFFF).to_bytes(4, "big") for v in ints)
        total_words = len(ints)
        requested = max(1, int(getattr(o, "vm_fragments", 4)))
        frag_count = max(1, min(requested, total_words))
        words_per_fragment = (total_words + frag_count - 1) // frag_count
        self.p.words_per_fragment = words_per_fragment
        self.p.fragment_count = frag_count

        fragments: list[StreamFragment] = []
        for f in range(frag_count):
            lo = f * words_per_fragment * 4
            hi = min(len(plain), (f + 1) * words_per_fragment * 4)
            chunk = plain[lo:hi]
            keylen = r.randint(8, 24)
            key = bytes(r.randrange(256) for _ in range(keylen))
            delta = r.randint(1, 251)
            gamma = r.randint(1, 251)
            salt = r.randint(0, keylen - 1)

            def enc(j: int, p: int) -> int:
                return (p + key[(j + salt) % keylen] + j * delta + (j // 8) * gamma) & 0xFF

            blob = bytes(enc(j, p) for j, p in enumerate(chunk))
            hp = make_params(r, blob + key)
            fragments.append(StreamFragment(
                index=f + 1,
                blob=blob,
                key=key,
                delta=delta,
                gamma=gamma,
                salt=salt,
                expected_hash=hp.expected,
                hash_params=hp,
                blob_literal=lua_bytes_literal(blob),
                key_literal=lua_bytes_literal(key),
                word_count=(hi - lo) // 4,
            ))

        self.p.fragments = fragments
        self.p.stream = b"".join(x.blob for x in fragments)
        self.p.stream_key = b"".join(x.key for x in fragments)
        self.p.hash_params = make_params(r, self.p.stream + self.p.stream_key)
        self.p.delta = fragments[0].delta
        self.p.gamma = fragments[0].gamma
        self.p.salt = fragments[0].salt
        self.p.stream_literal = fragments[0].blob_literal
        self.p.key_literal = fragments[0].key_literal
        self.p.operand_info = {
            "op_key": self.p.op_key,
            "len_key": self.p.len_key,
            "arg_key": self.p.arg_key,
            "mode": self.p.operand_mode,
            "a": self.p.operand_a,
            "b": self.p.operand_b,
            "expression": self.p.operand_expr,
            "word_order": self.p.word_order,
            "stream_order": self.p.stream_order,
            "offset_base": self.p.offset_base,
            "offset_count": offset_count,
            "offset_stride": offset_stride,
            "offset_shift": offset_shift,
            "words_per_fragment": words_per_fragment,
            "fragment_count": frag_count,
            "node_style": self.p.node_style,
            "node_outer_key": self.p.node_outer_key,
            "node_op_selector": self.p.node_op_selector,
            "node_len_selector": self.p.node_len_selector,
            "node_arg_selector": self.p.node_arg_selector,
            "physical_node_order": order,
            "per_node_operands": {
                "mode": self.p.operand_mode,
                "c": self.layout.per_node_operand_c,
                "d": self.layout.per_node_operand_d,
                "m_prime_or_power_of_two": True,
            },
        }

        self.p.source_map = []
        for i, (op, args) in enumerate(self.p.nodes, 1):
            loc = self.p.locations[i - 1] if i - 1 < len(self.p.locations) else None
            sp = self.ctx.source.span(loc)
            self.p.source_map.append({
                "index": i,
                "op": op,
                "opcode": self.p.opcodes[op],
                "operands": list(args),
                "span": list(sp) if sp else None,
                "excerpt": (
                    self.ctx.source.slice(sp).decode("utf-8", "replace")[:160] if sp else None
                ),
            })
        return self.p


def compile_program(tree: dict, ctx: Context) -> Program:
    c = Compiler(ctx)
    return c.finish(tree["root"])
