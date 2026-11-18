"""
Luau AST -> custom IR -> fragmented, randomly laid-out instruction stream.

Each build gets:
  * random 32-bit opcode / operator values instead of a small 1..N range;
  * a per-build affine operand permutation with decoy operand slots;
  * a scrambled offset region instead of a sequential node array;
  * several independently encrypted stream fragments with late word decoding;
  * private source spans for the debug/source map.

No source text, identifier, string literal or number literal survives in the
emitted program; everything lives in the encrypted constant pool or stream.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from functools import wraps

from .. import ast as A
from ..pool import ConstantPool, lua_bytes_literal
from ..render import Context


class Unsupported(Exception):
    """The AST contains something the prototype VM cannot compile."""


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

IGNORED_STATEMENTS = frozenset(
    {"AstStatTypeAlias", "AstStatTypeFunction", "AstStatDeclareGlobal",
     "AstStatDeclareFunction", "AstStatDeclareClass"}
)


def _fnv(data: bytes, seed: int = 0x811C9DC5) -> int:
    h = seed
    for j, c in enumerate(data):
        h ^= c
        h = (h + ((j + 1) % 256) * 16777619) & 0xFFFFFFFF
    return h


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
        return self.add("BLOCK", len(stmts), *stmts)

    @_located
    def stmt(self, n: dict) -> int:
        t = n.get("type")
        if t == "AstStatBlock":
            return self.block(n.get("body") or [])
        if t in IGNORED_STATEMENTS:
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
            elsebody = n.get("elsebody")
            els = self.stmt(elsebody) if isinstance(elsebody, dict) else 0
            return self.add(
                "IF", self.expr(n["condition"]), self.block(n["thenbody"].get("body") or []), els
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
        max_physical = max(
            1, max((len(args) for _op, args in self.p.nodes), default=0) + 3
        )
        self.p.operand_stride = _next_prime(max_physical + 1)
        self.p.operand_shift = r.randrange(0, 1 << 20)

        offset_count = _next_prime(num_nodes + r.randint(4, 16))
        offset_stride = r.randrange(1, offset_count)
        offset_shift = r.randrange(0, offset_count)
        self.p.offset_base = 0
        self.p.offset_count = offset_count
        self.p.offset_stride = offset_stride
        self.p.offset_shift = offset_shift

        starts = [r.randrange(0, 1 << 20) for _ in range(offset_count)]
        node_words: list[int] = []

        for n, (op, args) in enumerate(self.p.nodes, 1):
            local_start = len(node_words)
            m = max(1, len(args) + r.randint(0, 3))
            A = self.p.operand_stride
            Bv = self.p.operand_shift
            invA = pow(A, -1, m)
            phys = [0] * m
            for p in range(1, m + 1):
                i = ((p - 1 - Bv) * invA) % m + 1
                if i <= len(args):
                    phys[p - 1] = args[i - 1] & 0xFFFFFFFF
                else:
                    phys[p - 1] = r.randrange(0, 1 << 32)
            node_words.extend([self.p.opcodes[op], m, *phys])
            slot = ((n - 1) * offset_stride + offset_shift) % offset_count + 1
            starts[slot - 1] = offset_count + local_start

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

        ints = starts + node_words
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
            fragments.append(StreamFragment(
                index=f + 1,
                blob=blob,
                key=key,
                delta=delta,
                gamma=gamma,
                salt=salt,
                expected_hash=_fnv(blob + key),
                blob_literal=lua_bytes_literal(blob),
                key_literal=lua_bytes_literal(key),
                word_count=(hi - lo) // 4,
            ))

        self.p.fragments = fragments
        self.p.stream = b"".join(x.blob for x in fragments)
        self.p.stream_key = b"".join(x.key for x in fragments)
        self.p.delta = fragments[0].delta
        self.p.gamma = fragments[0].gamma
        self.p.salt = fragments[0].salt
        self.p.stream_literal = fragments[0].blob_literal
        self.p.key_literal = fragments[0].key_literal
        self.p.operand_info = {
            "op_key": self.p.op_key,
            "len_key": self.p.len_key,
            "arg_key": self.p.arg_key,
            "stride": self.p.operand_stride,
            "shift": self.p.operand_shift,
            "offset_count": offset_count,
            "offset_stride": offset_stride,
            "offset_shift": offset_shift,
            "words_per_fragment": words_per_fragment,
            "fragment_count": frag_count,
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
