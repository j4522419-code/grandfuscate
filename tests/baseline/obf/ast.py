"""
Front end: turns Luau source into the official Luau AST (JSON from `luau-ast`)
and provides byte-accurate source spans.

Why the official AST: it resolves every local to its declaration, so renaming
and registerisation are scope-correct even with shadowing and upvalues.  We do
NOT emit code from the AST; we only use it to locate spans in the original
source.  That means every Luau syntax feature we do not explicitly rewrite is
preserved verbatim, automatically.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from typing import Any

TOOLS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools")


class ParseError(Exception):
    pass


class ToolMissing(Exception):
    pass


def tool_path(name: str) -> str:
    p = os.path.join(TOOLS_DIR, name)
    if os.path.isfile(p) and os.access(p, os.X_OK):
        return p
    found = shutil.which(name)
    if found:
        return found
    raise ToolMissing(
        f"{name!r} not found. Run `python3 obf/fetch_tools.py` (or put the Luau "
        f"binaries in {TOOLS_DIR}/)."
    )


LOC_RE = re.compile(r"^(\d+),(\d+)\s*-\s*(\d+),(\d+)$")


def tool_timeout() -> int:
    """Subprocess budget. Hosted deployments set OBF_TIMEOUT lower than local."""
    try:
        return max(5, int(os.environ.get("OBF_TIMEOUT", "60")))
    except ValueError:
        return 60


class Source:
    """Byte-oriented view of the input. Luau AST columns are BYTE offsets."""

    def __init__(self, data: bytes):
        self.data = data
        starts = [0]
        for i, b in enumerate(data):
            if b == 0x0A:
                starts.append(i + 1)
        self.line_starts = starts

    def span(self, loc: Any) -> tuple[int, int] | None:
        if not isinstance(loc, str):
            return None
        m = LOC_RE.match(loc)
        if not m:
            return None
        l1, c1, l2, c2 = (int(x) for x in m.groups())
        if l1 >= len(self.line_starts) or l2 >= len(self.line_starts):
            return None
        s = self.line_starts[l1] + c1
        e = self.line_starts[l2] + c2
        if s < 0 or e > len(self.data) or e < s:
            return None
        return s, e

    def slice(self, sp: tuple[int, int]) -> bytes:
        return self.data[sp[0]:sp[1]]


# Keys whose subtrees are type-level (no runtime code) or are duplicate
# references to a declaration node; the renderer must never descend into them.
IGNORED_KEYS = frozenset(
    {
        "luauType",
        "returnAnnotation",
        "annotation",
        "generics",
        "genericPacks",
        "attributes",
        "typeList",
        "commentLocations",
    }
)

TYPE_PREFIXES = ("AstType", "AstTypePack", "AstStatType", "AstStatDeclare", "AstDeclared")
DECL_KEYS = frozenset({"vars", "args", "name", "var", "self"})


def _find_errors(node: Any) -> bool:
    if isinstance(node, dict):
        t = node.get("type", "")
        if t in ("AstStatError", "AstExprError", "AstTypeError"):
            return True
        return any(_find_errors(v) for k, v in node.items() if not k.startswith("_"))
    if isinstance(node, list):
        return any(_find_errors(v) for v in node)
    return False


def parse(data: bytes) -> tuple[dict, Source]:
    exe = tool_path("luau-ast")
    fd, path = tempfile.mkstemp(suffix=".luau")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        p = subprocess.run([exe, path], capture_output=True, timeout=tool_timeout())
        try:
            tree = json.loads(p.stdout.decode("utf-8", "replace"))
        except Exception as exc:  # pragma: no cover
            raise ParseError(f"luau-ast produced no JSON: {exc}: {p.stderr[:400]!r}") from exc
        err = p.stderr.decode("utf-8", "replace")
        if p.returncode != 0 or _find_errors(tree):
            raise ParseError("Luau parse error:\n" + err.strip())
        return tree, Source(data)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def tag_tree(tree: dict) -> None:
    """Annotate nodes in-place with parent/ancestor context and role markers."""

    def visit(node: dict, ptype: str | None, pkey: str | None, ancestors: tuple) -> None:
        t = node.get("type", "")
        node["_ptype"] = ptype
        node["_pkey"] = pkey
        node["_ancestors"] = ancestors

        if t == "AstExprTableItem" and node.get("kind") == "record":
            key = node.get("key")
            if isinstance(key, dict):
                key["_record_key"] = True
        if t == "AstStatFunction":
            name = node.get("name")
            if isinstance(name, dict):
                name["_decl_name"] = True
                if name.get("op") == ":":
                    name["_method_decl"] = True
        if t == "AstExprCall" and node.get("self"):
            func = node.get("func")
            if isinstance(func, dict):
                func["_self_call"] = True
        if t == "AstLocal":
            if pkey == "local":
                node["_is_ref"] = True
            elif pkey in DECL_KEYS:
                node["_is_decl"] = True

        next_anc = ancestors + ((t, pkey),)

        def child(v: Any, k: str) -> None:
            if isinstance(v, dict) and "type" in v:
                visit(v, t, k, next_anc)
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, dict) and "type" in item:
                        visit(item, t, k, next_anc)

        for k, v in node.items():
            if k.startswith("_") or k in IGNORED_KEYS:
                continue
            if isinstance(v, dict) and "type" in v:
                visit(v, t, k, next_anc)
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, dict) and "type" in item:
                        visit(item, t, k, next_anc)

    root = tree["root"]
    visit(root, None, None, ())


def iter_nodes(node: Any):
    if isinstance(node, dict):
        if "type" in node:
            yield node
        for k, v in node.items():
            if k.startswith("_") or k in IGNORED_KEYS:
                continue
            yield from iter_nodes(v)
    elif isinstance(node, list):
        for v in node:
            yield from iter_nodes(v)


def decl_locations(tree: dict) -> list[str]:
    """Every distinct local declaration, keyed by its AST location string."""
    seen: list[str] = []
    found = set()
    for n in iter_nodes(tree):
        if n.get("type") == "AstLocal" and n.get("_is_decl"):
            loc = n.get("location")
            if loc and loc not in found:
                found.add(loc)
                seen.append(loc)
    return seen
