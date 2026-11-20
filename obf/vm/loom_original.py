"""Adapter for the vendored Loom Original VM core (vendor/loom-original).

The Original edition compiles a deliberately small Luau subset straight to
register bytecode and emits a single-file Luau chunk whose only runtime
dependency is the stock Luau standard library plus Roblox services
(``workspace``/``game``). It is offered as an *explicit* alternative backend
(``Options(loom_original=True)``); it never silently replaces the V7 single
VM pipeline, and any out-of-subset construct raises ``LoomOriginalUnsupported``
with the parser location instead of emitting unprotected source.
"""
from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
from pathlib import Path

from ..ast import tool_path, ToolMissing

_VENDOR = Path(__file__).resolve().parent.parent.parent / "vendor" / "loom-original"
_MODULE_NAME = "grandfuscate_loom_original_core"


class LoomOriginalUnsupported(ValueError):
    """The input uses a construct outside the Original VM subset."""


def _load_core():
    spec = importlib.util.spec_from_file_location(_MODULE_NAME, _VENDOR / "loom.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[_MODULE_NAME] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def loom_original_available() -> bool:
    return (_VENDOR / "loom.py").is_file() and (_VENDOR / "runtime.luau.in").is_file()


def compile_source(data: bytes, *, seed: int | None = None, parser: str | None = None) -> str:
    """Compile ``data`` to a single-file Loom Original chunk.

    Raises :class:`LoomOriginalUnsupported` (a ``ValueError``) when the input
    is outside the subset, and :class:`OSError` when the vendored core is
    missing or broken. The parser defaults to ``LUAU_AST`` on the environment
    or ``luau-ast`` on PATH, matching the rest of the toolchain.
    """
    if not loom_original_available():
        raise OSError(f"vendored Loom Original core is missing at {_VENDOR}")
    core = _load_core()
    try:
        resolved = parser or os.environ.get("LUAU_AST") or tool_path("luau-ast")
    except ToolMissing as exc:
        raise OSError(str(exc)) from exc
    with tempfile.TemporaryDirectory(prefix="loom-original-") as tmp:
        src = Path(tmp, "input.luau")
        src.write_bytes(data)
        try:
            return core.compile_file(src, resolved, seed)
        except core.Unsupported as exc:  # type: ignore[attr-defined]
            raise LoomOriginalUnsupported(str(exc)) from exc
