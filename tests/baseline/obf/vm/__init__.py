"""Polymorphic VM layer (opt-in).  See compiler.py / runtime.py."""
from .compiler import Unsupported, compile_program  # noqa: F401
from . import runtime  # noqa: F401
