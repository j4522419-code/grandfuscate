"""Opaque predicates and decoy statements used by the flattener."""
from __future__ import annotations

from .render import Context


def opaque_true(ctx: Context) -> bytes:
    """Always true, never a literal `true`, cheap enough for a hot dispatch."""
    r = ctx.rng
    a = r.randrange(2, 9999)
    shape = r.randrange(4)
    if shape == 0:
        return f"(({a} * {a} + {a}) % 2 == 0)".encode()
    if shape == 1:
        b = r.randrange(2, 9999)
        return f"(({a} + {b}) * ({a} - {b}) == {a * a - b * b})".encode()
    if shape == 2:
        return f"(bit32.bxor({a}, {a}) == 0)".encode()
    return f"(({a} * 2) % 2 == 0)".encode()


def opaque_false(ctx: Context) -> bytes:
    r = ctx.rng
    a = r.randrange(2, 9999)
    shape = r.randrange(3)
    if shape == 0:
        return f"(({a} * {a} + {a} + 1) % 2 == 0)".encode()
    if shape == 1:
        return f"(({a} * 2 + 1) % 2 == 0)".encode()
    return f"(bit32.bxor({a}, {a}) ~= 0)".encode()


def junk_stmt(ctx: Context, state_name: bytes, reg_name: bytes) -> bytes:
    """Unreachable-looking noise; every branch is either dead or a no-op."""
    r = ctx.rng
    d1 = ctx.pool.add_decoy()
    d2 = ctx.pool.add_decoy()
    tmp = ctx.names.new().encode()
    shape = r.randrange(4)
    if shape == 0:
        return b"; ".join(
            [
                b"local " + tmp + b" = " + ctx.D(d1) + b" .. " + ctx.D(d2),
                state_name + b" = " + state_name + b" + 0",
            ]
        )
    if shape == 1:
        return (
            reg_name
            + b"["
            + str(r.randrange(1, 9999)).encode()
            + b"] = "
            + ctx.D(d1)
        )
    if shape == 2:
        return b"if " + opaque_false(ctx) + b" then " + state_name + b" = " + str(r.randrange(1, 2**40)).encode() + b" end"
    return b"local " + tmp + b" = #" + ctx.D(d1) + b" + #" + ctx.D(d2) + b"; " + state_name + b" = " + state_name + b" + 0"
