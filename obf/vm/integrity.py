"""Build-time VM integrity manifest and distributed runtime verification (v4).

A canonical byte representation of the compiled VM state — instruction stream,
fragment blobs/keys, constant-pool slices/keys, opcode/bin/un maps, dispatch
coefficients and per-node operand coefficients — is folded into per-domain
rolling checksums (``ChecksumParams``). These are obfuscation checksums, not a
cryptographic MAC and not a security boundary.

Each domain's expected digest becomes the seed of a bounded window checksum
over an inert high-entropy marker literal. The check is emitted next to that
domain's real decoder and folds a mismatch into the decoder's existing ``ok``
flag, which already returns a harmless default (option 1 of ``do 1 and 2``).
Tickets are additionally salted per build through ``Layout.integrity_salt``.
"""
from __future__ import annotations

import math
import random
from dataclasses import dataclass, field

from .. import entropy as EN
from ..checksum import ChecksumParams, checksum, make_params
from . import traps as TR

DOMAINS: tuple[str, ...] = (
    "byte", "fragment", "word", "node", "constant", "eval", "exec",
)
# Which real decoder `ok` flag each domain folds into.
DOMAIN_OK = {
    "byte": "byte", "fragment": "byte",
    "word": "word", "node": "node",
    "constant": "eval", "eval": "eval", "exec": "exec",
}

# v3 benchmark sizes (used only as the <=15% size-gate reference).
V3_BASELINE = {"light": 156438, "medium": 196415, "heavy": 610864}
# Approximate build sizes (compact-name build, no v4 additions).
BASE_NO_V4 = {"light": 103000, "medium": 140000, "heavy": 537000}


def _i(x) -> bytes:
    return (int(x) & ((1 << 64) - 1)).to_bytes(8, "big")


def _b(x: bytes) -> bytes:
    x = bytes(x)
    return len(x).to_bytes(4, "big") + x


def _s(x: str) -> bytes:
    d = x.encode("utf-8")
    return len(d).to_bytes(2, "big") + d


def _map(name: str, m: dict) -> bytes:
    out = [_s(name)]
    for k in sorted(m):
        out.append(_s(str(k)))
        out.append(_i(m[k]))
    return b"".join(out)


def _hp(p: ChecksumParams) -> bytes:
    return b"".join(_i(v) for v in (p.seed, p.add, p.k, p.j_mod, p.expected))


def canonical_bytes(program, built, layout) -> bytes:
    """Deterministic, structured encoding of the core VM encoded state."""
    p: list[bytes] = [b"GFV4"]
    p.append(_map("opcodes", program.opcodes))
    p.append(_map("binmap", program.binmap))
    p.append(_map("unmap", program.unmap))
    p.append(_i(len(program.decoy_opcodes)))
    for x in program.decoy_opcodes:
        p.append(_i(x))
    p.append(_b(program.stream))
    p.append(_b(program.stream_key))
    for attr in ("delta", "gamma", "salt", "op_key", "len_key", "arg_key",
                 "operand_stride", "operand_shift", "operand_a", "operand_b",
                 "offset_base", "offset_count", "offset_stride", "offset_shift",
                 "node_outer_key", "node_op_selector", "node_len_selector",
                 "node_arg_selector", "words_per_fragment", "fragment_count",
                 "pad_words", "entry"):
        p.append(_i(getattr(program, attr, 0)))
    for attr in ("word_order", "stream_order", "operand_mode", "node_style"):
        p.append(_s(str(getattr(program, attr, ""))))
    p.append(_i(len(program.fragments)))
    for f in program.fragments:
        p.append(_b(f.blob))
        p.append(_b(f.key))
        for attr in ("delta", "gamma", "salt", "expected_hash", "word_count"):
            p.append(_i(getattr(f, attr, 0)))
        hp = getattr(f, "hash_params", None)
        if hp is not None:
            p.append(_hp(hp))
    p.append(_i(len(built.slices)))
    for sl in built.slices:
        p.append(_b(sl.blob))
        p.append(_b(sl.key))
        for attr in ("delta", "gamma", "salt", "expected_hash", "count"):
            p.append(_i(getattr(sl, attr, 0)))
        hp = getattr(sl, "hash_params", None)
        if hp is not None:
            p.append(_hp(hp))
    for attr in ("dispatch_n", "dispatch_b", "slot_base", "const_span",
                 "const_bias", "bank_count", "bank_a", "bank_b",
                 "handler_groups", "handler_a", "handler_b", "word_groups",
                 "word_a", "word_b", "constant_groups", "constant_a",
                 "constant_b", "node_groups", "node_a", "node_b",
                 "byte_groups", "byte_a", "byte_b", "per_node_operand_c",
                 "per_node_operand_d", "slice_stride", "slice_shift",
                 "integrity_salt"):
        p.append(_i(getattr(layout, attr, 0)))
    return b"".join(p)


@dataclass
class VMIntegrityPlan:
    global_digest: int
    group_digests: dict[str, int]
    trap_salt: int
    ticket_salt: int
    expected_by_group: dict[str, ChecksumParams]
    canonical_len: int
    real_opcode_values: frozenset[int]
    canon: bytes = b""  # private build-time manifest; never emitted


def plan_digests(canon: bytes, rng: random.Random) -> tuple[dict, dict, int]:
    """Split a canonical manifest into per-domain checksums + a global digest.

    Pure and deterministic for a given ``rng`` seed, so a tampered manifest can
    be compared against the original in tests. Tampering any region changes the
    checksum of the domain that owns it (and hence the global digest).
    """
    n = len(DOMAINS)
    step = max(1, math.ceil(len(canon) / n))
    group_digests: dict[str, int] = {}
    expected_by_group: dict[str, ChecksumParams] = {}
    for idx, dom in enumerate(DOMAINS):
        chunk = canon[idx * step:(idx + 1) * step] or canon[-1:]
        cp = make_params(rng, chunk)
        expected_by_group[dom] = cp
        group_digests[dom] = cp.expected
    gbytes = b"".join(_i(group_digests[d]) for d in DOMAINS)
    global_digest = make_params(rng, gbytes).expected
    return group_digests, expected_by_group, global_digest


def build_integrity_plan(program, built, layout, rng: random.Random) -> VMIntegrityPlan:
    canon = canonical_bytes(program, built, layout)
    group_digests, expected_by_group, global_digest = plan_digests(canon, rng)
    trap_salt = (global_digest ^ 0x5BF03635) & 0x7FFFFFFF
    ticket_salt = (global_digest * 2654435761) & 0x7FFFFFFF
    real = set(int(v) for v in program.opcodes.values())
    real |= set(int(v) for v in program.binmap.values())
    real |= set(int(v) for v in program.unmap.values())
    real |= set(int(v) for v in program.decoy_opcodes)
    return VMIntegrityPlan(
        global_digest=global_digest,
        group_digests=group_digests,
        trap_salt=trap_salt,
        ticket_salt=ticket_salt,
        expected_by_group=expected_by_group,
        canonical_len=len(canon),
        real_opcode_values=frozenset(real),
        canon=canon,
    )


@dataclass
class Marker:
    var: str
    literal: str
    domain: str
    params: ChecksumParams
    form: str  # "long" or "quoted"
    decoded: bytes


@dataclass
class V4Plan:
    integrity: VMIntegrityPlan
    traps: TR.TrapPlan
    markers: list[Marker] = field(default_factory=list)
    domain_markers: dict[str, list[Marker]] = field(default_factory=dict)
    h_vars: dict[str, str] = field(default_factory=dict)
    j_vars: dict[str, str] = field(default_factory=dict)
    padding_bytes: int = 0
    budget: EN.LiteralBudget | None = None

    @property
    def decoy_opcodes(self) -> list[int]:
        return [d.key for d in self.traps.decoys]

    def emit_marker_definitions(self) -> list[str]:
        return [f"local {m.var} = {m.literal}" for m in self.markers]

    def emit_trap_group(self) -> list[str]:
        return TR.emit_trap_group_lines(self.traps)

    def emit_verify_lines(self, domains: list[str], ok_var: str,
                          indent: str = "") -> list[str]:
        """Window checksums for the given domains, folding into ``ok_var``.

        Uses only a bounded ``for j = 1, WINDOW`` loop (no unbounded work). All
        referenced globals (bit32.bxor, string.byte) are alias-rewritten later.
        """
        L: list[str] = []
        W = EN.INTEGRITY_WINDOW
        for dom in domains:
            m = self.domain_markers[dom][0]
            h, j = self.h_vars[dom], self.j_vars[dom]
            p = m.params
            L.append(f"{indent}local {h} = {p.seed}")
            L.append(f"{indent}for {j} = 1, {W} do")
            L.append(
                f"{indent}  {h} = (bit32.bxor({h}, string.byte({m.var}, {j})) "
                f"+ {p.add} + ({j} % {p.j_mod}) * {p.k}) % (2 ^ 32)"
            )
            L.append(f"{indent}end")
            L.append(f"{indent}if {h} ~= {p.expected} then {ok_var} = false end")
        return L


def _marker_params(rng: random.Random, digest: int, decoded: bytes) -> ChecksumParams:
    """A window checksum whose seed is the domain's manifest digest."""
    p = ChecksumParams(
        seed=digest & 0xFFFFFFFF,
        add=rng.randrange(1, 1 << 20),
        k=rng.randrange(1, 1 << 20),
        j_mod=rng.randrange(97, 251),
        expected=0,
    )
    window = decoded[:EN.INTEGRITY_WINDOW]
    expected = checksum(window, p)
    return ChecksumParams(p.seed, p.add, p.k, p.j_mod, expected)


def prepare_v4(ctx, program, built, layout, opts, base_bytes: int | None = None) -> V4Plan:
    """Build the whole v4 plan and stash it on ``ctx`` for the VM renderer.

    ``base_bytes`` is the exact size of the same build with zero entropy
    padding (measured by :func:`obf.pipeline.obfuscate`). Feeding the real base
    into :class:`~obf.entropy.LiteralBudget` makes the ``<=15%`` size gate hold
    for every seed, not just the seed the v3 baseline was measured on.
    """
    ns = ctx.names
    # A dedicated RNG keeps v4 reproducible without perturbing the existing
    # build's random stream (so adding v4 does not change non-v4 structure).
    rng = random.Random((int(opts.seed) ^ 0x56463431) & 0xFFFFFFFF)
    integrity = build_integrity_plan(program, built, layout, rng)
    traps = TR.make_trap_plan(
        rng, integrity, max(0, int(opts.decoy_traps)), ns
    )

    # The measured base already contains the marker/trap/verify skeleton, so
    # the only remaining budget room goes to the inert symbol-soup padding.
    budget = EN.LiteralBudget(
        baseline_bytes=V3_BASELINE.get(opts.preset, V3_BASELINE["medium"]),
        base_bytes=(base_bytes if base_bytes is not None
                    else BASE_NO_V4.get(opts.preset, BASE_NO_V4["medium"])),
        structural_estimate=0,
        safety=0.06,
    )
    padding = min(int(opts.entropy_budget), budget.padding_bytes)

    # Split the symbol soup across six long-bracket markers; one domain carries
    # a small mixed-escape quoted marker so both literal forms are exercised.
    quoted_domain = "constant"
    long_domains = [d for d in DOMAINS if d != quoted_domain]
    per = max(EN.INTEGRITY_WINDOW + 8, padding // max(1, len(long_domains)))
    markers: list[Marker] = []
    domain_markers: dict[str, list[Marker]] = {}
    h_vars: dict[str, str] = {}
    j_vars: dict[str, str] = {}
    for dom in DOMAINS:
        var = ns.fresh_runtime()
        digest = integrity.group_digests[dom]
        if dom == quoted_domain:
            decoded = bytes(rng.randrange(256) for _ in range(256))
            eq = None
            literal = EN.lua_mixed_quoted(decoded, rng)
            form = "quoted"
        else:
            decoded = EN.symbol_soup(rng, per)
            eq = rng.randint(0, 4)
            literal = EN.lua_long_bracket(decoded, eq)
            form = "long"
        params = _marker_params(rng, digest, decoded)
        m = Marker(var=var, literal=literal, domain=dom, params=params,
                   form=form, decoded=decoded)
        markers.append(m)
        domain_markers[dom] = [m]
        h_vars[dom] = ns.fresh_runtime()
        j_vars[dom] = ns.fresh_runtime()

    plan = V4Plan(
        integrity=integrity,
        traps=traps,
        markers=markers,
        domain_markers=domain_markers,
        h_vars=h_vars,
        j_vars=j_vars,
        padding_bytes=padding,
        budget=budget,
    )
    ctx.v4 = plan
    return plan


def make_integrity_probe_script(marker: Marker, tamper: bool) -> str:
    """Standalone Luau exercising one marker's window check (tests only)."""
    m = marker
    literal = m.literal
    if tamper:
        # Flip one symbol inside the first window of a long-bracket marker.
        if m.form == "long" and len(m.decoded) > 20:
            body = literal
            # Replace a soup char at a fixed offset near the start.
            start = body.find("[") + 1
            while start < len(body) and body[start] == "=":
                start += 1
            start += 1  # past the opening '['
            pos = start + 10
            repl = "%" if body[pos] != "%" else "#"
            body = body[:pos] + repl + body[pos + 1:]
            literal = body
    p = m.params
    W = EN.INTEGRITY_WINDOW
    return "\n".join([
        f"local m = {literal}",
        f"local h = {p.seed}",
        f"for j = 1, {W} do",
        f"  h = (bit32.bxor(h, string.byte(m, j)) + {p.add} "
        f"+ (j % {p.j_mod}) * {p.k}) % (2 ^ 32)",
        "end",
        f'print((h ~= {p.expected}) and "OK_FALSE" or "OK_TRUE")',
    ]) + "\n"
