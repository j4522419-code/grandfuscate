"""Orchestration: parse -> analyse -> rewrite -> pack -> verify."""
from __future__ import annotations

import hashlib
import json
import os
import random
import subprocess
import tempfile
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone

from . import ast as A
from . import crypto as CR
from .banner import BANNER_BYTES, strip_banner
from . import flatten, format as F, hardening, minify, runtime, transform, vm
from .fields import randomize_fields
from .layout import make_layout
from .names import Names
from .pool import ConstantPool, PoolBuild, _next_prime
from .render import Context, Options, Renderer
from .vm.integrity import prepare_v4
from .crypto import CryptoPlan

# Bounded cache of exact zero-padding base sizes, keyed by the full option set
# and input digest. The suite, scanner and example regeneration obfuscate the
# same (opts, input) many times; measuring the base once keeps those builds from
# doing a second full render each time. Bounded so a long-lived web process does
# not grow without limit.
_V4_BASE_CACHE: dict[tuple, int] = {}
_V4_BASE_CACHE_MAX = 512


def _v4_base_key(data: bytes, opts: Options) -> tuple:
    return (
        hashlib.sha256(data).hexdigest(),
        tuple(sorted((k, repr(v)) for k, v in vars(opts).items())),
    )


@dataclass
class Result:
    output: bytes
    build: PoolBuild
    keys: dict
    stats: dict = field(default_factory=dict)
    # Private debug/source map.  It is returned to the caller but never
    # serialized into the production .luau chunk.
    source_map: dict = field(default_factory=dict)
    # Private v4 integrity/trap/entropy plan (Python-side only; used by tests
    # and reports, never embedded in the emitted chunk).
    v4: object | None = None
    # Private V5 active-decoy plan; None when stealth is off. Also reachable as
    # ``result.v4.stealth`` for compatibility with the V4 plan object.
    stealth: object | None = None
    # Private V7 crypto plan; None when crypto is off. Python-side only.
    crypto: CryptoPlan | None = None


PRESETS: dict[str, dict] = {
    "light": dict(
        vm=True, virtualize_globals=True, virtualize_properties=False,
        encode_constants=True, flatten=False, junk=0, flatten_ratio=0.0,
        min_stmts=3, integrity=True, anti_env=False, anti_tamper=False,
        nested_vm=False, blob_pad=0, pool_slices=2, vm_fragments=2,
        decoy_traps=8, entropy_budget=40000, stealth=False,
    ),
    "medium": dict(
        vm=True, virtualize_globals=True, virtualize_properties=True,
        encode_constants=True, flatten=True, junk=2, flatten_ratio=0.75,
        min_stmts=3, integrity=True, anti_env=False, anti_tamper=False,
        nested_vm=False, blob_pad=4096, pool_slices=3, vm_fragments=4,
        decoy_traps=24, entropy_budget=60000, stealth=False,
    ),
    "heavy": dict(
        vm=True, virtualize_globals=True, virtualize_properties=True,
        encode_constants=True, flatten=True, junk=8, flatten_ratio=1.0,
        min_stmts=1, integrity=True, anti_env=False, anti_tamper=False,
        nested_vm=False, blob_pad=65536, pool_slices=5, vm_fragments=7,
        decoy_traps=64, entropy_budget=100000, stealth=False,
    ),
}

# `light`, `balanced` and `aggressive` are the user-facing protection levels.
# The public preset surface stays exactly three values for UI/API compatibility.
PRESET_ALIASES: dict[str, str] = {
    "balanced": "medium",
    "aggressive": "heavy",
    "max": "heavy",
}
PROTECTION_LEVELS: dict[str, str] = {
    "light": "light",
    "medium": "balanced",
    "heavy": "aggressive",
}


def make_options(preset: str = "medium", **overrides) -> Options:
    canonical = PRESET_ALIASES.get(preset, preset)
    if canonical not in PRESETS:
        raise ValueError(f"unknown preset {preset!r}; choose from {list(PRESETS)}")
    opts = Options(preset=canonical, **PRESETS[canonical])
    for k, v in overrides.items():
        if not hasattr(opts, k):
            raise ValueError(f"unknown option {k!r}")
        setattr(opts, k, v)
    return opts


def _build_source_map(
    data: bytes,
    opts: Options,
    ctx: Context,
    pool: ConstantPool,
    vm_program,
    built: PoolBuild,
    runtime_consts: dict[str, int],
    layout,
    fmt,
) -> dict:
    """Private debug/source map.  Never serialized into production output."""
    sha = hashlib.sha256(data).hexdigest()
    nodes: list[dict] = []
    if vm_program is not None:
        for i, (op, args) in enumerate(vm_program.nodes, 1):
            span = None
            excerpt = None
            locs = getattr(vm_program, "locations", None)
            if locs and i - 1 < len(locs):
                sp = ctx.source.span(locs[i - 1])
                if sp is not None:
                    span = [sp[0], sp[1]]
                    excerpt = ctx.source.slice(sp).decode("utf-8", "replace")[:160]
            nodes.append({
                "index": i,
                "op": op,
                "opcode": getattr(vm_program, "opcodes", {}).get(op),
                "operands": list(args),
                "span": span,
                "excerpt": excerpt,
            })
    constants = []
    for i, e in enumerate(pool.entries, 1):
        constants.append({
            "index": i,
            "tag": e.tag,
            "payload_hex": e.payload.hex(),
            "text": e.text,
        })
    return {
        "marker": "__GRANDFUSCATE_PRIVATE_SOURCE_MAP_V3__",
        "format": 3,
        "build_id": built.build_id,
        "preset": opts.preset,
        "protection_level": PROTECTION_LEVELS.get(opts.preset, opts.preset),
        "seed": opts.seed,
        "input_sha256": sha,
        "input_bytes": len(data),
        "nodes": nodes,
        "constants": constants,
        "declarations": [
            {"location": loc, "renamed": name}
            for loc, name in sorted(ctx.decl_map.items())
        ],
        "opcodes": dict(vm_program.opcodes) if vm_program else {},
        "binmap": dict(vm_program.binmap) if vm_program else {},
        "unmap": dict(vm_program.unmap) if vm_program else {},
        "operand": getattr(vm_program, "operand_info", {}) if vm_program else {},
        "fragments": getattr(vm_program, "fragment_count", 0) if vm_program else 0,
        "entry_layout": fmt.shape_id,
        "boot_layout": fmt.boot_id,
        "alias_count": fmt.aliases,
        "decoy_count": fmt.decoys,
        "runtime_layout": layout.summary(),
        "field_keys": layout.field_keys,
        "pool_chunk_plans": built.chunk_plans,
        "vm_chunk_plans": getattr(vm_program, "chunk_plans", []) if vm_program else [],
        "control_flow": getattr(vm_program, "control_flow", {}) if vm_program else {},
        "compile_notes": getattr(vm_program, "compile_notes", []) if vm_program else [],
        "pool_slices": built.slice_count,
        "slice_stride": built.slice_stride,
        "slice_shift": built.slice_shift,
        "runtime_consts": runtime_consts,
        "third_pass": {
            "vm_profile": layout.vm_profile,
            "bank_count": layout.bank_count,
            "handler_groups": layout.handler_groups,
            "constant_groups": layout.constant_groups,
            "byte_groups": layout.byte_groups,
            "word_groups": layout.word_groups,
            "node_groups": layout.node_groups,
            "per_node_operands": {
                "mode": getattr(vm_program, "operand_mode", None),
                "c": layout.per_node_operand_c,
                "d": layout.per_node_operand_d,
            },
            "source_spread": dict(layout.source_spread),
            "structural_digest": hashlib.sha256(
                json.dumps(
                    [
                        layout.summary(),
                        getattr(vm_program, "operand_info", {}) if vm_program else {},
                        getattr(vm_program, "control_flow", {}) if vm_program else {},
                        built.chunk_plans,
                        getattr(vm_program, "chunk_plans", []) if vm_program else [],
                    ],
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest(),
        },
    }


def _obfuscate_loom_original(data: bytes, opts: Options) -> Result:
    """Alternative Loom Original register-VM backend (explicit opt-in).

    The output is a single-file chunk: banner line first, then the Loom
    Original loader. The input must fit Loom's small Luau subset; the
    compiler raises ``LoomOriginalUnsupported`` (a ``ValueError``) otherwise,
    and no partial/unprotected output is produced. The V7 single VM remains
    the default for general scripts.
    """
    from .vm.loom_original import compile_source

    if opts.place_id is not None or opts.game_id is not None:
        raise ValueError("loom_original backend does not support place/game locks")

    text = compile_source(data, seed=opts.seed)
    output = BANNER_BYTES + b"\n" + text.encode("utf-8")
    build_id = hashlib.sha256(
        f"loom-original|{opts.seed}|{hashlib.sha256(data).hexdigest()}".encode("ascii")
    ).hexdigest()[:16]
    mini = ConstantPool(random.Random(opts.seed), build_id=build_id)
    built = mini.build(slices=2)
    stats = {
        "input_bytes": len(data),
        "output_bytes": len(output),
        "expansion": round(len(output) / max(1, len(data)), 2),
        "backend": "loom-original",
        "vm": True,
        "vm_nodes": 0,
        "vm_stream_bytes": 0,
        "vm_fallback": None,
        "nested_vm": False,
        "crypto": False,
        "anti_env": False,
        "anti_tamper": False,
        "stealth": False,
        "protection_level": PROTECTION_LEVELS.get(opts.preset, opts.preset),
        "source_map_nodes": 0,
        "source_map_constants": 0,
        "loom_original": True,
    }
    keys = {
        "backend": "loom-original",
        "seed": opts.seed,
        "build_id": build_id,
        "sha256": hashlib.sha256(output).hexdigest(),
    }
    return Result(
        output=output,
        build=built,
        keys=keys,
        stats=stats,
        source_map={"nodes": [], "constants": []},
        v4=None,
        stealth=None,
        crypto=None,
    )


def obfuscate(data: bytes, opts: Options, *, _v4_base_bytes: int | None = None) -> Result:
    """Obfuscate ``data``.

    ``loom_original`` builds short-circuit the V7 pipeline entirely; they are
    reproducible from the seed and never parse as V7 ciphertext. All other
    behaviour is unchanged.
    """
    if getattr(opts, "loom_original", False):
        return _obfuscate_loom_original(data, opts)
    # ``_v4_base_bytes`` is an internal measurement hook: when ``None``
    # (normal builds) the exact size of the same build with zero entropy
    # padding is measured first, so the v4 ``<=15%`` size gate is enforced
    # against the real per-seed/per-input base instead of a hardcoded
    # estimate. The measurement build passes ``0`` to terminate recursion.
    tree, source = A.parse(data)
    A.tag_tree(tree)

    rng = random.Random(opts.seed)
    names = Names(opts.seed)
    layout = make_layout(opts.seed, opts.preset)
    # The build id must be derived from the seed and input, not uuid4.  A
    # seeded build is byte-for-byte reproducible for differential tests.
    build_id = hashlib.sha256(
        f"{opts.seed}|{hashlib.sha256(data).hexdigest()}".encode("ascii")
    ).hexdigest()[:16]
    pool = ConstantPool(rng, build_id=build_id)

    renderer = Renderer()
    transform.install(renderer)
    flatten.install(renderer)

    ctx = Context(
        source=source, names=names, pool=pool, rng=rng, opts=opts, renderer=renderer
    )
    ctx.layout = layout
    ctx.crypto = None
    ctx.decl_map = {loc: names.new() for loc in A.decl_locations(tree)}

    vm_program = None
    vm_warning = None
    if opts.vm:
        # Unsupported runtime syntax is an explicit build error.  There is no
        # silent source-mode fallback that would leave unprotected syntax in a
        # production chunk.  Type-only declarations are recorded as no-ops.
        vm_program = vm.compile_program(tree, ctx)

    rendered = b""
    n_flat = 0
    if vm_program is None:
        n_flat = flatten.select_blocks(tree, ctx)
        rendered = renderer.render(tree["root"], ctx)

    # Locks are added last so they never shift an already-emitted pool index.
    idx_game = idx_place = idx_gameid = idx_pid = idx_gid = None
    if opts.place_id is not None or opts.game_id is not None:
        idx_game = pool.add_string("game")
        if opts.place_id is not None:
            idx_place = pool.add_string("PlaceId")
            idx_pid = pool.add_number(float(opts.place_id))
        if opts.game_id is not None:
            idx_gameid = pool.add_string("GameId")
            idx_gid = pool.add_number(float(opts.game_id))

    # Runtime helper strings are real pool constants too, so no plaintext
    # format patterns, weak-table key or error text survives in output.
    runtime_consts = {
        "split": pool.add_string("([^;]+)"),
        "rec": pool.add_string("(%d+),(%d+),(%d+)"),
        "true": pool.add_string("1"),
        "weak_k": pool.add_string("k"),
        "for_error": pool.add_string("'for' step is zero"),
    }

    # Unreferenced high-entropy pool entries are added after every real
    # constant and lock, so they cannot shift any emitted D(i) index.
    pool.add_padding(opts.blob_pad)
    slice_count = _next_prime(opts.pool_slices)
    if opts.vm:
        layout.tune_source_spread(pool.entries, data, slice_count)
    built = pool.build(
        slices=opts.pool_slices,
        stride=layout.slice_stride if opts.vm else None,
        shift=layout.slice_shift if opts.vm else None,
    )
    if opts.vm:
        names.prepare_runtime_groups(
            layout, built.slice_count,
            getattr(vm_program, "fragment_count", opts.vm_fragments),
        )
    # v4 core integrity + decoy traps + high-entropy markers. Computed from
    # the compiled program/pool/layout; the plan is consumed by vm.runtime.
    if opts.vm and opts.integrity:
        if _v4_base_bytes is None:
            # Exact zero-padding base for THIS (preset, seed, input). The VM
            # runtime dominates output size and varies ~2x across seeds, so a
            # hardcoded base estimate cannot enforce the size gate. One extra
            # render (no Luau execution) is cheap and keeps the build seeded-
            # reproducible: the measurement build passes 0 and does not recurse.
            key = _v4_base_key(data, opts)
            if key in _V4_BASE_CACHE:
                base_bytes = _V4_BASE_CACHE[key]
            else:
                # Exclude the fixed top banner from the V4 padding base so the
                # protected body stays byte-compatible with pre-banner builds.
                base_bytes = len(strip_banner(obfuscate(
                    data, replace(opts, entropy_budget=0), _v4_base_bytes=0
                ).output))
                if len(_V4_BASE_CACHE) >= _V4_BASE_CACHE_MAX:
                    _V4_BASE_CACHE.clear()
                _V4_BASE_CACHE[key] = base_bytes
        else:
            base_bytes = _v4_base_bytes
        ctx.v4 = prepare_v4(ctx, vm_program, built, layout, opts, base_bytes)
    else:
        ctx.v4 = None

    # V7 opt-in whitening. A dedicated RNG keeps the encryption material from
    # perturbing the existing seeded build. The plan binds every tag to the
    # private V4 integrity digest, so literals from another build fail HMAC.
    if opts.crypto:
        integrity = getattr(getattr(ctx, "v4", None), "integrity", None)
        digest = int(getattr(integrity, "global_digest", 0))
        aad_extra = f"{digest}|{built.expected_hash}".encode("ascii")
        payloads: list[tuple[str, int, bytes]] = []
        for sl in built.slices:
            payloads.append(("pool_blob", sl.index, sl.blob))
            payloads.append(("pool_key", sl.index, sl.key))
        if vm_program is not None:
            for frag in vm_program.fragments:
                payloads.append(("vm_blob", frag.index, frag.blob))
                payloads.append(("vm_key", frag.index, frag.key))
        crng = random.Random((int(opts.seed) ^ 0x56375721) & 0xFFFFFFFF)
        passphrase = CR.load_passphrase(opts.key_text, opts.key_file)
        ctx.crypto = CR.make_crypto_plan(
            passphrase,
            build_id=built.build_id,
            preset=opts.preset,
            seed=opts.seed,
            rng=crng,
            payloads=payloads,
            aad_extra=aad_extra,
        )
        if not CR.verify_plan(ctx.crypto):
            raise RuntimeError("V7 crypto plan failed build-time verification")

    # Normal builds ship exactly one VM runtime. The old nested/armor layer is
    # no longer used by any preset because its environment checks poisoned D()
    # in ordinary executors; the module remains for explicit experiments only.
    outer = None
    inner_program = vm_program

    extra_hash = None
    if opts.anti_tamper:
        extra_hash = hardening.fnv(built.blob + built.key, 0x9E3779B9)
    stealth_plan = getattr(getattr(ctx, "v4", None), "stealth", None)

    prelude = runtime.render_runtime(
        names,
        built,
        layout=layout,
        place_id=opts.place_id,
        game_id=opts.game_id,
        idx_game=idx_game,
        idx_place=idx_place,
        idx_gameid=idx_gameid,
        idx_pid=idx_pid,
        idx_gid=idx_gid,
        integrity=opts.integrity,
        anti_env=opts.anti_env,
        anti_tamper=opts.anti_tamper,
        extra_hash=extra_hash,
        extra_hash_seed=0x9E3779B9,
        runtime_consts=runtime_consts,
        vm=opts.vm,
        stealth_plan=stealth_plan,
        crypto_plan=ctx.crypto,
    )

    if vm_program is not None:
        inner_code = vm.runtime.render(
            inner_program, ctx, built, layout=layout,
            runtime_consts=runtime_consts
        )
        if outer is not None:
            body = (
                outer.prelude
                + f"local {outer.inner_fn} = function()\n"
                + inner_code
                + "\nend\n"
                + outer.tail
            ).encode("utf-8")
        else:
            body = inner_code.encode("utf-8")
    else:
        body = rendered
    chunk = prelude.encode("utf-8") + b"\n" + body
    chunk_text = randomize_fields(chunk.decode("utf-8"), layout.field_keys)
    wrapped, fmt = F.build_entry(chunk_text, ctx)
    raw = wrapped.encode("utf-8")
    minified = minify.minify(raw, one_line=opts.one_line).rstrip() + b"\n"
    # The required user banner is the very first line. The protected
    # `return`-based chunk follows on the next line.
    output = BANNER_BYTES + minified

    vm_hash = None
    if vm_program is not None:
        vm_hash = vm_program.hash_params.expected

    source_map = _build_source_map(
        data, opts, ctx, pool, vm_program, built, runtime_consts, layout, fmt
    )

    # With crypto on, the private key file records ciphertext material rather
    # than plaintext pool/stream bytes. The derived key is never written here;
    # only hashes and public statistics are kept.
    crypto = ctx.crypto
    if crypto is not None:
        pool_blob_literal = crypto.payload(
            "pool_blob", built.slices[0].index
        ).ciphertext_literal
        pool_key_hex = b"".join(
            crypto.payload("pool_key", sl.index).ciphertext
            for sl in built.slices
        ).hex()
        slice_literals = [
            crypto.payload("pool_blob", sl.index).ciphertext_literal
            for sl in built.slices
        ]
        stream_key_hex = (
            b"".join(
                crypto.payload("vm_key", frag.index).ciphertext
                for frag in vm_program.fragments
            ).hex() if vm_program else None
        )
        crypto_fields = {
            "crypto": True,
            "crypto_alg": crypto.alg,
            "crypto_key_source": crypto.key_source,
            "crypto_passphrase_sha256": crypto.passphrase_sha256,
            "crypto_key_sha256": hashlib.sha256(crypto.key).hexdigest(),
            "crypto_aad_extra_sha256": crypto.aad_extra_sha256,
            "crypto_bytes": crypto.encrypted_bytes,
            "crypto_payloads": len(crypto.payloads),
            "crypto_tag_ok": CR.verify_plan(crypto),
        }
    else:
        pool_blob_literal = built.blob_literal
        pool_key_hex = built.key.hex()
        slice_literals = [s.blob_literal for s in built.slices]
        stream_key_hex = vm_program.stream_key.hex() if vm_program else None
        crypto_fields = {
            "crypto": False,
            "crypto_alg": None,
            "crypto_key_source": None,
            "crypto_passphrase_sha256": None,
            "crypto_key_sha256": None,
            "crypto_aad_extra_sha256": None,
            "crypto_bytes": 0,
            "crypto_payloads": 0,
            "crypto_tag_ok": True,
        }

    keys = {
        "format": 3,
        "protection_level": PROTECTION_LEVELS.get(opts.preset, opts.preset),
        "build_id": built.build_id,
        "created": datetime.now(timezone.utc).isoformat(),
        "preset": opts.preset,
        "seed": opts.seed,
        "place_id": opts.place_id,
        "game_id": opts.game_id,
        "blob_literal": pool_blob_literal,
        "key_hex": pool_key_hex,
        "delta": built.delta,
        "gamma": built.gamma,
        "salt": built.salt,
        "expected_hash": built.expected_hash,
        "anti_tamper_hash": extra_hash,
        "constants": built.count,
        "vm": vm_program is not None,
        "vm_fallback_reason": vm_warning,
        "opcodes": vm_program.opcodes if vm_program else None,
        "stream_key_hex": stream_key_hex,
        "vm_hash": vm_hash,
        "nested_vm": outer is not None,
        "anti_env": opts.anti_env,
        "anti_tamper": opts.anti_tamper,
        "stealth": opts.stealth,
        "stealth_decoys": stealth_plan.count if stealth_plan else 0,
        **crypto_fields,
        "blob_pad": opts.blob_pad,
        "flatten_ratio": opts.flatten_ratio,
        "junk": opts.junk,
        "min_stmts": opts.min_stmts,
        "vm_decoy_words": vm_program.pad_words if vm_program else 0,
        "outer_decoy_chunks": outer.extra_chunks if outer else 0,
        "outer_decoy_meta": outer.extra_meta if outer else 0,
        "decoy_factor": outer.decoy_factor if outer else 0.0,
        "outer_key_hex": outer.outer_key.hex() if outer else None,
        "outer_hash": outer.outer_hash if outer else None,
        "combined_hash": outer.combined_hash if outer else None,
        "outer_meta_opcodes": outer.meta_opcodes if outer else None,
        "chunk_keys": outer.chunk_keys if outer else None,
        "chunk_count": outer.chunk_count if outer else None,
        "meta_count": outer.meta_count if outer else None,
        "outer_delta": outer.outer_delta if outer else None,
        "chunk_delta": outer.chunk_delta if outer else None,
        "rolling_seed": outer.rolling_seed if outer else None,
        "entry_layout": fmt.shape_id,
        "boot_layout": fmt.boot_id,
        "alias_count": fmt.aliases,
        "decoy_count": fmt.decoys,
        "pool_slices": built.slice_count,
        "slice_stride": built.slice_stride,
        "slice_shift": built.slice_shift,
        "slice_literals": slice_literals,
        "vm_fragments": getattr(vm_program, "fragment_count", 0) if vm_program else 0,
        "operand_stride": getattr(vm_program, "operand_stride", 0) if vm_program else 0,
        "operand_shift": getattr(vm_program, "operand_shift", 0) if vm_program else 0,
        "source_map_sha256": hashlib.sha256(
            json.dumps(source_map, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "output_sha256": hashlib.sha256(output).hexdigest(),
    }
    stats = {
        "input_bytes": len(data),
        "output_bytes": len(output),
        "expansion": round(len(output) / max(1, len(data)), 2),
        "constants": built.count,
        "flattened_blocks": n_flat,
        "declarations": len(ctx.decl_map),
        "vm": bool(vm_program),
        "vm_nodes": len(vm_program.nodes) if vm_program else 0,
        "vm_stream_bytes": len(vm_program.stream) if vm_program else 0,
        "vm_fallback": vm_warning,
        "nested_vm": outer is not None,
        "outer_stream_bytes": len(outer.outer_blob) if outer else 0,
        "outer_chunks": outer.chunk_count if outer else 0,
        "outer_meta_ops": outer.meta_count if outer else 0,
        "anti_env": opts.anti_env,
        "anti_tamper": opts.anti_tamper,
        "stealth": opts.stealth,
        "stealth_decoys": stealth_plan.count if stealth_plan else 0,
        "crypto": crypto_fields["crypto"],
        "crypto_alg": crypto_fields["crypto_alg"],
        "crypto_key_source": crypto_fields["crypto_key_source"],
        "crypto_bytes": crypto_fields["crypto_bytes"],
        "crypto_payloads": crypto_fields["crypto_payloads"],
        "crypto_tag_ok": crypto_fields["crypto_tag_ok"],
        "blob_pad_bytes": opts.blob_pad,
        "flatten_ratio": opts.flatten_ratio,
        "junk": opts.junk,
        "min_stmts": opts.min_stmts,
        "vm_decoy_words": vm_program.pad_words if vm_program else 0,
        "outer_decoy_chunks": outer.extra_chunks if outer else 0,
        "outer_decoy_meta": outer.extra_meta if outer else 0,
        "decoy_factor": outer.decoy_factor if outer else 0.0,
        "entry_layout": fmt.shape_id,
        "boot_layout": fmt.boot_id,
        "alias_count": fmt.aliases,
        "decoy_count": fmt.decoys,
        "protection_level": PROTECTION_LEVELS.get(opts.preset, opts.preset),
        "pool_slices": built.slice_count,
        "vm_fragments": getattr(vm_program, "fragment_count", 0) if vm_program else 0,
        "source_map_nodes": len(source_map["nodes"]),
        "source_map_constants": len(source_map["constants"]),
        "node_style": layout.node_style,
        "dispatch_style": layout.dispatch_style,
        "router_style": layout.router_style,
        "chunk_assembly": layout.chunk_assembly,
        "operand_mode": vm_program.operand_mode if vm_program else None,
        "word_order": vm_program.word_order if vm_program else None,
        "stream_order": vm_program.stream_order if vm_program else None,
    }
    return Result(
        output=output,
        build=built,
        keys=keys,
        stats=stats,
        source_map=source_map,
        v4=ctx.v4,
        stealth=getattr(getattr(ctx, "v4", None), "stealth", None),
        crypto=crypto,
    )


def validate_syntax(data: bytes) -> tuple[bool, str]:
    """Compile-only check with the official Luau compiler."""
    exe = A.tool_path("luau-compile")
    fd, path = tempfile.mkstemp(suffix=".luau")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        p = subprocess.run(
            [exe, "--only-parse", path], capture_output=True, timeout=A.tool_timeout()
        )
        msg = (p.stdout + p.stderr).decode("utf-8", "replace")
        return p.returncode == 0, msg.strip()
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def identify_bytes(data: bytes, keys: dict) -> dict:
    """Provenance check without touching the filesystem (used by the web API)."""
    blob = keys.get("blob_literal", "").encode("utf-8")
    sha = hashlib.sha256(data).hexdigest()
    return {
        "build_id": keys.get("build_id"),
        "created": keys.get("created"),
        "preset": keys.get("preset"),
        "vm": keys.get("vm"),
        "blob_present": bool(blob) and blob in data,
        "exact_file": sha == keys.get("output_sha256"),
        "tampered": sha != keys.get("output_sha256"),
        "file_sha256": sha,
    }


def identify(path: str, keys_path: str) -> dict:
    with open(path, "rb") as f:
        data = f.read()
    with open(keys_path, "r", encoding="utf-8") as f:
        keys = json.load(f)
    return identify_bytes(data, keys)
