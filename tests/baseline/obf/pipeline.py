"""Orchestration: parse -> analyse -> rewrite -> pack -> verify."""
from __future__ import annotations

import hashlib
import json
import os
import random
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import ast as A
from . import flatten, format as F, hardening, minify, runtime, transform, vm
from .names import Names
from .pool import ConstantPool, PoolBuild
from .render import Context, Options, Renderer

# Prepended verbatim after minification so it is always the first line of the
# delivered file (CLI, examples, and web API alike).
BRAND_COMMENT = b'-- obfuscated by grandfuscate (discord "grand6_7")\n'


@dataclass
class Result:
    output: bytes
    build: PoolBuild
    keys: dict
    stats: dict = field(default_factory=dict)
    # Private debug/source map.  It is returned to the caller but never
    # serialized into the production .luau chunk.
    source_map: dict = field(default_factory=dict)


PRESETS: dict[str, dict] = {
    "light": dict(
        vm=True, virtualize_globals=True, virtualize_properties=False,
        encrypt_constants=True, flatten=False, junk=0, flatten_ratio=0.0,
        min_stmts=3, integrity=True, anti_env=False, anti_tamper=False,
        nested_vm=False, blob_pad=0, pool_slices=2, vm_fragments=2,
    ),
    "medium": dict(
        vm=True, virtualize_globals=True, virtualize_properties=True,
        encrypt_constants=True, flatten=True, junk=2, flatten_ratio=0.75,
        min_stmts=3, integrity=True, anti_env=False, anti_tamper=False,
        nested_vm=False, blob_pad=4096, pool_slices=3, vm_fragments=4,
    ),
    "heavy": dict(
        vm=True, virtualize_globals=True, virtualize_properties=True,
        encrypt_constants=True, flatten=True, junk=8, flatten_ratio=1.0,
        min_stmts=1, integrity=True, anti_env=False, anti_tamper=False,
        nested_vm=False, blob_pad=65536, pool_slices=5, vm_fragments=7,
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
        "pool_slices": built.slice_count,
        "slice_stride": built.slice_stride,
        "slice_shift": built.slice_shift,
        "runtime_consts": runtime_consts,
    }


def obfuscate(data: bytes, opts: Options) -> Result:
    tree, source = A.parse(data)
    A.tag_tree(tree)

    rng = random.Random(opts.seed)
    names = Names(opts.seed)
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
    ctx.decl_map = {loc: names.new() for loc in A.decl_locations(tree)}

    vm_program = None
    vm_warning = None
    if opts.vm:
        try:
            vm_program = vm.compile_program(tree, ctx)
        except vm.Unsupported as exc:
            vm_warning = str(exc)

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
    built = pool.build(slices=opts.pool_slices)

    # Normal builds ship exactly one VM runtime. The old nested/armor layer is
    # no longer used by any preset because its environment checks poisoned D()
    # in ordinary executors; the module remains for explicit experiments only.
    outer = None
    inner_program = vm_program

    extra_hash = None
    if opts.anti_tamper:
        extra_hash = hardening.fnv(built.blob + built.key, 0x9E3779B9)

    prelude = runtime.render_runtime(
        names,
        built,
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
    )

    if vm_program is not None:
        inner_code = vm.runtime.render(
            inner_program, ctx, built, runtime_consts=runtime_consts
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
    wrapped, fmt = F.build_entry(chunk.decode("utf-8"), ctx)
    raw = wrapped.encode("utf-8")
    minified = minify.minify(raw, one_line=opts.one_line).rstrip() + b"\n"
    output = BRAND_COMMENT + minified

    vm_hash = None
    if vm_program is not None:
        vm_hash = vm.runtime.fnv(
            vm_program.stream + vm_program.stream_key + built.blob + built.key
        )

    source_map = _build_source_map(
        data, opts, ctx, pool, vm_program, built, runtime_consts
    )

    keys = {
        "format": 3,
        "protection_level": PROTECTION_LEVELS.get(opts.preset, opts.preset),
        "build_id": built.build_id,
        "created": datetime.now(timezone.utc).isoformat(),
        "preset": opts.preset,
        "seed": opts.seed,
        "place_id": opts.place_id,
        "game_id": opts.game_id,
        "blob_literal": built.blob_literal,
        "key_hex": built.key.hex(),
        "delta": built.delta,
        "gamma": built.gamma,
        "salt": built.salt,
        "expected_hash": built.expected_hash,
        "anti_tamper_hash": extra_hash,
        "constants": built.count,
        "vm": vm_program is not None,
        "vm_fallback_reason": vm_warning,
        "opcodes": vm_program.opcodes if vm_program else None,
        "stream_key_hex": vm_program.stream_key.hex() if vm_program else None,
        "vm_hash": vm_hash,
        "nested_vm": outer is not None,
        "anti_env": opts.anti_env,
        "anti_tamper": opts.anti_tamper,
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
        "entry_shape": fmt.shape,
        "format_boot": fmt.boot_style,
        "format_aliases": fmt.aliases,
        "format_decoys": fmt.decoys,
        "pool_slices": built.slice_count,
        "slice_stride": built.slice_stride,
        "slice_shift": built.slice_shift,
        "slice_literals": [s.blob_literal for s in built.slices],
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
        "blob_pad_bytes": opts.blob_pad,
        "flatten_ratio": opts.flatten_ratio,
        "junk": opts.junk,
        "min_stmts": opts.min_stmts,
        "vm_decoy_words": vm_program.pad_words if vm_program else 0,
        "outer_decoy_chunks": outer.extra_chunks if outer else 0,
        "outer_decoy_meta": outer.extra_meta if outer else 0,
        "decoy_factor": outer.decoy_factor if outer else 0.0,
        "entry_shape": fmt.shape,
        "format_boot": fmt.boot_style,
        "format_aliases": fmt.aliases,
        "format_decoys": fmt.decoys,
        "protection_level": PROTECTION_LEVELS.get(opts.preset, opts.preset),
        "pool_slices": built.slice_count,
        "vm_fragments": getattr(vm_program, "fragment_count", 0) if vm_program else 0,
        "source_map_nodes": len(source_map["nodes"]),
        "source_map_constants": len(source_map["constants"]),
    }
    return Result(
        output=output,
        build=built,
        keys=keys,
        stats=stats,
        source_map=source_map,
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
