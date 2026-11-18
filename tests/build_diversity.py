"""Generate and verify five structurally different production builds."""
from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from obf import minify, pipeline  # noqa: E402
from tests import anti_analysis as AA  # noqa: E402
from tests.return_probe import run as run_with_returns  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BUILD_DIR = os.path.join(HERE, "builds")
SOURCE = os.path.join(HERE, "cases", "print67.luau")
MANIFEST = os.path.join(BUILD_DIR, "manifest.json")


def _features(r) -> dict:
    layout = r.source_map["runtime_layout"]
    operand = r.source_map["operand"] or {}
    return {
        "entry_layout": r.source_map["entry_layout"],
        "boot_layout": r.source_map["boot_layout"],
        "node_style": layout["node_style"],
        "dispatch_style": layout["dispatch_style"],
        "router_style": layout["router_style"],
        "chunk_assembly": layout["chunk_assembly"],
        "slot_base": layout["slot_base"],
        "const_span": layout["const_span"],
        "const_bias": layout["const_bias"],
        "vm_profile": layout["vm_profile"],
        "bank_count": layout["bank_count"],
        "constant_groups": layout["constant_groups"],
        "byte_groups": layout["byte_groups"],
        "word_groups": layout["word_groups"],
        "node_groups": layout["node_groups"],
        "handler_groups": layout["handler_groups"],
        "per_node_c": layout["per_node_operand_c"],
        "per_node_d": layout["per_node_operand_d"],
        "structural_digest": r.source_map["third_pass"]["structural_digest"],
        "operand_mode": operand.get("mode"),
        "word_order": operand.get("word_order"),
        "stream_order": operand.get("stream_order"),
    }


def _choose_seeds(count: int = 5) -> list[int]:
    candidates: dict[int, tuple] = {}
    for seed in range(1, 161):
        r = pipeline.obfuscate(
            open(SOURCE, "rb").read(), pipeline.make_options("medium", seed=seed)
        )
        candidates[seed] = tuple(_features(r).values())
    chosen: list[int] = []
    covered: set[tuple[int, object]] = set()
    while len(chosen) < count:
        best = None
        best_score = -1
        for seed, vals in candidates.items():
            if seed in chosen:
                continue
            score = sum((i, v) not in covered for i, v in enumerate(vals))
            # Prefer earlier seeds on ties for determinism.
            if score > best_score:
                best, best_score = seed, score
        if best is None:
            break
        chosen.append(best)
        covered.update((i, v) for i, v in enumerate(candidates[best]))
    return chosen


def _token_stats(data: bytes) -> dict:
    toks = [t for t in minify.tokenize(data) if t.kind not in ("ws", "comment")]
    prefix = "|".join(t.kind for t in toks[:96]).encode("ascii")
    strings = [len(t.text) for t in toks if t.kind == "string"]
    return {
        "token_prefix_sha256": hashlib.sha256(prefix).hexdigest()[:16],
        "token_count": len(toks),
        "string_tokens": len(strings),
        "largest_string_token": max(strings, default=0),
    }


def generate() -> dict:
    os.makedirs(BUILD_DIR, exist_ok=True)
    source = open(SOURCE, "rb").read()
    rc0, out0, err0 = run_with_returns(source)
    if rc0 != 0 or err0:
        raise RuntimeError(f"original return probe failed: {err0!r}")
    seeds = _choose_seeds()
    builds = []
    for index, seed in enumerate(seeds, 1):
        r = pipeline.obfuscate(source, pipeline.make_options("medium", seed=seed))
        ok, msg = pipeline.validate_syntax(r.output)
        if not ok:
            raise RuntimeError(f"build {seed} syntax failed: {msg}")
        rc, out, err = run_with_returns(r.output)
        findings = AA.scan_output(source, r.output, r.keys, r.source_map)
        payload = json.dumps(
            [r.source_map["pool_chunk_plans"], r.source_map["vm_chunk_plans"]],
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        path = os.path.join(BUILD_DIR, f"build_{index:02d}.luau")
        with open(path, "wb") as f:
            f.write(r.output)
        builds.append({
            "file": os.path.relpath(path, ROOT),
            "seed": seed,
            "bytes": len(r.output),
            "sha256": hashlib.sha256(r.output).hexdigest(),
            "preset": r.keys["preset"],
            "protection_level": r.keys["protection_level"],
            "layout": _features(r),
            "opcodes_sha256": hashlib.sha256(
                json.dumps(r.source_map["opcodes"], sort_keys=True).encode("ascii")
            ).hexdigest()[:16],
            "payload_digest_sha256": hashlib.sha256(payload).hexdigest()[:16],
            "structural_digest": r.source_map["third_pass"]["structural_digest"],
            "pool_chunk_plans": r.source_map["pool_chunk_plans"],
            "vm_chunk_plans": r.source_map["vm_chunk_plans"],
            "control_flow": r.source_map["control_flow"],
            "token_stats": _token_stats(r.output),
            "scanner_findings": findings,
            "syntax": ok,
            "behaviour": {
                "rc": rc,
                "stdout_sha256": hashlib.sha256(out).hexdigest(),
                "stderr": err.decode("utf-8", "replace"),
                "same_as_original": (rc, out, err) == (rc0, out0, err0),
            },
        })
    manifest = {
        "marker": "GRANDFUSCATE_FIVE_BUILD_DIVERSITY_V2",
        "created": datetime.now(timezone.utc).isoformat(),
        "source": os.path.relpath(SOURCE, ROOT),
        "source_sha256": hashlib.sha256(source).hexdigest(),
        "original_behaviour": {
            "rc": rc0,
            "stdout_sha256": hashlib.sha256(out0).hexdigest(),
            "stderr": err0.decode("utf-8", "replace"),
        },
        "preset": "medium",
        "seeds": seeds,
        "builds": builds,
        "diversity": {
            "outputs": len({b["sha256"] for b in builds}),
            "entry_layouts": sorted({b["layout"]["entry_layout"] for b in builds}),
            "boot_layouts": sorted({b["layout"]["boot_layout"] for b in builds}),
            "node_styles": sorted({b["layout"]["node_style"] for b in builds}),
            "dispatch_styles": sorted({b["layout"]["dispatch_style"] for b in builds}),
            "router_styles": sorted({b["layout"]["router_style"] for b in builds}),
            "chunk_assemblies": sorted({b["layout"]["chunk_assembly"] for b in builds}),
            "slot_bases": sorted({b["layout"]["slot_base"] for b in builds}),
            "const_spans": sorted({b["layout"]["const_span"] for b in builds}),
            "const_biases": sorted({b["layout"]["const_bias"] for b in builds}),
            "operand_modes": sorted({b["layout"]["operand_mode"] for b in builds}),
            "word_orders": sorted({b["layout"]["word_order"] for b in builds}),
            "stream_orders": sorted({b["layout"]["stream_order"] for b in builds}),
            "opcode_maps": len({b["opcodes_sha256"] for b in builds}),
            "payload_digests": len({b["payload_digest_sha256"] for b in builds}),
            "vm_profiles": sorted({b["layout"]["vm_profile"] for b in builds}),
            "bank_counts": sorted({b["layout"]["bank_count"] for b in builds}),
            "group_signatures": len({
                (
                    b["layout"]["constant_groups"],
                    b["layout"]["byte_groups"],
                    b["layout"]["word_groups"],
                    b["layout"]["node_groups"],
                    b["layout"]["handler_groups"],
                )
                for b in builds
            }),
            "structural_digests": len({b["structural_digest"] for b in builds}),
            "token_prefixes": len({b["token_stats"]["token_prefix_sha256"] for b in builds}),
        },
    }
    with open(MANIFEST, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
    return manifest


def verify() -> tuple[bool, list[str]]:
    if not os.path.isfile(MANIFEST):
        generate()
    with open(MANIFEST, encoding="utf-8") as f:
        m = json.load(f)
    bad: list[str] = []
    source = open(SOURCE, "rb").read()
    rc0, out0, err0 = run_with_returns(source)
    if m.get("marker") != "GRANDFUSCATE_FIVE_BUILD_DIVERSITY_V2":
        bad.append("wrong manifest marker")
    if len(m.get("builds", [])) != 5:
        bad.append("manifest does not contain five builds")
    d = m.get("diversity", {})
    for key, needed in (
        ("outputs", 5), ("entry_layouts", 3), ("boot_layouts", 2),
        ("node_styles", 3), ("dispatch_styles", 3), ("router_styles", 3),
        ("chunk_assemblies", 2), ("slot_bases", 5), ("const_spans", 2),
        ("const_biases", 2), ("operand_modes", 3), ("word_orders", 2),
        ("stream_orders", 2), ("opcode_maps", 5), ("payload_digests", 5),
        ("vm_profiles", 2), ("bank_counts", 2), ("group_signatures", 5),
        ("structural_digests", 5), ("token_prefixes", 5),
    ):
        got = d.get(key)
        n = len(got) if isinstance(got, list) else got
        if not isinstance(n, int) or n < needed:
            bad.append(f"diversity/{key}: {n} < {needed}")
    for b in m.get("builds", []):
        path = os.path.join(ROOT, b["file"])
        if not os.path.isfile(path):
            bad.append(f"missing build file {b['file']}")
            continue
        data = open(path, "rb").read()
        if hashlib.sha256(data).hexdigest() != b["sha256"]:
            bad.append(f"build hash mismatch {b['file']}")
        if not data.startswith(b"return"):
            bad.append(f"build does not start with return: {b['file']}")
        if any(t.kind == "comment" for t in minify.tokenize(data)):
            bad.append(f"build contains a comment: {b['file']}")
        ok, msg = pipeline.validate_syntax(data)
        if not ok:
            bad.append(f"build syntax failed: {b['file']}: {msg[:100]}")
        rc, out, err = run_with_returns(data)
        if (rc, out, err) != (rc0, out0, err0):
            bad.append(f"build behaviour differs: {b['file']}")
        # Scanner needs keys/source_map; regenerate deterministically from seed.
        r = pipeline.obfuscate(source, pipeline.make_options("medium", seed=b["seed"]))
        findings = AA.scan_output(source, data, r.keys, r.source_map)
        if findings:
            bad.append(f"build scanner findings: {b['file']}: {findings[:3]}")
    return not bad, bad
