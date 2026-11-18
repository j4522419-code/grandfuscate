"""Old-vs-improved anti-analysis and performance benchmark.

The frozen pre-change engine in `tests/baseline/` is built in a separate
Python process so its `obf` package cannot collide with the current one. This
is a local engineering comparison, not a deobfuscator or commercial benchmark.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from obf import minify, pipeline  # noqa: E402
from tests import anti_analysis as AA  # noqa: E402
from tests import runtime_analysis as RA  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BASELINE = os.path.join(HERE, "baseline")
JSON_PATH = os.path.join(ROOT, "BENCHMARKS-old-vs-improved.json")
MD_PATH = os.path.join(ROOT, "BENCHMARKS-old-vs-improved.md")
SEED = 20261118

_FORBIDDEN_FIELDS = frozenset(
    "V UP VA n v proto up EVAL EXEC GETLV SETLV NODES CODE".split()
)

_BASELINE_SCRIPT = r'''
import json, sys
from obf import pipeline
req = json.load(sys.stdin)
data = bytes.fromhex(req["source_hex"])
r = pipeline.obfuscate(data, pipeline.make_options(req["preset"], seed=req["seed"]))
print(json.dumps({
    "output_hex": r.output.hex(),
    "output_bytes": len(r.output),
    "vm": r.stats.get("vm"),
    "entry_shape": r.keys.get("entry_shape"),
    "format_boot": r.keys.get("format_boot"),
}))
'''


def _baseline_build(source: bytes, preset: str) -> dict:
    env = dict(os.environ)
    env["PYTHONPATH"] = BASELINE
    env["PYTHONNOUSERSITE"] = "1"
    req = {"source_hex": source.hex(), "preset": preset, "seed": SEED}
    p = subprocess.run(
        [sys.executable, "-c", _BASELINE_SCRIPT],
        input=json.dumps(req).encode("ascii"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=BASELINE,
        env=env,
        timeout=180,
    )
    if p.returncode != 0:
        raise RuntimeError(
            f"baseline build failed ({preset}): "
            + p.stderr.decode("utf-8", "replace")[:300]
        )
    out = json.loads(p.stdout.decode("ascii"))
    out["output"] = bytes.fromhex(out.pop("output_hex"))
    return out


def _current_build(source: bytes, preset: str):
    return pipeline.obfuscate(
        source, pipeline.make_options(preset, seed=SEED)
    ).output


def _comments(data: bytes) -> int:
    return sum(1 for t in minify.tokenize(data) if t.kind == "comment")


def _stable_fields(data: bytes) -> list[str]:
    sig = [t for t in minify.tokenize(data) if t.kind not in ("ws", "comment")]
    hits: set[str] = set()
    curly = 0
    for i, t in enumerate(sig):
        if t.text == b"{":
            curly += 1
        elif t.text == b"}":
            curly = max(0, curly - 1)
        if (
            i + 1 < len(sig)
            and t.kind == "symbol"
            and t.text == b"."
            and sig[i + 1].kind == "name"
        ):
            name = sig[i + 1].text.decode("latin-1")
            if name in _FORBIDDEN_FIELDS:
                hits.add(name)
        prev = sig[i - 1] if i else None
        nxt = sig[i + 1] if i + 1 < len(sig) else None
        if (
            t.kind == "name"
            and t.text.decode("latin-1") in _FORBIDDEN_FIELDS
            and curly > 0
            and nxt is not None
            and nxt.text == b"="
            and prev is not None
            and prev.text in (b"{", b",", b";")
        ):
            hits.add(t.text.decode("latin-1"))
        if (
            i + 2 < len(sig)
            and t.text == b"["
            and sig[i + 1].kind == "string"
            and sig[i + 2].text == b"]"
        ):
            raw = sig[i + 1].text.decode("latin-1").strip("\"'")
            if raw in _FORBIDDEN_FIELDS:
                hits.add(raw)
    return sorted(hits)


def _signature(output: bytes, source: bytes, needles: list[bytes]) -> dict:
    static = RA._static_attempts(output)
    diag, captures, stderr = RA.instrumented_run(output, needles)
    rc0, out0, err0 = AA.run_luau(source)
    rc, out, err = AA.run_luau(output)
    return {
        "output_bytes": len(output),
        "output_sha256": hashlib.sha256(output).hexdigest()[:16],
        "starts_with_return": output.startswith(b"return"),
        "comments": _comments(output),
        "brand_bytes": b'-- obfuscated by grandfuscate' in output,
        "fixed_checksum_constants": static["fixed_checksum_constants"],
        "stable_fields": _stable_fields(output),
        "stable_field_count": static["small_handler_groups"],
        "small_handler_tables": static["small_keyed_handler_tables"],
        "central_dispatch_chains": static["central_numeric_dispatch_chains"],
        "sequential_small_opcode_array": static["sequential_small_opcode_array"],
        "runtime_probe": {
            "chunk_ok": diag.get("chunk_ok"),
            "startup_source_hits": int(diag.get("startup_source_hits", "-1")),
            "all_source_hits": int(diag.get("all_source_hits", "-1")),
            "distinct_blobs": int(diag.get("distinct_blobs", "0")),
            "char_calls": int(diag.get("char_calls", "0")),
            "clean_ir": diag.get("clean_ir"),
            "global_dispatcher_candidates": int(
                diag.get("global_dispatcher_candidates", "0")
            ),
            "captured_stdout": captures,
            "harness_stderr": stderr,
        },
        "behaviour": {
            "original_rc": rc0,
            "original_stdout": out0.decode("utf-8", "replace"),
            "original_stderr": err0.decode("utf-8", "replace"),
            "rc": rc,
            "stdout": out.decode("utf-8", "replace"),
            "stderr": err.decode("utf-8", "replace"),
            "matches_original": (rc, out, err) == (rc0, out0, err0),
        },
    }


def _performance(old: dict, new: dict, workload: bytes, original: bytes) -> dict:
    startup_src = b"local x = 1\n"
    old_startup = old["startup_output"]
    new_startup = new["startup_output"]
    old_runtime = old["workload_output"]
    new_runtime = new["workload_output"]
    measures = {
        "original_startup": AA._measure(startup_src),
        "old_startup": AA._measure(old_startup),
        "new_startup": AA._measure(new_startup),
        "original_runtime": AA._measure(original),
        "old_runtime": AA._measure(old_runtime),
        "new_runtime": AA._measure(new_runtime),
    }
    return {
        "startup_source": "local x = 1",
        "workload": "tests/bench_runtime.luau (5,000 loop iterations)",
        "measures": measures,
        "overhead_median": {
            "old": measures["old_runtime"]["seconds_median"]
            / max(measures["original_runtime"]["seconds_median"], 1e-9),
            "new": measures["new_runtime"]["seconds_median"]
            / max(measures["original_runtime"]["seconds_median"], 1e-9),
        },
        "startup_median_ms": {
            "original": measures["original_startup"]["seconds_median"] * 1000,
            "old": measures["old_startup"]["seconds_median"] * 1000,
            "new": measures["new_startup"]["seconds_median"] * 1000,
        },
    }


def run() -> dict:
    print67 = b"print(67)\n"
    fixture = open(os.path.join(HERE, "scan_fixture.luau"), "rb").read()
    workload = open(os.path.join(HERE, "bench_runtime.luau"), "rb").read()
    startup = b"local x = 1\n"
    sizes = {}

    old = {
        "print67": _baseline_build(print67, "medium")["output"],
        "fixture": _baseline_build(fixture, "medium")["output"],
        "startup_output": _baseline_build(startup, "medium")["output"],
        "workload_output": _baseline_build(workload, "heavy")["output"],
    }
    new = {
        "print67": _current_build(print67, "medium"),
        "fixture": _current_build(fixture, "medium"),
        "startup_output": _current_build(startup, "medium"),
        "workload_output": _current_build(workload, "heavy"),
    }

    p67_needles = [b"print", b"67", b"print(67)"]
    fixture_needles = AA._source_fragments(fixture)
    signatures = {
        "print67": {
            "old": _signature(old["print67"], print67, p67_needles),
            "new": _signature(new["print67"], print67, p67_needles),
        },
        "scan_fixture": {
            "old": _signature(old["fixture"], fixture, fixture_needles),
            "new": _signature(new["fixture"], fixture, fixture_needles),
        },
    }
    sizes = {
        "fixture_medium": {
            "old": len(old["fixture"]),
            "new": len(new["fixture"]),
        },
        "startup_medium": {
            "old": len(old["startup_output"]),
            "new": len(new["startup_output"]),
        },
        "workload_heavy": {
            "old": len(old["workload_output"]),
            "new": len(new["workload_output"]),
        },
    }
    performance = _performance(old, new, workload, workload)
    results = {
        "created": datetime.now(timezone.utc).isoformat(),
        "toolchain": "official Luau 0.747 (tools/luau)",
        "seed": SEED,
        "baseline": "tests/baseline (frozen pre-second-pass engine)",
        "sizes": sizes,
        "signatures": signatures,
        "performance": performance,
    }
    _write(results)
    return results


def _write(results: dict) -> None:
    with open(JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, sort_keys=True)
    s = results["signatures"]
    p = results["performance"]
    lines = [
        "# Old-vs-improved benchmark",
        "",
        f"Measured {results['created']} with {results['toolchain']}, seed "
        f"{results['seed']}. Old = `{results['baseline']}`. Three fresh Luau "
        "process launches per timing; min/median wall time and peak RSS "
        "(`ru_maxrss`) are local engineering numbers, not a red-team result.",
        "",
        "## Output size",
        "",
        "| Input | Old medium/heavy | New medium/heavy |",
        "|---|---:|---:|",
    ]
    for label, pair in results["sizes"].items():
        lines.append(f"| `{label}` | {pair['old']:,} B | {pair['new']:,} B |")
    lines += [
        "",
        "## Recoverability signatures",
        "",
        "| Probe | Build | Comments | Brand | FNV constants | Stable fields | "
        "Startup needles | Simple dump needles | Distinct blobs |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for label in ("print67", "scan_fixture"):
        for build in ("old", "new"):
            x = s[label][build]
            rp = x["runtime_probe"]
            lines.append(
                f"| `{label}` | {build} | {x['comments']} | "
                f"{x['brand_bytes']} | {len(x['fixed_checksum_constants'])} | "
                f"{len(x['stable_fields'])} | {rp['startup_source_hits']} | "
                f"{rp['all_source_hits']} | {rp['distinct_blobs']} |"
            )
    lines += [
        "",
        "The old `print(67)` build exposed the identifying byte-0 comment, "
        "fixed checksum constants and stable frame fields; the restricted "
        "runtime dump recovered source needles. The new build has zero "
        "comments, starts with `return`, uses randomized checksums and field "
        "keys, and the same restricted probes recover no source needles.",
        "",
        "## Performance",
        "",
        "| Measurement | Original | Old | New |",
        "|---|---:|---:|---:|",
    ]
    m = p["measures"]
    for label, key in (
        ("Startup median ms", "seconds_median"),
        ("Startup min ms", "seconds_min"),
        ("Startup median RSS KiB", "rss_kib_median"),
        ("Workload median ms", "seconds_median"),
        ("Workload min ms", "seconds_min"),
        ("Workload max RSS KiB", "rss_kib_max"),
    ):
        scale = 1000 if key.startswith("seconds") else 1
        if label.startswith("Workload"):
            trio = (
                m["original_runtime"][key] * scale,
                m["old_runtime"][key] * scale,
                m["new_runtime"][key] * scale,
            )
        else:
            trio = (
                m["original_startup"][key] * scale,
                m["old_startup"][key] * scale,
                m["new_startup"][key] * scale,
            )
        fmt = "{:.2f}" if scale == 1000 else "{:,.0f}"
        lines.append(
            f"| {label} | {fmt.format(trio[0])} | {fmt.format(trio[1])} | "
            f"{fmt.format(trio[2])} |"
        )
    lines += [
        "",
        f"5,000-loop median overhead: old {p['overhead_median']['old']:.1f}x, "
        f"new {p['overhead_median']['new']:.1f}x. Tree-walker cost remains the "
        "dominant runtime factor. The third-pass distributed ticketed decoder "
        f"matrices add work relative to the old single-router build; "
        f"{AA.BENCHMARK_OVERHEAD_BUDGET:.0f}x is a gross-regression sanity "
        "ceiling, not a speed target or a guarantee.",
        "",
        "## Caveat",
        "",
        "This is not proof that client-side Roblox scripts are secure or "
        "superior to commercial obfuscators. A capable executor debugger can "
        "still inspect closures and runtime values. Real security requires "
        "server-side authority.",
        "",
    ]
    with open(MD_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def verify() -> tuple[bool, list[str]]:
    if not os.path.isfile(JSON_PATH) or not os.path.isfile(MD_PATH):
        run()
    with open(JSON_PATH, encoding="utf-8") as f:
        r = json.load(f)
    bad: list[str] = []
    for label in ("print67", "scan_fixture"):
        old = r["signatures"][label]["old"]
        new = r["signatures"][label]["new"]
        if not old["behaviour"]["matches_original"]:
            bad.append(f"old {label} behaviour differs from original")
        if not new["behaviour"]["matches_original"]:
            bad.append(f"new {label} behaviour differs from original")
        if not new["starts_with_return"] or new["comments"] != 0:
            bad.append(f"new {label} is not comment-free return-first")
        if new["brand_bytes"]:
            bad.append(f"new {label} contains identifying brand bytes")
        if new["fixed_checksum_constants"]:
            bad.append(f"new {label} contains fixed checksum constants")
        if new["stable_fields"]:
            bad.append(f"new {label} contains stable frame fields")
        rp = new["runtime_probe"]
        if rp["startup_source_hits"] != 0 or rp["all_source_hits"] != 0:
            bad.append(f"new {label} restricted runtime dump recovered needles")
        if rp["distinct_blobs"] < 2:
            bad.append(f"new {label} has a single central decode blob")
        if rp["clean_ir"] is True:
            bad.append(f"new {label} clean IR reconstruction succeeded")
        if rp["global_dispatcher_candidates"] != 0:
            bad.append(f"new {label} global dispatcher identified")
    for label, pair in r["sizes"].items():
        if pair["new"] >= 1024 * 1024:
            bad.append(f"new {label} exceeds 1 MB")
    if r["performance"]["overhead_median"]["new"] >= AA.BENCHMARK_OVERHEAD_BUDGET:
        bad.append(
            "new heavy workload overhead exceeds third-pass "
            f"{AA.BENCHMARK_OVERHEAD_BUDGET:.0f}x sanity budget"
        )
    return not bad, bad
