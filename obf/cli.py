"""Command line entry point:  python3 -m obf.cli ..."""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import pipeline


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="luau-obf",
        description="AST-based Luau obfuscator (protects source you own).",
    )
    p.add_argument("input", nargs="?", help="input .luau file")
    p.add_argument("-o", "--output", help="output file (default: <input>.obf.luau)")
    p.add_argument(
        "--preset",
        type=lambda s: pipeline.PRESET_ALIASES.get(s, s),
        choices=list(pipeline.PRESETS),
        default="medium",
        help="light, medium or heavy (aliases: balanced, aggressive, max)",
    )
    p.add_argument("--seed", type=int, default=None, help="build seed (random if omitted)")
    p.add_argument("--keys", help="write the build's private key file here")
    p.add_argument(
        "--source-map",
        help="write the private debug/source map here (never embedded in output)",
    )
    p.add_argument("--place-id", type=int, help="lock output to a Roblox PlaceId")
    p.add_argument("--game-id", type=int, help="lock output to a Roblox GameId / UniverseId")
    p.add_argument("--verify", action="store_true", help="compile-check output with luau-compile")
    p.add_argument(
        "--stealth", "--fail-closed", dest="stealth", action="store_true",
        help="opt-in V5 active decoys: fail-closed / poison reactions (off by default)",
    )
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--identify", metavar="FILE", help="report provenance for an output file")
    p.add_argument("--self-test", action="store_true", help="run the behaviour test suite")
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.self_test:
        from tests import run_tests  # type: ignore
        return run_tests.main()

    if a.identify:
        if not a.keys:
            print("error: --identify needs --keys <file>", file=sys.stderr)
            return 2
        print(json.dumps(pipeline.identify(a.identify, a.keys), indent=2))
        return 0

    if not a.input:
        print("error: an input .luau file is required (or --self-test / --identify)", file=sys.stderr)
        return 2
    with open(a.input, "rb") as f:
        data = f.read()

    seed = a.seed
    if seed is None:
        seed = int.from_bytes(os.urandom(8), "big") & 0x7FFFFFFFFFFFFFFF

    # One normal VM runtime. Presets control intensity; hardening flags that
    # poisoned ordinary executors are never turned on here.
    overrides: dict = {
        "seed": seed,
        "one_line": True,
        "vm": True,
        "nested_vm": False,
        "anti_env": False,
        "anti_tamper": False,
        "stealth": bool(a.stealth),
    }
    if a.place_id is not None:
        overrides["place_id"] = a.place_id
    if a.game_id is not None:
        overrides["game_id"] = a.game_id

    opts = pipeline.make_options(a.preset, **overrides)
    try:
        result = pipeline.obfuscate(data, opts)
    except pipeline.A.ParseError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except pipeline.A.ToolMissing as exc:
        print(str(exc), file=sys.stderr)
        return 2

    out_path = a.output or (os.path.splitext(a.input)[0] + ".obf.luau")
    with open(out_path, "wb") as f:
        f.write(result.output)
    if a.keys:
        with open(a.keys, "w", encoding="utf-8") as f:
            json.dump(result.keys, f, indent=2)
    if a.source_map:
        with open(a.source_map, "w", encoding="utf-8") as f:
            json.dump(result.source_map, f, indent=2)

    ok, msg = True, ""
    if a.verify:
        ok, msg = pipeline.validate_syntax(result.output)

    if not a.quiet:
        s = result.stats
        print(f"preset        : {opts.preset}")
        print(f"build id      : {result.keys['build_id']}")
        print(f"input         : {s['input_bytes']} B")
        print(f"output        : {s['output_bytes']} B  ({s['expansion']}x)")
        print(f"constants     : {s['constants']} encoded")
        print(f"blocks flat   : {s['flattened_blocks']}")
        print(f"declarations  : {s['declarations']} renamed")
        if s.get("vm"):
            print(f"VM layer      : ON  (single runtime, {s['vm_nodes']} IR nodes, {s['vm_stream_bytes']} B stream)")
        else:
            print("VM layer      : OFF (direct library use only)")
        print(f"entry         : layout #{s.get('entry_layout')} / boot #{s.get('boot_layout')} (return, no top-level locals)")
        print(f"format        : {s.get('alias_count', 0)} aliases, {s.get('decoy_count', 0)} decoy handlers")
        print(
            f"hardening     : {s.get('protection_level')} / {s.get('pool_slices')} pool slices / "
            f"{s.get('vm_fragments')} VM fragments / {s.get('source_map_nodes')} private map nodes"
        )
        print(f"blob pad      : {s.get('blob_pad_bytes', 0)} B")
        print(
            f"stealth       : {'ON' if s.get('stealth') else 'OFF'} "
            f"({s.get('stealth_decoys', 0)} active decoys)"
        )
        print(f"chaff         : ratio {s.get('flatten_ratio')}, junk {s.get('junk')}, min {s.get('min_stmts')}, {s.get('vm_decoy_words', 0)} IR decoys")
        print(f"syntax check  : {'OK' if ok else 'FAILED'}" if a.verify else "")
        print(f"wrote         : {out_path}")
        if a.keys:
            print(f"keys          : {a.keys}  (keep private)")
        if a.source_map:
            print(f"source map    : {a.source_map}  (private; not in output)")
        if msg:
            print(msg)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
