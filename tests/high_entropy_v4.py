"""v4 high-entropy emitted-byte surface verification.

Imported by ``tests/run_tests.py`` (section 29); standalone:
``python3 tests/high_entropy_v4.py``.

Per the approved plan (section 12 / ``lower_target``):

* the ``<=15%`` output-size gate (measured against the v3 benchmark baseline at
  the canonical seed) **wins** over the 90–95% encoded-literal-share target;
* v4 entropy padding is clamped against the exact zero-padding base of each
  build, so no build is ever enlarged past ``max(fixed_gate, own_base)``;
* raw ``!@^&#%...`` outside a string literal is impossible (Luau rejects it),
  so all symbol soup lives inside long-bracket / mixed-escape quoted literals;
* no 99% claim, no multi-megabyte padding, no ``loadstring`` self-decoding;
* exact literal-share numbers are measured and exposed by :func:`measure_all`
  for the report/benchmark artifacts.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from obf import ast as A  # noqa: E402
from obf.banner import BANNER_BYTES, BANNER_TEXT, strip_banner  # noqa: E402
from obf import entropy as EN  # noqa: E402
from obf import minify  # noqa: E402
from obf import pipeline  # noqa: E402
from obf.vm import integrity as IN  # noqa: E402

CANONICAL_SEED = 20261118
SEEDS = (20261118, 7, 99991)
PRESETS = ("light", "medium", "heavy")


def check(failures: list[str], condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


def _src() -> bytes:
    return (ROOT / "tests" / "cases" / "hello_world.luau").read_bytes()


def _run(data: bytes, timeout: int = 25) -> tuple[int, bytes, bytes]:
    fd, path = tempfile.mkstemp(suffix=".luau")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        p = subprocess.run(
            [A.tool_path("luau"), path], capture_output=True, timeout=timeout
        )
        return p.returncode, p.stdout, p.stderr
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _structural_bytes(data: bytes) -> bytes:
    """All non-string token text (operators, identifiers, reserved words...)."""
    return b"".join(t.text for t in EN.tokens(data) if t.kind != "string")


def measure_all() -> list[dict]:
    """Exact size / literal-share records for every preset x seed (for reports)."""
    src = _src()
    records: list[dict] = []
    for preset in PRESETS:
        gate = int(IN.V3_BASELINE[preset] * 1.15)
        for seed in SEEDS:
            opts = pipeline.make_options(preset, seed=seed)
            res = pipeline.obfuscate(src, opts)
            m = EN.measure(res.output)
            base = res.v4.budget.base_bytes
            pad = res.v4.padding_bytes
            records.append({
                "preset": preset,
                "seed": seed,
                "bytes": len(res.output),
                "v3_baseline": IN.V3_BASELINE[preset],
                "gate_bytes": gate,
                "base_no_v4": base,
                "padding_bytes": pad,
                "within_fixed_gate": len(res.output) <= gate,
                "increase_vs_v3": round(
                    (len(res.output) - IN.V3_BASELINE[preset])
                    / IN.V3_BASELINE[preset], 4
                ),
                "string_share": m["string_share"],
                "encoded_share": m["encoded_share"],
                "string_literal_bytes": m["string_literal_bytes"],
                "encoded_literal_bytes": m["encoded_literal_bytes"],
                "structural_bytes": m["structural_bytes"],
                "num_string_literals": m["num_string_literals"],
                "num_long_bracket": m["num_long_bracket"],
            })
    return records


def run(failures: list[str]) -> int:
    """Run all high-entropy checks; return the number of checks."""
    checks = 0
    src = _src()
    rc0, out0, _ = _run(src)

    for preset in PRESETS:
        gate = int(IN.V3_BASELINE[preset] * 1.15)
        for seed in SEEDS:
            tag = f"v4-entropy/{preset}/{seed}"
            opts = pipeline.make_options(preset, seed=seed)
            res = pipeline.obfuscate(src, opts)
            o = res.output
            m = EN.measure(o)
            base = res.v4.budget.base_bytes

            ok, msg = pipeline.validate_syntax(o)
            check(failures, ok, f"{tag}: output does not parse: {msg[:120]!r}")
            checks += 1
            rc, out, err = _run(o)
            check(failures, (rc, out) == (rc0, out0),
                  f"{tag}: behaviour changed rc={rc} out={out[:60]!r} err={err[:100]!r}")
            checks += 1

            # required top banner, then zero-comment return-first body
            body = strip_banner(o)
            check(failures, o.startswith(BANNER_BYTES)
                  and body.startswith(b"return")
                  and not any(t.kind == "comment" for t in minify.tokenize(body)),
                  f"{tag}: output breaks banner / return-first body policy")
            checks += 1
            # no dynamic loader / self-decoding chunk
            check(failures, b"loadstring" not in o and b"HttpGet" not in o,
                  f"{tag}: dynamic loader or HttpGet present"); checks += 1
            # no multi-megabyte padding
            check(failures, len(o) < 1024 * 1024,
                  f"{tag}: output >= 1 MiB ({len(o)} B) — padding too large")
            checks += 1

            # <=15% gate: measured against the v3 baseline at the canonical
            # seed. For other seeds the third-pass VM's own base can exceed that
            # fixed baseline; in that case v4 must add zero padding.
            check(failures, len(body) <= max(gate, base) + 16,
                  f"{tag}: protected body {len(body)} exceeds max(fixed_gate {gate}, base {base})")
            checks += 1
            if seed == CANONICAL_SEED:
                check(failures, len(body) <= gate,
                      f"{tag}: canonical-seed 15% gate exceeded ({len(body)} > {gate})")
                checks += 1
            if base > gate:
                check(failures, res.v4.padding_bytes == 0,
                      f"{tag}: base already over gate but v4 added padding")
                checks += 1
            # padding is bounded by the configured budget, never runaway
            check(failures, 0 <= res.v4.padding_bytes <= opts.entropy_budget,
                  f"{tag}: padding {res.v4.padding_bytes} outside [0, {opts.entropy_budget}]")
            checks += 1
            check(failures, len(o) <= base + opts.entropy_budget + 8192,
                  f"{tag}: v4 added more than its entropy budget over the base")
            checks += 1

            # high-entropy surface: long-bracket + quoted markers, soup inside
            # literals, raw soup never outside a string token.
            check(failures, m["num_long_bracket"] >= 5,
                  f"{tag}: expected >=5 long-bracket markers, got {m['num_long_bracket']}")
            checks += 1
            check(failures, m["encoded_share"] >= m["string_share"] >= 0.0
                  and m["encoded_share"] <= 1.0,
                  f"{tag}: invalid literal shares {m['string_share']}/{m['encoded_share']}")
            checks += 1
            struct = _structural_bytes(o)
            check(failures, b"!" not in struct and b"@" not in struct,
                  f"{tag}: raw symbol soup found outside a string literal")
            checks += 1
            lits = EN.long_bracket_literals(o)
            check(failures, any(c in b"".join(lits) for c in b"!@^&#%"),
                  f"{tag}: no high-entropy symbol soup in long-bracket literals")
            checks += 1
            # The VM's stream-bounded dispatch loop is pre-existing; v4 must
            # not introduce any new unbounded `while` loop of its own.
            from obf.vm import traps as TR  # local import to keep module lean
            v4_lines = "\n".join(
                TR.emit_trap_group_lines(res.v4.traps)
                + res.v4.emit_marker_definitions()
                + res.v4.emit_verify_lines(list(IN.DOMAINS), "ok")
            )
            check(failures, "while " not in v4_lines,
                  f"{tag}: v4-emitted code contains a `while` loop"); checks += 1

    # Standalone literal-form probes (valid Luau + correct decoding).
    soup = EN.symbol_soup(__import__("random").Random(1), 512)
    long_lit = EN.lua_long_bracket(soup, 3)
    rc, out, err = _run(
        f"local s = {long_lit}\nprint(#s, s:sub(1,1), s:sub(#s,#s))\n".encode()
    )
    expected_long = b"512\t" + soup[:1] + b"\t" + soup[-1:]
    check(failures, rc == 0 and out.strip() == expected_long,
          f"literal-probe/long-bracket: rc={rc} out={out[:80]!r} "
          f"expected={expected_long!r} err={err[:120]!r}")
    checks += 1
    raw = bytes(range(256))
    quoted = EN.lua_mixed_quoted(raw, __import__("random").Random(2))
    rc, out, err = _run(
        f"local s = {quoted}\nprint(#s, s:byte(1), s:byte(200), s:byte(256))\n".encode()
    )
    check(failures, rc == 0 and out.strip() == b"256\t0\t199\t255",
          f"literal-probe/mixed-quoted: rc={rc} out={out[:80]!r} err={err[:120]!r}")
    checks += 1

    return checks


if __name__ == "__main__":
    fails: list[str] = []
    n = run(fails)
    if fails:
        print(f"HIGH-ENTROPY-V4: {n} checks, {len(fails)} failure(s)")
        for f in fails[:40]:
            print(" -", f)
        raise SystemExit(1)
    print(f"HIGH-ENTROPY-V4: ALL GREEN ({n} checks)")
    print("\nExact literal-share records:")
    print(f"{'preset':<7}{'seed':<10}{'bytes':>9}{'gate':>9}{'base':>9}"
          f"{'pad':>8}{'str%':>8}{'enc%':>8}{'vs_v3':>9}")
    for r in measure_all():
        print(f"{r['preset']:<7}{r['seed']:<10}{r['bytes']:>9}{r['gate_bytes']:>9}"
              f"{r['base_no_v4']:>9}{r['padding_bytes']:>8}"
              f"{r['string_share']*100:>7.2f}%{r['encoded_share']*100:>7.2f}%"
              f"{r['increase_vs_v3']*100:>8.1f}%")
