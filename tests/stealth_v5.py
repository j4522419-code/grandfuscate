"""V5 opt-in stealth / fail-closed active-decoy verification.

Imported by ``tests/run_tests.py`` (section 30) and runnable standalone:
``python3 tests/stealth_v5.py``.

Checks:
* default builds have stealth off and no active-decoy plan;
* ``stealth=True`` builds parse, run, keep ``return`` entry, no comments;
* decoys are embedded in real handler tables and referenced from guard lines;
* all four reaction classes exist and the bounded Luau probe exercises them;
* no bare forbidden globals / member chains, no dynamic loader, no raw soup;
* ``<=15%`` size gate still holds;
* CLI / API accept the opt-in flag and the ``fail_closed`` alias.

Hard boundary: these are obfuscation decoys. They make the protected script
fail closed / poison an enumerating logger; they do NOT crash a third-party
env-logger process and are not a security boundary.
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
from obf import minify, pipeline, web  # noqa: E402
from obf.cli import build_parser  # noqa: E402
from obf.layout import make_layout  # noqa: E402
from obf.vm import stealth as V5S  # noqa: E402
from tests import anti_analysis as AA  # noqa: E402
from tests.high_entropy_v4 import _structural_bytes  # noqa: E402

SRC = b'print("Hello World!")'
EXPECTED = b"Hello World!\n"
PRESETS = ("light", "medium", "heavy")
SEED = 20261118


def check(failures: list[str], condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


def _luau(script: str, timeout: int = 60) -> tuple[int, str, str]:
    exe = A.tool_path("luau")
    fd, path = tempfile.mkstemp(suffix=".luau")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(script)
        p = subprocess.run([exe, path], capture_output=True, text=True,
                           timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _run_output(data: bytes, timeout: int = 60) -> tuple[int, bytes, bytes]:
    exe = A.tool_path("luau")
    fd, path = tempfile.mkstemp(suffix=".luau")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        p = subprocess.run([exe, path], capture_output=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _name_tokens(data: bytes) -> set[str]:
    return {
        t.text.decode("latin-1")
        for t in minify.tokenize(data)
        if t.kind == "name"
    }


def run(failures: list[str]) -> int:
    checks = 0

    # -- defaults / opt-in surface ----------------------------------------
    normal = pipeline.make_options("medium", seed=SEED)
    check(failures, normal.stealth is False,
          "stealth-v5: default Options.stealth is not False"); checks += 1
    meta = web.meta()
    check(failures, meta["defaults"]["stealth"] is False,
          "stealth-v5: /api/meta defaults do not report stealth=false"); checks += 1

    opts_on, _verify, _raw = web.build_request({
        "source": SRC.decode(), "preset": "medium", "stealth": True,
    })
    check(failures, opts_on.stealth is True,
          "stealth-v5: API stealth=true was not honoured"); checks += 1
    opts_alias, _v, _r = web.build_request({
        "source": SRC.decode(), "preset": "medium", "fail_closed": True,
    })
    check(failures, opts_alias.stealth is True,
          "stealth-v5: API fail_closed alias was not honoured"); checks += 1
    opts_default, _v, _r = web.build_request({
        "source": SRC.decode(), "preset": "medium",
    })
    check(failures, opts_default.stealth is False,
          "stealth-v5: API default stealth is not False"); checks += 1

    parser = build_parser()
    a1 = parser.parse_args(["examples/sample.luau", "--stealth"])
    a2 = parser.parse_args(["examples/sample.luau", "--fail-closed"])
    a3 = parser.parse_args(["examples/sample.luau"])
    check(failures, a1.stealth is True and a2.stealth is True
          and a3.stealth is False,
          "stealth-v5: CLI --stealth / --fail-closed flags are wrong"); checks += 1

    # -- normal build remains unchanged ------------------------------------
    off = pipeline.obfuscate(SRC, pipeline.make_options("medium", seed=SEED))
    check(failures, off.stealth is None and off.v4.stealth is None,
          "stealth-v5: normal build unexpectedly has an active-decoy plan")
    checks += 1
    check(failures, off.stats.get("stealth") is False
          and off.keys.get("stealth") is False
          and off.stats.get("stealth_decoys") == 0,
          "stealth-v5: normal build stats/keys do not report stealth off")
    checks += 1

    # -- plan structure + real-path embedding ------------------------------
    for preset in PRESETS:
        tag = f"stealth-v5/{preset}"
        res = pipeline.obfuscate(SRC, pipeline.make_options(
            preset, seed=SEED, stealth=True
        ))
        plan = res.stealth
        check(failures, plan is not None and res.v4.stealth is plan,
              f"{tag}: missing active-decoy plan"); checks += 1
        if plan is None:
            continue
        check(failures, plan.count == res.stats.get("stealth_decoys")
              and plan.count >= 4,
              f"{tag}: decoy count mismatch {plan.count}"); checks += 1
        check(failures, all(plan.reaction_counts[k] > 0 for k in V5S.REACTIONS),
              f"{tag}: not all four reaction classes present"); checks += 1
        keys = [d.key for d in plan.decoys]
        check(failures, len(keys) == len(set(keys)),
              f"{tag}: duplicate decoy handler keys"); checks += 1
        real = set(int(v) for v in res.v4.integrity.real_opcode_values)
        check(failures, all(k not in real for k in keys),
              f"{tag}: decoy key collides with a real opcode"); checks += 1
        check(failures, all(d.table_key in V5S.HANDLER_TABLES
                            and d.reaction in V5S.REACTIONS
                            for d in plan.decoys),
              f"{tag}: invalid decoy table/reaction mapping"); checks += 1
        check(failures, len({plan.table_var, plan.bait_var, plan.react_var}) == 3,
              f"{tag}: T/P/R locals are not distinct"); checks += 1

        emitted = V5S.emit_stealth_lines(plan)
        check(failures, not V5S.stealth_lines_have_loader(emitted),
              f"{tag}: stealth code contains a dynamic loader"); checks += 1
        joined = "\n".join(emitted)
        for marker in ("error(", "coroutine.yield", "return b", "pcall(tostring"):
            check(failures, marker in joined,
                  f"{tag}: emitted decoys missing reaction marker {marker!r}")
            checks += 1

        layout = make_layout(SEED, preset)
        object.__setattr__(layout, "stealth_plan", plan)
        guard = layout.guard_line("constant", "i", 0, 0, "nil")
        check(failures, plan.react_call("i", "t") in guard
              and "return nil" not in guard,
              f"{tag}: guard_line does not call the active-decoy reactor")
        checks += 1
        object.__setattr__(layout, "stealth_plan", None)
        guard_off = layout.guard_line("constant", "i", 0, 0, "nil")
        check(failures, "return nil" in guard_off
              and plan.react_var not in guard_off,
              f"{tag}: guard_line with no plan changed default behaviour")
        checks += 1
        table_vars = {k: f"TV_{k}" for k in V5S.HANDLER_TABLES}
        assignments = V5S.emit_handler_assignments(plan, layout, table_vars)
        check(failures, len(assignments) == plan.count
              and all(f"{plan.table_var}[" in line for line in assignments),
              f"{tag}: decoys are not assigned into real handler tables")
        checks += 1

        # -- production output --------------------------------------------
        ok_syntax, msg = pipeline.validate_syntax(res.output)
        check(failures, ok_syntax,
              f"{tag}: stealth build does not parse ({msg[:100]})"); checks += 1
        rc, out, err = _run_output(res.output)
        check(failures, (rc, out, err) == (0, EXPECTED, b""),
              f"{tag}: stealth build changed runtime behaviour "
              f"(rc={rc} out={out[:60]!r} err={err[:120]!r})"); checks += 1
        check(failures, res.output.startswith(b"return"),
              f"{tag}: output does not start with return"); checks += 1
        check(failures, not any(t.kind == "comment"
                                for t in minify.tokenize(res.output)),
              f"{tag}: output contains a comment"); checks += 1
        check(failures, res.v4.budget.within_gate(len(res.output)),
              f"{tag}: stealth build exceeds the <=15% size gate "
              f"({len(res.output)} > {res.v4.budget.gate_bytes})"); checks += 1
        findings = AA.scan_output(SRC, res.output, res.keys, res.source_map)
        check(failures, not findings,
              f"{tag}: production scanner findings: {findings[:3]}"); checks += 1
        struct = _structural_bytes(res.output)
        check(failures, b"!" not in struct and b"@" not in struct,
              f"{tag}: raw symbol soup outside a string literal"); checks += 1
        names = _name_tokens(res.output)
        forbidden = {"error", "coroutine", "yield", "setmetatable", "tostring",
                     "pcall", "rawset", "pairs", "loadstring"}
        check(failures, not (names & forbidden),
              f"{tag}: bare forbidden globals remain: {sorted(names & forbidden)}")
        checks += 1
        check(failures, b"loadstring" not in res.output,
              f"{tag}: dynamic loader present in output"); checks += 1
        check(failures, res.stats.get("anti_env") is False
              and res.stats.get("anti_tamper") is False,
              f"{tag}: legacy environment poisoning was re-enabled"); checks += 1

        # -- bounded decoy probe ------------------------------------------
        probe = V5S.make_probe_script(plan)
        try:
            prc, pout, perr = _luau(probe, timeout=60)
        except subprocess.TimeoutExpired:
            prc, pout, perr = -1, "", "probe timed out"
        m = re.search(
            r"DECOYS=(\d+) CHECKED=(\d+) ERROR=(\d+) YIELD=(\d+) "
            r"GARBAGE=(\d+) HYBRID=(\d+) HANG=0", pout
        )
        check(failures, prc == 0 and m is not None,
              f"{tag}: decoy probe failed rc={prc} out={pout[:120]!r} "
              f"err={perr[:160]!r}"); checks += 1
        if m:
            n, checked, e, y, g, h = (int(x) for x in m.groups())
            expected = plan.reaction_counts
            check(failures, (n, checked) == (plan.count, plan.count),
                  f"{tag}: probe did not check every decoy"); checks += 1
            check(failures, (e, y, g, h) == (
                expected["error"], expected["yield"],
                expected["garbage"], expected["hybrid"]),
                  f"{tag}: probe reaction counts {e,y,g,h} != {expected}")
            checks += 1

    return checks


if __name__ == "__main__":
    failures: list[str] = []
    total = run(failures)
    if failures:
        print(f"STEALTH-V5: FAIL ({total} checks, {len(failures)} failures)")
        for f in failures[:40]:
            print(" -", f)
        raise SystemExit(1)
    print(f"STEALTH-V5: ALL GREEN ({total} checks)")
