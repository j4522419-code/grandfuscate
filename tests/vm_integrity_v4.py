"""v4 VM integrity + opaque prediction/decoy-trap verification.

This module is imported by ``tests/run_tests.py`` (section 28) and can also be
run standalone:  ``python3 tests/vm_integrity_v4.py``.

It verifies the behaviour chosen in the approved plan:

* **core integrity** — a private canonical manifest covers bytecode / stream /
  fragment blobs / constant slices / opcode maps / dispatch / layout / per-node
  coefficients; per-domain and global digests are deterministic and change on
  a single-byte tamper;
* **decoy traps** — a guessed (wrong) capability ticket deterministically
  raises a controlled ``error(<opaque const>)`` with no hang; a valid build-time
  ticket returns a harmless default; decoys live in an inert, never-called table;
* **bounded work** — no ``while`` / ``repeat`` / ``while true do`` anywhere in
  the trap or window-check code;
* **harmless default** — tampering a marker inside the *real* decoder path does
  not raise an error or hang, it just degrades to a default;
* **no bare globals** — ``error`` / ``bit32.bxor`` / ``type`` / ``string.byte``
  are alias-rewritten so the shipped chunk has no forbidden bare globals;
* **no dynamic loader** and no legacy environment/hook poisoning.

These are obfuscation decoys, not a security boundary: an analyst who executes
the chunk can still observe everything and patch the checks. We do not claim to
defeat third-party dumpers or environment loggers.
"""
from __future__ import annotations

import os
import random
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from obf import ast as A  # noqa: E402
from obf import entropy as EN  # noqa: E402
from obf import pipeline  # noqa: E402
from obf.vm import integrity as IN  # noqa: E402
from obf.vm import traps as TR  # noqa: E402

SEED = 20261118


def check(failures: list[str], condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


def _luau(text: str, timeout: int = 25) -> tuple[int, str, str]:
    fd, path = tempfile.mkstemp(suffix=".luau")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        p = subprocess.run(
            [A.tool_path("luau"), path], capture_output=True, timeout=timeout
        )
        return p.returncode, p.stdout.decode("utf-8", "replace"), \
            p.stderr.decode("utf-8", "replace")
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _src() -> bytes:
    return (ROOT / "tests" / "cases" / "hello_world.luau").read_bytes()


def run(failures: list[str]) -> int:
    """Run all v4 integrity/trap checks; return the number of checks."""
    checks = 0
    src = _src()

    for preset in ("light", "medium", "heavy"):
        tag = f"v4-integrity/{preset}"
        res = pipeline.obfuscate(src, pipeline.make_options(preset, seed=SEED))
        v4 = res.v4
        check(failures, v4 is not None, f"{tag}: v4 plan not attached"); checks += 1
        if v4 is None:
            continue
        integ = v4.integrity

        # -- canonical manifest / digests ---------------------------------
        check(failures, integ.canonical_len > 0 and len(integ.canon) == integ.canonical_len,
              f"{tag}: canonical manifest empty or length mismatch"); checks += 1
        check(failures, set(integ.group_digests) == set(IN.DOMAINS),
              f"{tag}: manifest domains incomplete"); checks += 1
        check(failures, len(integ.real_opcode_values) > 0,
              f"{tag}: no real opcode values captured"); checks += 1

        canon = integ.canon
        g1, _, d1 = IN.plan_digests(canon, random.Random(0x5EED))
        g2, _, d2 = IN.plan_digests(canon, random.Random(0x5EED))
        check(failures, g1 == g2 and d1 == d2,
              f"{tag}: integrity digests are not deterministic"); checks += 1
        tampered = bytearray(canon)
        tampered[len(tampered) // 2] ^= 0xFF
        g3, _, d3 = IN.plan_digests(bytes(tampered), random.Random(0x5EED))
        check(failures, g1 != g3 or d1 != d3,
              f"{tag}: one-byte manifest tamper did not change any digest"); checks += 1

        # -- decoy traps (wrong ticket -> controlled error) ---------------
        trap_lines = TR.emit_trap_group_lines(v4.traps)
        rc, out, err = _luau(TR.make_probe_script(v4.traps))
        m = re.search(
            r"DECOYS=(\d+) NGUESSES=(\d+) WRONG_ERRORS=(\d+) "
            r"VALID_OK=(\d+) HANG=(\d+)", out
        )
        check(failures, rc == 0 and m is not None,
              f"{tag}: decoy probe did not run cleanly rc={rc} out={out!r} err={err[:120]!r}")
        checks += 1
        if m:
            n, ng, wrong, valid_ok, hang = (int(x) for x in m.groups())
            check(failures, n == v4.traps.count,
                  f"{tag}: probe decoy count {n} != {v4.traps.count}"); checks += 1
            check(failures, wrong == n * ng,
                  f"{tag}: wrong-ticket tickets did not all error ({wrong}/{n*ng})")
            checks += 1
            check(failures, valid_ok == n,
                  f"{tag}: valid-ticket tickets did not all return a harmless default "
                  f"({valid_ok}/{n})"); checks += 1
            check(failures, hang == 0,
                  f"{tag}: decoy probe reported a hang"); checks += 1
        check(failures, not TR.trap_lines_have_unbounded_loop(trap_lines),
              f"{tag}: trap code contains an unbounded loop"); checks += 1

        # -- bounded window checks ----------------------------------------
        verify = v4.emit_verify_lines(list(IN.DOMAINS), "ok")
        joined = "\n".join(verify)
        check(failures, "while" not in joined and "repeat" not in joined
              and "until" not in joined,
              f"{tag}: window check contains an unbounded loop"); checks += 1
        for dom in IN.DOMAINS:
            check(failures, any(f"for {v4.j_vars[dom]} = 1, {EN.INTEGRITY_WINDOW} do"
                                in line for line in verify),
                  f"{tag}: domain {dom} has no bounded {EN.INTEGRITY_WINDOW}-step window")
            checks += 1
        # The VM's own dispatch loop is a pre-existing, stream-bounded
        # `while true do` (it breaks on the terminating opcode). The plan only
        # forbids adding new unbounded loops in the v4 trap/verify/marker code.
        v4_code = "\n".join(
            trap_lines + verify + v4.emit_marker_definitions()
        )
        check(failures, "while true do" not in v4_code and "while " not in v4_code,
              f"{tag}: v4-emitted code contains a `while` loop"); checks += 1

        # -- window integrity probes (clean / tampered / quoted) ----------
        long_m = next((m for m in v4.markers if m.form == "long"), None)
        quoted_m = next((m for m in v4.markers if m.form == "quoted"), None)
        check(failures, long_m is not None and quoted_m is not None,
              f"{tag}: missing long-bracket or mixed-escape marker"); checks += 1
        if long_m is not None:
            rc, out, _ = _luau(IN.make_integrity_probe_script(long_m, tamper=False))
            check(failures, rc == 0 and "OK_TRUE" in out,
                  f"{tag}: clean long-bracket window did not verify ({out.strip()!r})")
            checks += 1
            rc, out, _ = _luau(IN.make_integrity_probe_script(long_m, tamper=True))
            check(failures, rc == 0 and "OK_FALSE" in out,
                  f"{tag}: tampered long-bracket window was not detected ({out.strip()!r})")
            checks += 1
        if quoted_m is not None:
            rc, out, _ = _luau(IN.make_integrity_probe_script(quoted_m, tamper=False))
            check(failures, rc == 0 and "OK_TRUE" in out,
                  f"{tag}: clean mixed-escape marker did not verify ({out.strip()!r})")
            checks += 1

        # -- real decoder integrity mismatch -> harmless default ----------
        lits = EN.long_bracket_literals(res.output)
        if lits:
            target = max(lits, key=len)
            pos = res.output.find(target)
            eq = target[1:target.find(b"[", 1)]
            start = pos + 1 + len(eq) + 1  # first byte of the long-bracket body
            ch = res.output[start + 10]
            repl = b"%" if ch != ord("%") else b"#"
            bad = res.output[:start + 10] + repl + res.output[start + 11:]
            rc, out, err = _luau_bytes(bad)
            # No controlled error text, no hang (rc 0). Output may be degraded.
            check(failures, rc == 0 and "error" not in err.lower(),
                  f"{tag}: real-decoder tamper raised an error/hang rc={rc} err={err[:120]!r}")
            checks += 1

        # -- no bare globals / no dynamic loader --------------------------
        bare_patterns = [
            rb"(?<![\w.])error\s*\(", rb"bit32\.bxor",
            rb"(?<![\w.])type\s*\(", rb"string\.byte",
        ]
        check(failures, not any(re.search(p, res.output) for p in bare_patterns),
              f"{tag}: emitted chunk contains a bare forbidden global"); checks += 1
        check(failures, b"loadstring" not in res.output and b"HttpGet" not in res.output,
              f"{tag}: emitted chunk contains a dynamic loader"); checks += 1

    # integrity=False must disable the whole v4 plan.
    off = pipeline.obfuscate(src, pipeline.make_options("light", seed=7, integrity=False))
    check(failures, off.v4 is None,
          "v4-integrity: integrity=False still produced a v4 plan"); checks += 1

    # Decoy keys never collide with real VM opcodes.
    on = pipeline.obfuscate(src, pipeline.make_options("heavy", seed=SEED))
    keys = set(on.v4.decoy_opcodes)
    check(failures, keys.isdisjoint(set(on.v4.integrity.real_opcode_values)),
          "v4-integrity: a decoy key collides with a real opcode"); checks += 1
    check(failures, len(keys) == on.v4.traps.count,
          "v4-integrity: decoy keys are not unique"); checks += 1

    return checks


def _luau_bytes(data: bytes, timeout: int = 25) -> tuple[int, str, str]:
    fd, path = tempfile.mkstemp(suffix=".luau")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        p = subprocess.run(
            [A.tool_path("luau"), path], capture_output=True, timeout=timeout
        )
        return p.returncode, p.stdout.decode("utf-8", "replace"), \
            p.stderr.decode("utf-8", "replace")
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


if __name__ == "__main__":
    fails: list[str] = []
    n = run(fails)
    if fails:
        print(f"VM-INTEGRITY-V4: {n} checks, {len(fails)} failure(s)")
        for f in fails[:40]:
            print(" -", f)
        raise SystemExit(1)
    print(f"VM-INTEGRITY-V4: ALL GREEN ({n} checks)")
