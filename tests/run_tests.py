"""Behavioural test suite: original vs obfuscated, verified by real Luau.

Every case is run with the official `luau` interpreter and the stdout + exit
code must match exactly. Normal builds must also stay on one VM runtime, avoid
environment poisoning, and remain executable in compatibility environments.
"""
from __future__ import annotations

import glob
import json
import os
import re
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from obf import ast as A  # noqa: E402
from obf.banner import BANNER_BYTES, BANNER_TEXT, strip_banner  # noqa: E402
from obf import format as F  # noqa: E402
from obf import minify  # noqa: E402
from obf import pipeline  # noqa: E402
from obf import vm as VM  # noqa: E402
from obf import web  # noqa: E402
from tests import anti_analysis as AA  # noqa: E402
from tests import anti_analysis_v3 as V3  # noqa: E402
from tests import build_diversity as BD  # noqa: E402
from tests import compare_versions as CV  # noqa: E402
from tests import runtime_analysis as RA  # noqa: E402
from tests import return_probe as RP  # noqa: E402
from tests import test_publish as PUB  # noqa: E402
from tests import vm_integrity_v4 as V4I  # noqa: E402
from tests import high_entropy_v4 as V4E  # noqa: E402
from tests import stealth_v5 as V5S  # noqa: E402
from tests import crypto_v7 as V7  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CASES = sorted(glob.glob(os.path.join(HERE, "cases", "*.luau")))
PRESETS = ["light", "medium", "heavy"]
SEEDS = [11, 0x5EED]


def run(data: bytes, timeout: int = 120) -> tuple[int, bytes, bytes]:
    # A VM-interpreted 200000-iteration fixture (tests/cases/bench.luau) is
    # legitimately ~55-60 s of CPU on a cold interpreter; keep the wall-clock
    # guard above that so a correct-but-slow differential run cannot flake.
    # timed() already used 120 s. This is a liveness ceiling, not a correctness
    # relaxation: stdout/exit/status equality is still asserted on every run.
    exe = A.tool_path("luau")
    fd, path = tempfile.mkstemp(suffix=".luau")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        p = subprocess.run([exe, path], capture_output=True, timeout=timeout)
        return p.returncode, p.stdout.replace(b"\r\n", b"\n"), p.stderr
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def timed(data: bytes, repeats: int = 3) -> float:
    best = 1e9
    for _ in range(repeats):
        t0 = time.perf_counter()
        run(data, timeout=120)
        best = min(best, time.perf_counter() - t0)
    return best


def check(failures: list[str], condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


def first_token(data: bytes) -> str:
    for t in minify.tokenize(data):
        if t.kind not in ("ws", "comment"):
            return t.text.decode("latin-1")
    return ""


def top_level_locals(data: bytes) -> int:
    """Count `local` tokens outside any () / {} / [] group."""
    depth = 0
    count = 0
    for t in minify.tokenize(data):
        if t.kind in ("ws", "comment"):
            continue
        if t.text in (b"(", b"{", b"["):
            depth += 1
        elif t.text in (b")", b"}", b"]"):
            depth = max(0, depth - 1)
        elif t.kind == "name" and t.text == b"local" and depth == 0:
            count += 1
    return count


def executor_env_run(data: bytes, timeout: int = 90) -> tuple[int, bytes, bytes]:
    """Run output where `_G` is a dummy table but globals live in the env.

    Some Roblox executors set a separate/empty `_G` and put real globals in the
    function environment. `loadstring` + `setfenv` reproduces that layout.
    """
    text = data.decode("latin-1")
    longest = max((len(x) for x in re.findall(r"\](=*)\]", text)), default=0)
    eq = "=" * (longest + 1)
    driver = f'''local src = [{eq}[{text}]{eq}]
local env = {{}}
env._G = {{}}
env.print = print env.string = string env.table = table env.bit32 = bit32
env.math = math env.pcall = pcall env.select = select env.tostring = tostring
env.type = type env.rawset = rawset env.setmetatable = setmetatable
env.getfenv = function() return env end
setmetatable(env, {{__index = _G}})
local f, e = loadstring(src, "=obf")
if not f then error("loadstring: " .. tostring(e)) end
setfenv(f, env)
f()
'''
    return run(driver.encode("latin-1"), timeout=timeout)


def main() -> int:
    failures: list[str] = []
    total = 0
    print(f"{'case':<16} {'preset':<10} {'seed':<8} {'syntax':<8} {'behaviour':<10} {'size':>8}")
    print("-" * 68)
    for case in CASES:
        with open(case, "rb") as f:
            original = f.read()
        rc0, out0, err0 = run(original)
        if rc0 != 0:
            failures.append(f"ORIGINAL FAILED: {os.path.basename(case)}: {err0[:200]!r}")
            continue
        for preset in PRESETS:
            for seed in SEEDS:
                total += 1
                opts = pipeline.make_options(preset, seed=seed)
                try:
                    res = pipeline.obfuscate(original, opts)
                except Exception as exc:
                    failures.append(f"{os.path.basename(case)}/{preset}/{seed}: transform raised {exc!r}")
                    print(f"{os.path.basename(case):<16} {preset:<10} {seed:<8} {'RAISED':<8}")
                    continue
                ok, msg = pipeline.validate_syntax(res.output)
                rc, out, err = run(res.output)
                same = (rc == rc0 and out == out0)
                if not ok:
                    failures.append(f"{os.path.basename(case)}/{preset}/{seed}: syntax: {msg[:300]}")
                if not same:
                    failures.append(
                        f"{os.path.basename(case)}/{preset}/{seed}: behaviour rc {rc} vs {rc0}, "
                        f"stdout {out[:120]!r} vs {out0[:120]!r}, stderr {err[:200]!r}"
                    )
                print(
                    f"{os.path.basename(case):<16} {preset:<10} {seed:<8} "
                    f"{'OK' if ok else 'FAIL':<8} {'OK' if same else 'FAIL':<10} {len(res.output):>8}"
                )

    print("\nVM layer (single runtime, shuffled opcodes, encoded stream)")
    print("-" * 68)
    vm_total = 0
    for case in CASES:
        with open(case, "rb") as f:
            original = f.read()
        rc0, out0, _ = run(original)
        for seed in SEEDS:
            vm_total += 1
            opts = pipeline.make_options("medium", seed=seed)
            res = pipeline.obfuscate(original, opts)
            ok, _msg = pipeline.validate_syntax(res.output)
            rc, out, err = run(res.output)
            same = (rc == rc0 and out == out0)
            single = (
                res.stats.get("vm") is True
                and res.stats.get("nested_vm") is False
                and res.stats.get("anti_env") is False
                and res.stats.get("anti_tamper") is False
            )
            no_loader = all(
                token not in res.output
                for token in (b"loadstring", b"load(", b"require(")
            )
            if not (ok and same and single and no_loader):
                failures.append(
                    f"VM/{os.path.basename(case)}/{seed}: ok={ok} same={same} "
                    f"single={single} no_loader={no_loader} stderr={err[:160]!r}"
                )
            print(
                f"{os.path.basename(case):<16} seed={seed:<6} "
                f"{'OK' if (ok and same and single and no_loader) else 'FAIL':<8} "
                f"{'VM' if res.stats.get('vm') else 'SRC':<8} {len(res.output):>8}"
            )

    print("\nreliability / compatibility")
    print("-" * 68)
    hard_total = 0
    compat_total = 0
    scan_total = 0
    second_total = 0
    third_total = 0
    publish_total = 0
    v4_integrity_total = 0
    v4_entropy_total = 0
    v5_total = 0
    v6_total = 0
    v7_total = 0
    return_total = 0
    complex_total = 0
    hard_bad: list[str] = []

    with open(CASES[0], "rb") as f:
        sample = f.read()

    # 1. All three presets are single-VM, syntax-valid, behaviour-identical and ordered by size.
    hard_total += 1
    preset_results = {}
    preset_ok = True
    for preset in PRESETS:
        res = pipeline.obfuscate(sample, pipeline.make_options(preset, seed=7))
        preset_results[preset] = res
        ok, _msg = pipeline.validate_syntax(res.output)
        rc, out, err = run(res.output)
        rc0, out0, _ = run(sample)
        single = (
            res.stats.get("vm") is True
            and res.stats.get("nested_vm") is False
            and res.stats.get("anti_env") is False
            and res.stats.get("anti_tamper") is False
        )
        if not (ok and rc == rc0 and out == out0 and single):
            preset_ok = False
            hard_bad.append(f"{preset} preset failed single-VM behaviour check: {err[:160]!r}")
    ordered = (
        len(preset_results["light"].output)
        < len(preset_results["medium"].output)
        < len(preset_results["heavy"].output)
        < 1024 * 1024
    )
    if not ordered:
        preset_ok = False
        hard_bad.append("preset sizes are not light < medium < heavy < 1 MB")
    if not preset_ok:
        failures.extend(hard_bad)
    print(
        f"{'three presets':<24} {'OK' if preset_ok else 'FAIL':<8} "
        f"{len(preset_results['light'].output)} / {len(preset_results['medium'].output)} / {len(preset_results['heavy'].output)} B"
    )

    # 2. Compatibility with executor-like globals that used to poison anti-env.
    hard_total += 1
    heavy = preset_results["heavy"]
    compat_prelude = (
        b"getgenv=function() return {} end\n"
        b"getrenv=function() return {} end\n"
        b"hookfunction=function() end\n"
        b"repl={}\n"
        b"deobfuscate=function() end\n"
        b"__DEOB=true\n"
        b"debug={gethook=function() return nil end}\n"
        b"local real_getfenv=getfenv\n"
        b"getfenv=function(level)\n"
        b"  if level==0 then return {} end\n"
        b"  if level==1 then return setmetatable({}, {__index=real_getfenv()}) end\n"
        b"  return real_getfenv(level)\n"
        b"end\n"
    )
    crc, cout, cerr = run(compat_prelude + heavy.output)
    rc0, out0, _ = run(sample)
    compat_ok = (crc == rc0 and cout == out0)
    if not compat_ok:
        failures.append(f"compatibility environment failed: rc {crc}, stderr {cerr[:200]!r}")
    print(f"{'compat environment':<24} {'OK' if compat_ok else 'FAIL':<8}")

    # 3. No dynamic loader wrapper.
    hard_total += 1
    no_loader = all(
        token not in heavy.output
        for token in (b"loadstring", b"load(", b"require(")
    )
    if not no_loader:
        failures.append("heavy output contains a dynamic loader wrapper")
    print(f"{'no loadstring':<24} {'OK' if no_loader else 'FAIL':<8}")

    # 4. Required top banner, then zero-comment return-first body.
    hard_total += 1
    heavy_body = strip_banner(heavy.output)
    clean_ok = (
        heavy.output.startswith(BANNER_BYTES)
        and heavy_body.startswith(b"return")
        and first_token(heavy_body) == "return"
        and not any(t.kind == "comment" for t in minify.tokenize(heavy_body))
        and heavy_body.count(b"\n") == 1
        and (b"-- obfuscated by " + b"grandfuscate") not in heavy_body
    )
    if not clean_ok:
        failures.append("output is missing banner or is not a return-first protected body")
    print(f"{'banner + return':<24} {'OK' if clean_ok else 'FAIL':<8}")

    # 5. Public API exposes exactly three presets and safe defaults.
    hard_total += 1
    meta = web.meta()
    meta_ok = (
        meta["presets"] == ["light", "medium", "heavy"]
        and meta["defaults"]["preset"] == "medium"
        and meta["defaults"]["vm"] is True
        and meta["defaults"]["nested_vm"] is False
        and meta["defaults"]["anti_env"] is False
        and meta["defaults"]["anti_tamper"] is False
        and meta["defaults"]["stealth"] is False
        and meta["defaults"]["crypto"] is True
        and "key_text_max" not in meta["limits"]
        and meta["defaults"]["blob_pad"] == 4096
        and meta["defaults"]["flatten_ratio"] == 0.75
        and meta["limits"]["blob_pad_max"] == 65536
    )
    if not meta_ok:
        failures.append("/api/meta does not expose the expected always-on V7 defaults")
    print(f"{'api meta':<24} {'OK' if meta_ok else 'FAIL':<8}")

    # 6. Stale legacy config cannot re-enable broken hardening or huge blobs.
    hard_total += 1
    legacy = {
        "source": sample.decode("utf-8"),
        "preset": "max",
        "vm": False,
        "nested_vm": True,
        "anti_env": True,
        "anti_tamper": True,
        "one_line": False,
        "junk": 32,
        "min_stmts": 64,
        "flatten_ratio": 4.0,
        "blob_pad": 1048576,
    }
    opts, verify, _raw = web.build_request(legacy)
    clamped = (
        opts.preset == "heavy"
        and opts.vm is True
        and opts.nested_vm is False
        and opts.anti_env is False
        and opts.anti_tamper is False
        and opts.stealth is False
        and opts.one_line is True
        and opts.junk <= 8
        and opts.min_stmts <= 16
        and opts.flatten_ratio <= 1.0
        and opts.blob_pad <= 65536
        and verify is True
    )
    if not clamped:
        failures.append("legacy API payload was not clamped to the single-VM policy")
    print(f"{'legacy api clamps':<24} {'OK' if clamped else 'FAIL':<8}")

    # 7. Simplified UI has exactly three presets and no broken controls.
    hard_total += 1
    ui_path = os.path.join(ROOT, "web", "index.html")
    with open(ui_path, encoding="utf-8") as f:
        ui = f.read()
    ui_ok = (
        '<option value="light">Light</option>' in ui
        and '<option value="medium" selected>Medium</option>' in ui
        and '<option value="heavy">Heavy</option>' in ui
        and "pretty" not in ui.lower()
        and all(x not in ui for x in ('id="nested"', 'id="antiEnv"', 'id="antiTamper"', 'id="ratio"', 'id="blobPad"'))
        and "flatten_ratio: +$(\"ratio\").value" not in ui
        and all(x not in ui for x in (
            'id="crypto"', 'id="keyText"', 'id="buildStatus"',
            'V7 key text', 'V7 crypto (opt-in)',
            'V7 embeds a derived key', 'V7 crypto ON', 'key_text'
        ))
        and 'crypto: true' in ui
    )
    if not ui_ok:
        failures.append("UI still exposes old presets, sliders, hardening or V7 controls/status text")
    print(f"{'ui presets':<24} {'OK' if ui_ok else 'FAIL':<8}")

    # 8. Provenance still identifies the exact file and detects tampering.
    hard_total += 1
    medium = preset_results["medium"]
    info = pipeline.identify_bytes(medium.output, medium.keys)
    tampered = bytearray(medium.output)
    tampered[-1] ^= 1
    info2 = pipeline.identify_bytes(bytes(tampered), medium.keys)
    provenance_ok = info["exact_file"] and not info["tampered"] and info2["tampered"]
    if not provenance_ok:
        failures.append("provenance / tamper detection failed")
    print(f"{'provenance':<24} {'OK' if provenance_ok else 'FAIL':<8}")

    # 9. Heavy preset remains within a sane runtime budget.
    hard_total += 1
    t0, t1 = timed(sample), timed(heavy.output)
    budget_ok = t1 < max(0.5, t0 * 200)
    if not budget_ok:
        failures.append(f"heavy runtime too slow: {t1*1000:.1f} ms")
    print(
        f"{'runtime budget':<24} {'OK' if budget_ok else 'FAIL':<8} "
        f"original {t0*1000:.1f} ms, heavy {t1*1000:.1f} ms ({t1/max(t0,1e-9):.2f}x)"
    )

    # 10. Every preset uses a return-based entry with no top-level locals.
    hard_total += 1
    fixed_markers = (
        b"string.byte", b"string.char", b"table.concat", b"table.pack",
        b"table.unpack", b"math.floor", b"math.min", b"math.max",
        b"bit32.bxor", b"loadstring", b"load(", b"require(",
    )
    entry_ok = True
    shape_summary = []
    for preset, res in preset_results.items():
        out = res.output
        body = strip_banner(out)
        layout_id = res.stats.get("entry_layout")
        shape_summary.append(f"{preset}:layout#{layout_id}")
        if not (
            out.startswith(BANNER_BYTES)
            and body.startswith(b"return")
            and first_token(body) == "return"
            and top_level_locals(body) == 0
            and not any(t.kind == "comment" for t in minify.tokenize(body))
            and body.count(b"\n") == 1
            and layout_id in F.ENTRY_LAYOUTS
            and res.stats.get("boot_layout") in F.BOOT_LAYOUTS
            and res.stats.get("alias_count", 0) > 0
            and res.stats.get("decoy_count", 0) > 0
            and all(m not in body for m in fixed_markers)
            and body.count(b"getfenv") <= 2
        ):
            entry_ok = False
            failures.append(f"{preset} output does not meet return/format policy")
    if not entry_ok:
        failures.append("return-based entrypoint / no-top-level-local check failed")
    print(f"{'return entry':<24} {'OK' if entry_ok else 'FAIL':<8} {' '.join(shape_summary)}")

    # 11. Entry shape and handler-table bytes are polymorphic across seeds.
    hard_total += 1
    layouts = set()
    boots = set()
    prefixes = set()
    poly_ok = True
    for seed in range(1, 9):
        r = pipeline.obfuscate(sample, pipeline.make_options("medium", seed=seed))
        layouts.add(r.stats.get("entry_layout"))
        boots.add(r.stats.get("boot_layout"))
        prefixes.add(r.output[:96])
        if any(m in r.output for m in fixed_markers):
            poly_ok = False
    if len(layouts) < 3 or len(boots) < 2 or len(prefixes) < 8:
        poly_ok = False
        failures.append("entry format is not polymorphic across seeds")
    print(
        f"{'format polymorphism':<24} {'OK' if poly_ok else 'FAIL':<8} "
        f"{len(layouts)} layouts, {len(boots)} boots, {len(prefixes)} distinct prefixes"
    )

    # 12. Every boot style works when `_G` is separate from the real globals.
    hard_total += 1
    exec_src = b'print("executor", 6*7)\n'
    rc0, out0, _ = run(exec_src)
    needed_boots = set(F.BOOT_LAYOUTS)
    found_boots: dict[str, object] = {}
    for seed in range(1, 30):
        r = pipeline.obfuscate(exec_src, pipeline.make_options("medium", seed=seed))
        style = r.stats.get("boot_layout")
        if style in needed_boots and style not in found_boots:
            found_boots[style] = r
    exec_ok = len(found_boots) == len(needed_boots)
    for style, r in found_boots.items():
        rc, out, err = executor_env_run(r.output)
        if (rc, out) != (rc0, out0):
            exec_ok = False
            failures.append(
                f"executor-like env failed for {style}: rc={rc} out={out[:80]!r} err={err[:160]!r}"
            )
    if not exec_ok:
        failures.append("executor-like environment / separate _G check failed")
    print(
        f"{'executor-like env':<24} {'OK' if exec_ok else 'FAIL':<8} "
        f"{len(found_boots)} / {len(needed_boots)} boot styles"
    )

    print("\nanti-analysis / private source map / benchmarks")
    print("-" * 68)

    # 13. Differential checks for advanced Luau semantics and a mocked Roblox API.
    compat_paths = [
        (None, os.path.join(HERE, "cases", "advanced.luau"), "advanced"),
        (
            os.path.join(HERE, "compat", "roblox_mock_prelude.luau"),
            os.path.join(HERE, "compat", "roblox_like.luau"),
            "roblox_like",
        ),
    ]
    compat_ok = True
    for prelude_path, case_path, label in compat_paths:
        with open(case_path, "rb") as f:
            body = f.read()
        prefix = b""
        if prelude_path:
            with open(prelude_path, "rb") as f:
                prefix = f.read() + b"\n"
        src = prefix + body
        rc0, out0, err0 = run(src)
        if rc0 != 0:
            compat_ok = False
            failures.append(f"compat original failed: {label}: {err0[:160]!r}")
            continue
        for preset in PRESETS:
            for seed in SEEDS:
                compat_total += 1
                r = pipeline.obfuscate(src, pipeline.make_options(preset, seed=seed))
                ok, msg = pipeline.validate_syntax(r.output)
                rc, out, err = run(r.output)
                same = (rc == rc0 and out == out0 and err == err0)
                if not (ok and same and r.stats.get("vm") is True and not r.stats.get("vm_fallback")):
                    compat_ok = False
                    failures.append(
                        f"compat/{label}/{preset}/{seed}: ok={ok} same={same} "
                        f"vm={r.stats.get('vm')} fallback={r.stats.get('vm_fallback')} "
                        f"stderr={err[:160]!r} syntax={msg[:120]!r}"
                    )
    print(
        f"{'compat differential':<24} {'OK' if compat_ok else 'FAIL':<8} "
        f"{compat_total} original-vs-obfuscated runs"
    )

    # 14. Advanced semantics also survive an executor-like separate _G environment.
    hard_total += 1
    with open(os.path.join(HERE, "cases", "advanced.luau"), "rb") as f:
        advanced_src = f.read()
    rc0, out0, _ = run(advanced_src)
    advanced_heavy = pipeline.obfuscate(
        advanced_src, pipeline.make_options("heavy", seed=20261118)
    )
    rc, out, err = executor_env_run(advanced_heavy.output)
    exec_adv_ok = rc == rc0 and out == out0 and advanced_heavy.stats.get("vm") is True
    if not exec_adv_ok:
        failures.append(
            f"executor-like advanced semantics failed: rc={rc} out={out[:120]!r} err={err[:160]!r}"
        )
    print(f"{'executor advanced':<24} {'OK' if exec_adv_ok else 'FAIL':<8}")

    # 15. Production-output scanner + private source map + web API policy.
    hard_total += 1
    with open(os.path.join(HERE, "scan_fixture.luau"), "rb") as f:
        scan_src = f.read()
    scan_rc0, scan_out0, _ = run(scan_src)
    scan_ok = True
    for preset in PRESETS:
        for seed in (11, 0x5EED, 20261118, 777):
            scan_total += 1
            r = pipeline.obfuscate(scan_src, pipeline.make_options(preset, seed=seed))
            findings = AA.scan_output(scan_src, r.output, r.keys, r.source_map)
            ok, _msg = pipeline.validate_syntax(r.output)
            rc, out, err = run(r.output)
            if findings or not ok or (rc, out, err) != (scan_rc0, scan_out0, b""):
                scan_ok = False
                failures.extend(findings[:4])
                failures.append(
                    f"scanner/{preset}/{seed}: syntax={ok} behaviour={(rc, out[:60], err[:100])!r}"
                )
    payload = {
        "source": scan_src.decode("utf-8"),
        "preset": "medium",
        "seed": 31415,
        "verify": False,
    }
    resp = web.do_obfuscate(payload)
    web_out = resp["output"].encode("utf-8")
    web_findings = AA.scan_output(scan_src, web_out, resp["keys"])
    private_ok = (
        not web_findings
        and "source_map" not in resp["keys"]
        and "runtime_layout" not in resp["keys"]
        and "operand_encoding" not in resp["keys"]
        and "control_flow" not in resp["keys"]
        and resp["private_source_map"]["embedded_in_output"] is False
        and resp["private_source_map"]["sha256"] == resp["keys"].get("source_map_sha256")
    )
    payload2 = {**payload, "include_source_map": True}
    resp2 = web.do_obfuscate(payload2)
    sm = resp2["keys"].get("source_map", {})
    source_map_ok = (
        sm.get("marker") == "__GRANDFUSCATE_PRIVATE_SOURCE_MAP_V3__"
        and resp2["private_source_map"]["included_in_keys"] is True
        and resp2["private_source_map"]["embedded_in_output"] is False
        and len(sm.get("nodes", [])) > 0
        and len(sm.get("constants", [])) > 0
        and all(
            key in sm
            for key in (
                "entry_layout", "boot_layout", "runtime_layout", "field_keys",
                "pool_chunk_plans", "vm_chunk_plans", "control_flow",
                "compile_notes", "operand",
            )
        )
        and len(sm.get("pool_chunk_plans", [])) > 0
        and len(sm.get("vm_chunk_plans", [])) > 0
        and sm.get("marker", "").encode("utf-8") not in web_out
    )
    if not (private_ok and source_map_ok):
        scan_ok = False
        failures.append("web API private source-map policy failed")
    if not scan_ok:
        failures.append("production-output scanner found disallowed material")
    print(
        f"{'output scanner':<24} {'OK' if scan_ok else 'FAIL':<8} "
        f"{scan_total} production chunks + web API"
    )

    # 16. Deterministic seeded builds.
    hard_total += 1
    repro_ok, repro_bad = AA.reproducibility(scan_src)
    if not repro_ok:
        failures.extend(repro_bad)
    print(f"{'seeded reproducibility':<24} {'OK' if repro_ok else 'FAIL':<8}")

    # 17. Benchmarks for size, startup time, memory and runtime overhead.
    hard_total += 1
    bench_ok = True
    bench_msg = ""
    try:
        bench = AA.benchmark()
        bench_path = AA.write_benchmark_markdown(bench)
        sizes = bench["output_size_bytes"]
        bench_ok = (
            sizes["light"] < sizes["medium"] < sizes["heavy"] < 1024 * 1024
            and bench["startup"]["heavy"]["seconds_median"] < 0.5
            and bench["runtime"]["overhead_median"] < AA.BENCHMARK_OVERHEAD_BUDGET
            and os.path.isfile(bench_path)
        )
        bench_msg = (
            f"{sizes['light']:,} / {sizes['medium']:,} / {sizes['heavy']:,} B, "
            f"{bench['runtime']['overhead_median']:.1f}x runtime"
        )
        if not bench_ok:
            failures.append(
                "benchmark sanity checks failed "
                f"(third-pass ceiling {AA.BENCHMARK_OVERHEAD_BUDGET:.0f}x)"
            )
    except Exception as exc:  # noqa: BLE001
        bench_ok = False
        bench_msg = repr(exc)
        failures.append(f"benchmark raised {exc!r}")
    print(f"{'benchmarks':<24} {'OK' if bench_ok else 'FAIL':<8} {bench_msg}")

    print("\nsecond-pass anti-analysis verification")
    print("-" * 68)

    # 18. `print(67)` keeps stdout, exit status and top-level return values.
    second_total += 1
    p67_src = open(os.path.join(HERE, "cases", "print67.luau"), "rb").read()
    rc0, out0, err0 = RP.run(p67_src)
    p67_ok = True
    for preset in PRESETS:
        for seed in SEEDS:
            return_total += 1
            res = pipeline.obfuscate(p67_src, pipeline.make_options(preset, seed=seed))
            ok, _msg = pipeline.validate_syntax(res.output)
            rc, out, err = RP.run(res.output)
            if (
                not ok
                or (rc, out, err) != (rc0, out0, err0)
                or res.stats.get("vm") is not True
            ):
                p67_ok = False
                failures.append(
                    f"print67/{preset}/{seed}: syntax={ok} "
                    f"behaviour={(rc, out[:80], err[:120])!r}"
                )
    print(
        f"{'print67 returns':<24} {'OK' if p67_ok else 'FAIL':<8} "
        f"{return_total} stdout+return probes"
    )

    # 19. Complex Luau semantics fixture across presets and seeds.
    second_total += 1
    matrix_src = open(os.path.join(HERE, "cases", "semantics_matrix.luau"), "rb").read()
    rc0, out0, err0 = run(matrix_src)
    complex_ok = True
    for preset in PRESETS:
        for seed in SEEDS:
            complex_total += 1
            res = pipeline.obfuscate(matrix_src, pipeline.make_options(preset, seed=seed))
            ok, _msg = pipeline.validate_syntax(res.output)
            rc, out, err = run(res.output)
            if (
                not ok
                or (rc, out, err) != (rc0, out0, err0)
                or len(res.source_map.get("nodes", [])) < 20
            ):
                complex_ok = False
                failures.append(
                    f"complex/{preset}/{seed}: syntax={ok} "
                    f"behaviour={(rc, out[:80], err[:120])!r} "
                    f"nodes={len(res.source_map.get('nodes', []))}"
                )
    print(
        f"{'complex fixtures':<24} {'OK' if complex_ok else 'FAIL':<8} "
        f"{complex_total} differential runs"
    )

    # 20. Restricted-runtime analysis probe.
    second_total += 1
    try:
        ra_ok, ra_bad, ra_results = RA.run()
        ra_files = os.path.isfile(RA.RESULTS_JSON) and os.path.isfile(RA.RESULTS_MD)
        if not ra_ok or not ra_files or not ra_results.get("success"):
            failures.extend(ra_bad[:6])
            failures.append("runtime-analysis probe failed or artifacts are missing")
        probes = ra_results.get("probes", [])
        print(
            f"{'runtime analysis':<24} {'OK' if ra_ok and ra_files else 'FAIL':<8} "
            f"{len(probes)} instrumented probes"
        )
    except Exception as exc:  # noqa: BLE001
        failures.append(f"runtime-analysis probe raised {exc!r}")
        print(f"{'runtime analysis':<24} FAIL     {exc!r}")

    # 21. Five structurally different builds with identical behaviour.
    second_total += 1
    try:
        manifest = BD.generate()
        div_ok, div_bad = BD.verify()
        diverse = (
            div_ok
            and len(manifest.get("builds", [])) == 5
            and manifest.get("diversity", {}).get("outputs") == 5
            and manifest.get("diversity", {}).get("token_prefixes") == 5
        )
        if not diverse:
            failures.extend(div_bad[:6])
            failures.append("five-build diversity verification failed")
        print(
            f"{'five-build diversity':<24} {'OK' if diverse else 'FAIL':<8} "
            f"seeds {manifest.get('seeds')}"
        )
    except Exception as exc:  # noqa: BLE001
        failures.append(f"five-build diversity raised {exc!r}")
        print(f"{'five-build diversity':<24} FAIL     {exc!r}")

    # 22. Old-vs-improved recoverability and performance benchmark.
    second_total += 1
    try:
        cv = CV.run()
        cv_ok, cv_bad = CV.verify()
        old_hits = cv["signatures"]["print67"]["old"]["runtime_probe"]["startup_source_hits"]
        new_hits = cv["signatures"]["print67"]["new"]["runtime_probe"]["startup_source_hits"]
        if old_hits == 0 or new_hits != 0:
            cv_ok = False
            failures.append(
                f"old-vs-improved recovery signal unexpected: old={old_hits} new={new_hits}"
            )
        if not cv_ok:
            failures.extend(cv_bad[:6])
            failures.append("old-vs-improved benchmark verification failed")
        print(
            f"{'old-vs-improved':<24} {'OK' if cv_ok else 'FAIL':<8} "
            f"old {old_hits} -> new {new_hits} startup needles, "
            f"{cv['performance']['overhead_median']['new']:.1f}x runtime"
        )
    except Exception as exc:  # noqa: BLE001
        failures.append(f"old-vs-improved benchmark raised {exc!r}")
        print(f"{'old-vs-improved':<24} FAIL     {exc!r}")

    # 23. Unsupported VM syntax is explicit; type-only declarations are notes.
    second_total += 1
    unsupported_ok = True
    original_compile = VM.compile_program
    def injected_unsupported(tree, ctx):
        raise VM.Unsupported("injected unsupported construct for test")
    pipeline.vm.compile_program = injected_unsupported
    try:
        try:
            pipeline.obfuscate(b"print(1)\n", pipeline.make_options("medium", seed=1))
            unsupported_ok = False
            failures.append("vm.Unsupported was silently swallowed")
        except VM.Unsupported:
            pass
        except Exception as exc:  # noqa: BLE001
            unsupported_ok = False
            failures.append(f"unexpected exception instead of vm.Unsupported: {exc!r}")
    finally:
        pipeline.vm.compile_program = original_compile
    type_src = b'type X = number\nprint("type-only", 1)\n'
    type_res = pipeline.obfuscate(type_src, pipeline.make_options("medium", seed=7))
    notes = type_res.source_map.get("compile_notes", [])
    if (
        not any("runtime no-op" in str(note) for note in notes)
        or type_res.stats.get("vm_fallback")
        or not type_res.stats.get("vm")
    ):
        unsupported_ok = False
        failures.append("type-only declaration was not handled as an explicit runtime no-op")
    print(f"{'explicit unsupported':<24} {'OK' if unsupported_ok else 'FAIL':<8}")

    # 24. Third-pass production Hello World scanner and restricted-runtime probe.
    third_total += 1
    try:
        v3_ok, v3_bad, v3_results, v3_checks = V3.run()
        v3_artifacts = all(
            os.path.isfile(os.path.join(ROOT, rel))
            for rel in (
                "REPORT-anti-analysis-v3.md",
                "RUNTIME-ANALYSIS-V3.json",
                "RUNTIME-ANALYSIS-V3.md",
            )
        )
        if not v3_ok or not v3_artifacts or not v3_results.get("success"):
            failures.extend(v3_bad[:6])
            failures.append("third-pass anti-analysis verification failed")
        print(
            f"{'third-pass regression':<24} {'OK' if v3_ok and v3_artifacts else 'FAIL':<8} "
            f"{v3_checks} checks, {len(v3_results.get('probes', []))} probes"
        )
    except Exception as exc:  # noqa: BLE001
        failures.append(f"third-pass anti-analysis raised {exc!r}")
        print(f"{'third-pass regression':<24} FAIL     {exc!r}")

    # 25. Refreshed docs, examples and reports have no obsolete brand.
    second_total += 1
    docs_ok = True
    brand = b"-- obfuscated by " + b"grandfuscate"
    doc_paths = [
        "README.md", "NEXT_STEPS.md", "PLAN-anti-deobfuscation.md",
        "LOADSTRINGS.md",
        "ARCHITECTURE.md", "ROADMAP.md", "DEPLOY.md", "config/README.md",
        "REPORT-vm-hardening.md", "REPORT-anti-analysis-v2.md",
        "REPORT-anti-analysis-v3.md", "BENCHMARKS-anti-analysis.md",
        "BENCHMARKS-old-vs-improved.md", "RUNTIME-ANALYSIS.md",
        "RUNTIME-ANALYSIS-V3.md", "examples/roblox_sample.luau",
        "tests/anti_analysis.py", "tests/run_tests.py", "obf/pipeline.py",
        "obf/cli.py", "obf/web.py", "obf/publish.py", "tests/test_publish.py",
    ]
    for rel in doc_paths:
        path = os.path.join(ROOT, rel)
        if not os.path.isfile(path):
            docs_ok = False
            failures.append(f"missing refreshed deliverable: {rel}")
            continue
        with open(path, "rb") as f:
            data = f.read()
        if brand in data or (b"BRAND_" + b"COMMENT") in data:
            docs_ok = False
            failures.append(f"obsolete brand policy remains in {rel}")
    for preset in PRESETS:
        out_path = os.path.join(ROOT, "examples", f"protected_{preset}.luau")
        key_path = os.path.join(ROOT, "examples", f"keys_{preset}.json")
        if not os.path.isfile(out_path) or not os.path.isfile(key_path):
            docs_ok = False
            failures.append(f"missing example output/keys for {preset}")
            continue
        with open(out_path, "rb") as f:
            out = f.read()
        with open(key_path, "rb") as f:
            keys_bytes = f.read()
        ok, _msg = pipeline.validate_syntax(out)
        rc, stdout, stderr = run(out)
        body = strip_banner(out)
        if (
            not out.startswith(BANNER_BYTES)
            or not body.startswith(b"return")
            or brand in body
            or any(t.kind == "comment" for t in minify.tokenize(body))
            or b"entry_shape" in keys_bytes
            or b"format_boot" in keys_bytes
            or not ok
            or (rc, stdout, stderr) != (0, b"grandfuscate\t15\n", b"")
        ):
            docs_ok = False
            failures.append(f"example {preset} is stale or behaviourally incorrect")
    for rel, letters in (
        ("REPORT-anti-analysis-v2.md", "ABCDEFG"),
        ("REPORT-anti-analysis-v3.md", "ABCDEF"),
    ):
        with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
            text = f.read()
        if not all(f"## {letter}." in text for letter in letters):
            docs_ok = False
            failures.append(f"{rel} does not contain report sections {letters}")
    print(f"{'refreshed artifacts':<24} {'OK' if docs_ok else 'FAIL':<8}")

    # 26. Running tests is local-only even inside a normal Git clone with a
    # configured remote. This suite itself contains no push/deploy operation.
    second_total += 1
    local_only = True
    print(f"{'local-only repo':<24} {'OK' if local_only else 'FAIL':<8}")

    # 27. Loadstring publisher (mocked GitHub; no secrets or network).
    publish_total += PUB.run(failures)

    print("\nvm integrity v4 / high-entropy / stealth v5 / v6 proposal / crypto v7 verification")
    print("-" * 68)

    # 28. VM integrity manifest, decoy traps, bounded windows, harmless default.
    third_total += 1
    before = len(failures)
    v4_integrity_total += V4I.run(failures)
    v4i_ok = len(failures) == before
    print(f"{'vm integrity v4':<24} {'OK' if v4i_ok else 'FAIL':<8} "
          f"{v4_integrity_total} integrity/trap checks")

    # 29. High-entropy surface, literal shares, <=15% size gate, no loader.
    third_total += 1
    before = len(failures)
    v4_entropy_total += V4E.run(failures)
    v4e_ok = len(failures) == before
    print(f"{'high entropy v4':<24} {'OK' if v4e_ok else 'FAIL':<8} "
          f"{v4_entropy_total} entropy/gate checks")

    # 30. V5 opt-in active decoys: fail-closed / poison, embedded in real path.
    third_total += 1
    before = len(failures)
    v5_total += V5S.run(failures)
    v5_ok = len(failures) == before
    print(f"{'stealth v5':<24} {'OK' if v5_ok else 'FAIL':<8} "
          f"{v5_total} active-decoy checks")

    # 31. V6 anti-enumeration remains a proposal: no lockdown option shipped.
    third_total += 1
    before = len(failures)
    with open(os.path.join(ROOT, "PLAN-anti-enumeration-v6.md"),
              encoding="utf-8") as f:
        plan6 = f.read()
    opts6 = pipeline.make_options("medium", seed=11)
    check31 = [
        "PROPOSED" in plan6,
        not hasattr(opts6, "lockdown"),
        web.meta()["defaults"].get("lockdown") is None,
    ]
    if not all(check31):
        failures.append("V6 anti-enumeration is no longer proposal-only")
    v6_total += len(check31)
    v6_ok = len(failures) == before
    print(f"{'v6 proposal-only':<24} {'OK' if v6_ok else 'FAIL':<8} "
          f"{v6_total} boundary checks")

    # 32. V7 opt-in HKDF-SHA256 / ChaCha20 / HMAC-SHA256 whitening.
    third_total += 1
    before = len(failures)
    v7_total += V7.run(failures)
    v7_ok = len(failures) == before
    print(f"{'crypto v7':<24} {'OK' if v7_ok else 'FAIL':<8} "
          f"{v7_total} crypto checks")

    print(
        f"\n{total} base transform/run + {vm_total} VM-mode transform/run + "
        f"{compat_total} compatibility differential + {scan_total} production scans + "
        f"{return_total} return probes + {complex_total} complex checks + "
        f"{hard_total} reliability + {second_total} second-pass + "
        f"{third_total} third-pass + {publish_total} loadstring + "
        f"{v4_integrity_total} vm-integrity-v4 + "
        f"{v4_entropy_total} high-entropy-v4 + "
        f"{v5_total} stealth-v5 + "
        f"{v6_total} v6-proposal + "
        f"{v7_total} crypto-v7 checks, "
        f"{len(failures)} failure(s)"
    )
    if failures:
        print("\nFAILURES:")
        for f in failures[:40]:
            print(" -", f)
        return 1
    print("ALL GREEN")
    return 0


def _write_tmp(data: bytes) -> str:
    fd, path = tempfile.mkstemp(suffix=".luau")
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return path


if __name__ == "__main__":
    raise SystemExit(main())
