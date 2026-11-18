"""Anti-analysis scanner, reproducibility checks and hardening benchmarks.

The scanner inspects *production output only*: source identifiers, string
literals, comments, semantic VM labels, fixed library chains, fixed frame /
record fields, fixed checksum constants, debug markers and private source-map
material must not appear. It uses tokenisation where a raw substring could
occur by chance inside an encoded blob.

The benchmark measures output size, Luau process startup time, peak RSS and
runtime overhead with the official Luau 0.747 interpreter. It is a local
engineering measurement, not a red-team or commercial-obfuscator comparison.
"""
from __future__ import annotations

import os
import re
import statistics
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from obf import ast as A  # noqa: E402
from obf import minify  # noqa: E402
from obf import pipeline  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PRESETS = ("light", "medium", "heavy")
# Third-pass ticketed group matrices deliberately add interpreter work. This is
# a gross-regression sanity ceiling, not a performance target or a guarantee.
BENCHMARK_OVERHEAD_BUDGET = 650.0

_KEYWORDS = frozenset(
    """and break do else elseif end false for function if in local nil not or
    repeat return then true until while continue export type typeof""".split()
)
_COMMON_GLOBALS = frozenset(
    """_G getfenv setfenv loadstring load require print warn game workspace script
    Instance task coroutine debug shared Enum Vector3 CFrame UDim2 Color3
    BrickColor TweenInfo Ray Region3 NumberSequence ColorSequence NumberRange
    PhysicalProperties DateTime Random buffer utf8 os io math string table bit32
    tonumber tostring pairs ipairs select rawset rawget rawequal setmetatable
    getmetatable pcall xpcall error assert next unpack pack tick wait spawn delay
    elapsedTime time collectgarbage gcinfo self""".split()
)
_FORBIDDEN_NAMES = frozenset(
    """EVAL EXEC GETLV SETLV NODES CODE KQ DQ Q E B C S O D BAD H G
    APPLYBIN APPLYUN INVOKE DOCALL CMAP SETVAR DECL SNAP CLOSURE VAR
    EH SH BH UH LH GH DEC W NODE ARG op nd fr args vals EH SH BH UH
    source_map PRIVATE_SOURCE_MAP build_id input_sha256 opcodes binmap
    operand_info stream_key_hex DEBUG EVAL EXEC NODES GETLV SETLV
    NODE_N sourceMappingURL PX1""".split()
)
_FORBIDDEN_FIELDS = frozenset(
    """V UP VA n v proto up NODE_N EVAL EXEC GETLV SETLV NODES CODE""".split()
)
_STABLE_CONSTANTS = (b"2166136261", b"16777619", b"4294967295", b"811C9DC5")
_FORBIDDEN_GLOBALS = frozenset(
    """string table math bit32 tonumber pairs error setmetatable getmetatable
    tostring select rawset pcall print warn debug io os loadstring load require""".split()
)
_FORBIDDEN_MEMBER_CHAINS = frozenset(
    {
        ("string", "byte"), ("string", "char"), ("string", "gmatch"),
        ("string", "match"), ("table", "concat"), ("table", "pack"),
        ("table", "unpack"), ("math", "floor"), ("bit32", "bxor"),
        ("bit32", "band"), ("bit32", "bor"),
    }
)


def _sig(data: bytes) -> list[minify.Tok]:
    return [t for t in minify.tokenize(data) if t.kind not in ("ws", "comment")]


def first_token(data: bytes) -> str:
    for t in _sig(data):
        return t.text.decode("latin-1")
    return ""


def top_level_locals(data: bytes) -> int:
    depth = 0
    count = 0
    for t in _sig(data):
        if t.text in (b"(", b"{", b"["):
            depth += 1
        elif t.text in (b")", b"}", b"]"):
            depth = max(0, depth - 1)
        elif t.kind == "name" and t.text == b"local" and depth == 0:
            count += 1
    return count


def _source_fragments(source: bytes) -> list[bytes]:
    text = source.decode("utf-8", "replace")
    out: set[bytes] = set()
    for match in re.finditer(r"\b[A-Za-z_][A-Za-z0-9_]*\b", text):
        word = match.group(0)
        if len(word) >= 8 and word not in _KEYWORDS and word not in _COMMON_GLOBALS:
            out.add(word.encode("utf-8"))
    for pattern in (r'"([^"\\\n]{4,})"', r"'([^'\\\n]{4,})'"):
        for value in re.findall(pattern, text):
            out.add(value.encode("utf-8"))
    for value in re.findall(r"--\s*([A-Za-z0-9_]{6,})", text):
        out.add(value.encode("utf-8"))
    return sorted(out)


def scan_output(
    source: bytes,
    output: bytes,
    keys: dict,
    source_map: dict | None = None,
) -> list[str]:
    """Return a list of findings; empty means the production chunk is clean."""
    bad: list[str] = []

    def need(condition: bool, message: str) -> None:
        if not condition:
            bad.append(message)

    need(output.startswith(b"return"), "output does not start with return at byte zero")
    comments = [t for t in minify.tokenize(output) if t.kind == "comment"]
    need(not comments, f"production output contains {len(comments)} comment(s)")
    need(first_token(output) == "return", "first code token is not return")
    need(top_level_locals(output) == 0, "top-level local declaration found")
    need(output.count(b"\n") == 1, "output is not one code line + trailing newline")

    sig = _sig(output)
    names = [t.text.decode("latin-1") for t in sig if t.kind == "name"]
    forbidden = sorted(set(names) & _FORBIDDEN_NAMES)
    need(not forbidden, f"semantic VM names remain: {forbidden[:12]}")
    field_hits: set[str] = set()
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
            and sig[i + 1].text.decode("latin-1") in _FORBIDDEN_FIELDS
        ):
            field_hits.add(sig[i + 1].text.decode("latin-1"))
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
            field_hits.add(t.text.decode("latin-1"))
    need(not field_hits, f"stable VM/frame field names remain: {sorted(field_hits)}")
    stable = [c.decode("ascii") for c in _STABLE_CONSTANTS if c in output]
    need(not stable, f"fixed checksum constants remain: {stable}")
    hard_keys: set[str] = set()
    for i in range(len(sig) - 2):
        if (
            sig[i].text == b"["
            and sig[i + 1].kind == "string"
            and sig[i + 2].text == b"]"
        ):
            raw = sig[i + 1].text.decode("latin-1").strip("\"'")
            if raw in _FORBIDDEN_FIELDS:
                hard_keys.add(raw)
    need(not hard_keys, f"hard-coded global/frame key lookups remain: {sorted(hard_keys)}")
    need(
        not any(n.startswith("__p") for n in names),
        "predictable __p helper prefix remains",
    )

    forbidden_globals = sorted(set(names) & _FORBIDDEN_GLOBALS)
    need(not forbidden_globals, f"plaintext library/global names remain: {forbidden_globals[:12]}")
    for allowed in ("getfenv", "type", "_G"):
        need(names.count(allowed) <= 2, f"too many direct {allowed} references")

    for i in range(len(sig) - 2):
        if (
            sig[i].kind == "name"
            and sig[i + 1].text == b"."
            and sig[i + 2].kind == "name"
        ):
            pair = (
                sig[i].text.decode("latin-1"),
                sig[i + 2].text.decode("latin-1"),
            )
            need(
                pair not in _FORBIDDEN_MEMBER_CHAINS,
                f"fixed library chain remains: {pair[0]}.{pair[1]}",
            )
        if (
            sig[i].kind == "name"
            and sig[i].text in (b"loadstring", b"load", b"require")
        ):
            need(False, f"dynamic loader name remains: {sig[i].text.decode('latin-1')}")

    # No central `if op == <number>` dispatch chain.
    dispatch: dict[str, int] = defaultdict(int)
    for i in range(len(sig) - 3):
        if (
            sig[i].text in (b"if", b"elseif")
            and sig[i + 1].kind == "name"
            and sig[i + 2].text == b"=="
            and sig[i + 3].kind == "number"
        ):
            dispatch[sig[i + 1].text.decode("latin-1")] += 1
    need(
        not any(v > 4 for v in dispatch.values()),
        f"central numeric dispatch chain remains: {dict(dispatch)}",
    )
    need(
        "op" not in dispatch,
        "central op == opcode dispatch remains",
    )

    # No obvious small-numbered instruction table of function handlers and no
    # local one-argument decoder that simply forwards into one central table.
    raw_text = text if "text" in locals() else output.decode("latin-1")
    small_groups: dict[str, int] = {}
    for m in re.finditer(
        r"([A-Za-z_][A-Za-z0-9_]*)\[(\d+)\](?:\[(\d+)\])?"
        r"\s*=\s*function\(([^)]*)\)",
        raw_text,
    ):
        table, outer, inner, params = (
            m.group(1), int(m.group(2)), m.group(3), m.group(4)
        )
        # Ticketed decoder groups take a capability argument; classic opcode
        # handlers stored under consecutive small keys do not.
        if (
            outer <= 64
            and (inner is None or int(inner) <= 64)
            and len([p for p in params.split(",") if p.strip()]) <= 1
        ):
            small_groups[table] = small_groups.get(table, 0) + 1
    need(
        not any(v >= 4 for v in small_groups.values()),
        f"obvious small-keyed instruction handler table remains: {small_groups}",
    )
    local_lookup_decoders = re.findall(
        r"local\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*function\(\s*"
        r"([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*return\s+"
        r"[A-Za-z_][A-Za-z0-9_]*\[\s*\1\s*\]",
        raw_text,
    )
    need(
        not local_lookup_decoders,
        f"single obvious table-lookup decoder remains: {len(local_lookup_decoders)}",
    )

    # No readable sequential opcode table or long run of tiny constants.
    text = output.decode("latin-1")
    need(
        re.search(r"=\{1,2,3,4,5,6,7,8", text) is None,
        "sequential small-integer opcode table remains",
    )
    run = 0
    longest = 0
    for t in sig:
        if t.kind == "number" and t.text.isdigit() and 0 <= int(t.text) <= 42:
            run += 1
            longest = max(longest, run)
        else:
            run = 0
    need(longest < 12, f"long small-number run remains ({longest} values)")
    plain_quoted = re.findall(r'"([A-Za-z0-9_ ]{8,})"', text)
    need(len(plain_quoted) < 8, "centralized plain decoded-string table remains")
    central_string_tables = 0
    for m in re.finditer(r"\{([^{}]{0,5000})\}", text):
        if len(re.findall(r'"[A-Za-z0-9_ ]{4,}"', m.group(1))) >= 8:
            central_string_tables += 1
    need(
        central_string_tables == 0,
        f"centralized plain string table remains: {central_string_tables}",
    )

    # Source identifiers, strings and comments must not survive as plaintext.
    for fragment in _source_fragments(source):
        need(fragment not in output, f"plaintext source fragment remains: {fragment[:48]!r}")

    # No debug output or private key/source-map material in the chunk.
    debug_names = {
        "source_map", "PRIVATE_SOURCE_MAP", "build_id", "input_sha256",
        "opcodes", "binmap", "operand_info", "stream_key_hex", "DEBUG",
        "__GRANDFUSCATE_PRIVATE_SOURCE_MAP_V3__",
    }
    need(
        not (set(names) & debug_names),
        f"debug/source-map marker remains: {sorted(set(names) & debug_names)}",
    )
    need(b"source_map" not in output, "source_map marker remains in output")
    need(b"__GRANDFUSCATE_PRIVATE_SOURCE_MAP" not in output, "private source-map marker remains in output")
    need(b"sourceMappingURL" not in output, "accidental source-map URL remains in output")
    need(b"PX1" not in output, "recognizable provenance metadata remains in output")
    need(b"build_id" not in output, "build identifier remains in production output")

    if source_map is not None:
        need(
            source_map.get("marker") == "__GRANDFUSCATE_PRIVATE_SOURCE_MAP_V3__",
            "private source map has wrong marker",
        )
        need(len(source_map.get("nodes", [])) > 0, "private source map has no nodes")
        need(len(source_map.get("constants", [])) > 0, "private source map has no constants")
        need("source_map" not in keys, "private source map is embedded in public keys")
        need(
            "runtime_layout" not in keys and "operand_encoding" not in keys
            and "control_flow" not in keys,
            "private layout/operand/control-flow details leaked into public keys",
        )
        need(
            source_map.get("entry_layout") in range(5)
            and source_map.get("boot_layout") in range(4),
            "private source map lacks opaque entry/boot layout IDs",
        )
        need(
            all(
                key in source_map
                for key in (
                    "runtime_layout", "field_keys", "pool_chunk_plans",
                    "vm_chunk_plans", "control_flow", "compile_notes",
                    "operand", "third_pass",
                )
            ),
            "private source map lacks second-pass layout metadata",
        )
        need(
            len(source_map.get("pool_chunk_plans", [])) > 0
            and len(source_map.get("vm_chunk_plans", [])) > 0,
            "private source map lacks lazy chunk plans",
        )
        third = source_map.get("third_pass", {})
        need(
            third.get("bank_count", 0) >= 2
            and third.get("constant_groups", 0) >= 3
            and third.get("byte_groups", 0) >= 3
            and "structural_digest" in third
            and "third_pass" not in keys,
            "private source map lacks third-pass structural metadata",
        )
        for secret in (
            source_map.get("marker", ""),
            source_map.get("input_sha256", ""),
            keys.get("source_map_sha256", ""),
        ):
            need(
                bool(secret) and secret.encode("utf-8") not in output,
                "private source-map identifier is present in production output",
            )
        for node in source_map.get("nodes", []):
            excerpt = node.get("excerpt")
            if excerpt and ("GRANDFUSCATE_SECRET" in excerpt or "SOURCE_STRING_NEVER_SHIP" in excerpt):
                need(
                    excerpt.encode("utf-8") not in output,
                    "private source-map excerpt is present in production output",
                )
    return bad


def reproducibility(source: bytes, seed: int = 0x5EED) -> tuple[bool, list[str]]:
    """Same seed -> identical build; different seed -> different VM layout."""
    bad: list[str] = []
    a = pipeline.obfuscate(source, pipeline.make_options("medium", seed=seed))
    b = pipeline.obfuscate(source, pipeline.make_options("medium", seed=seed))
    c = pipeline.obfuscate(source, pipeline.make_options("medium", seed=seed + 1))

    def public_keys(r) -> dict:
        return {k: v for k, v in r.keys.items() if k != "created"}

    if a.output != b.output:
        bad.append("same seed produced different output bytes")
    if public_keys(a) != public_keys(b):
        bad.append("same seed produced different public keys")
    if a.source_map != b.source_map:
        bad.append("same seed produced different private source map")
    if a.stats != b.stats:
        bad.append("same seed produced different stats")
    if a.output == c.output:
        bad.append("different seed produced identical output")
    if a.source_map.get("opcodes") == c.source_map.get("opcodes"):
        bad.append("different seed reused opcode values")
    if a.source_map.get("operand") == c.source_map.get("operand"):
        bad.append("different seed reused operand layout")
    return not bad, bad


# --------------------------------------------------------------------------
# benchmarks
# --------------------------------------------------------------------------
def _write_tmp(data: bytes) -> str:
    fd, path = tempfile.mkstemp(suffix=".luau")
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return path


def run_luau(data: bytes, timeout: int = 120) -> tuple[int, bytes, bytes]:
    path = _write_tmp(data)
    try:
        p = subprocess.run(
            [A.tool_path("luau"), path], capture_output=True, timeout=timeout
        )
        return p.returncode, p.stdout, p.stderr
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _run_rusage(data: bytes, timeout: int = 120) -> tuple[float, int, int]:
    """Return (seconds, peak RSS KiB, exit status) for one fresh Luau process."""
    path = _write_tmp(data)
    devnull = os.open(os.devnull, os.O_WRONLY)
    try:
        exe = A.tool_path("luau")
        file_actions = [
            (os.POSIX_SPAWN_DUP2, devnull, 1),
            (os.POSIX_SPAWN_DUP2, devnull, 2),
        ]
        t0 = time.perf_counter()
        # posix_spawn avoids copying this Python process's pages into the
        # measured child, so ru_maxrss reflects the Luau process itself.
        pid = os.posix_spawn(exe, [exe, path], os.environ, file_actions=file_actions)
        _, status, usage = os.wait4(pid, 0)
        elapsed = time.perf_counter() - t0
        return elapsed, usage.ru_maxrss, os.waitstatus_to_exitcode(status)
    finally:
        os.close(devnull)
        try:
            os.unlink(path)
        except OSError:
            pass


def _measure(data: bytes, repeats: int = 3) -> dict:
    times: list[float] = []
    rss: list[int] = []
    for _ in range(repeats):
        t, mem, rc = _run_rusage(data)
        if rc != 0:
            raise RuntimeError(f"benchmark process exited {rc}")
        times.append(t)
        rss.append(mem)
    return {
        "seconds_min": min(times),
        "seconds_median": statistics.median(times),
        "rss_kib_max": max(rss),
        "rss_kib_median": statistics.median(rss),
    }


def benchmark() -> dict:
    startup_src = b"local x = 1\n"
    workload_src = open(os.path.join(HERE, "bench_runtime.luau"), "rb").read()
    size_src = open(os.path.join(HERE, "scan_fixture.luau"), "rb").read()
    seed = 20261118

    sizes = {}
    startup = {}
    for preset in PRESETS:
        r = pipeline.obfuscate(size_src, pipeline.make_options(preset, seed=seed))
        sizes[preset] = len(r.output)
        startup[preset] = _measure(
            pipeline.obfuscate(startup_src, pipeline.make_options(preset, seed=seed)).output
        )

    original_startup = _measure(startup_src)
    heavy = pipeline.obfuscate(workload_src, pipeline.make_options("heavy", seed=seed))
    original_runtime = _measure(workload_src)
    heavy_runtime = _measure(heavy.output)

    build_start = time.perf_counter()
    pipeline.obfuscate(workload_src, pipeline.make_options("heavy", seed=seed))
    build_ms = (time.perf_counter() - build_start) * 1000

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "toolchain": "official Luau 0.747 (tools/luau)",
        "repeats": 3,
        "input_size_bytes": len(size_src),
        "output_size_bytes": sizes,
        "startup": {"original": original_startup, **startup},
        "runtime": {
            "original": original_runtime,
            "heavy": heavy_runtime,
            "overhead_median": heavy_runtime["seconds_median"] / max(original_runtime["seconds_median"], 1e-9),
        },
        "build_ms_heavy": build_ms,
        "workload": "tests/bench_runtime.luau (5,000 loop iterations)",
    }


def write_benchmark_markdown(results: dict, path: str | None = None) -> str:
    path = path or os.path.join(ROOT, "BENCHMARKS-anti-analysis.md")
    sizes = results["output_size_bytes"]
    st = results["startup"]
    rt = results["runtime"]
    lines = [
        "# Anti-analysis benchmarks",
        "",
        f"Measured {results['timestamp']} with {results['toolchain']}.",
        "Three process launches per measurement; min/median wall time and max/median peak RSS (`ru_maxrss`).",
        "RSS includes the interpreter's allocator baseline and can vary with process placement; small differences are not meaningful. Local engineering measurement only.",
        "",
        "## Output size",
        "",
        f"Input fixture: `tests/scan_fixture.luau` ({results['input_size_bytes']} B).",
        "",
        "| Preset | Output bytes | Expansion |",
        "|---|---:|---:|",
    ]
    for p in PRESETS:
        lines.append(f"| {p} | {sizes[p]:,} | {sizes[p] / max(1, results['input_size_bytes']):.1f}x |")
    lines += [
        "",
        "## Startup (no-op script: `local x = 1`)",
        "",
        "| Build | Min ms | Median ms | Max RSS KiB | Median RSS KiB |",
        "|---|---:|---:|---:|---:|",
    ]
    for label, data in st.items():
        lines.append(
            f"| {label} | {data['seconds_min']*1000:.2f} | {data['seconds_median']*1000:.2f} | "
            f"{data['rss_kib_max']:,} | {data['rss_kib_median']:,.0f} |"
        )
    lines += [
        "",
        "## Runtime overhead",
        "",
        f"Workload: `{results['workload']}`. Heavy build generation took {results['build_ms_heavy']:.1f} ms.",
        "",
        "| Build | Min ms | Median ms | Max RSS KiB | Median RSS KiB |",
        "|---|---:|---:|---:|---:|",
    ]
    for label, data in rt.items():
        if isinstance(data, dict):
            lines.append(
                f"| {label} | {data['seconds_min']*1000:.2f} | {data['seconds_median']*1000:.2f} | "
                f"{data['rss_kib_max']:,} | {data['rss_kib_median']:,.0f} |"
            )
    lines += [
        "",
        f"Median runtime overhead: **{rt['overhead_median']:.2f}x** original.",
        "",
        f"Third-pass distributed ticketed decoders and per-build group matrices "
        f"add interpreter work; the suite uses a {BENCHMARK_OVERHEAD_BUDGET:.0f}x "
        "gross-regression ceiling rather than the earlier single-router budget.",
        "",
        "These numbers measure this local toolchain and workload. They are not a comparison with Luraph, LuaProtect, or any deobfuscator, and they are not a security proof.",
        "",
    ]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return path
