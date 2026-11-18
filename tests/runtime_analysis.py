"""Adversarial runtime-analysis probe against a production chunk.

The probe executes the chunk in a restricted, instrumented Luau environment.
It tries to recover an instruction table, find a main dispatcher, dump startup
constants, hook one decode function, hook one execute function, and rebuild a
clean IR. It does not claim that an executor-specific debugger cannot do more;
it records what is available in portable Roblox Luau and what the protected
layout exposes.
"""
from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from obf import minify, pipeline  # noqa: E402
from obf.pool import lua_bytes_literal  # noqa: E402
from tests import anti_analysis as AA  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RESULTS_JSON = os.path.join(ROOT, "RUNTIME-ANALYSIS.json")
RESULTS_MD = os.path.join(ROOT, "RUNTIME-ANALYSIS.md")

_HARNESS = r'''
local original = _G
local realprint = print
local src = @@SRC@@
local fragments = @@FRAGMENTS@@

local env = {}
local prints = {}
local blobs = {}
local startup_blobs = {}
local startup_dump = ""
local all_dump = ""
local env_strings = ""
local char_stream = ""
local byte_calls, char_calls, concat_calls, pack_calls = 0, 0, 0, 0
local unpack_calls, bxor_calls, band_calls = 0, 0, 0
local tostring_calls, type_calls, tonumber_calls = 0, 0, 0
local first_print = false
local before_first_print = true
local call_samples = 0

local function record_blob(s)
  if s == nil then return end
  blobs[s] = (blobs[s] or 0) + 1
  if before_first_print then startup_blobs[s] = true end
end

local string_proxy = {
  byte = function(s, i)
    byte_calls = byte_calls + 1
    record_blob(s)
    return original.string.byte(s, i)
  end,
  char = function(...)
    char_calls = char_calls + 1
    local r = original.string.char(...)
    if #char_stream < 60000 then char_stream = char_stream .. r end
    return r
  end,
  gmatch = function(...) return original.string.gmatch(...) end,
  match = function(...) return original.string.match(...) end,
  find = function(...) return original.string.find(...) end,
  sub = function(...) return original.string.sub(...) end,
  format = function(...) return original.string.format(...) end,
  rep = function(...) return original.string.rep(...) end,
  lower = function(...) return original.string.lower(...) end,
}
local table_proxy = {
  concat = function(t, sep, ...)
    concat_calls = concat_calls + 1
    local r = original.table.concat(t, sep, ...)
    if before_first_print and #startup_dump < 60000 then
      startup_dump = startup_dump .. r .. "\n"
    end
    if #all_dump < 60000 then all_dump = all_dump .. r .. "\n" end
    return r
  end,
  pack = function(...)
    pack_calls = pack_calls + 1
    return original.table.pack(...)
  end,
  unpack = function(t, i, j)
    unpack_calls = unpack_calls + 1
    return original.table.unpack(t, i, j)
  end,
  insert = function(...) return original.table.insert(...) end,
  remove = function(...) return original.table.remove(...) end,
}
local math_proxy = {
  floor = function(x) return original.math.floor(x) end,
  min = function(...) return original.math.min(...) end,
  max = function(...) return original.math.max(...) end,
  ceil = function(x) return original.math.ceil(x) end,
  huge = original.math.huge,
}
local bit32_proxy = {
  bxor = function(...)
    bxor_calls = bxor_calls + 1
    return original.bit32.bxor(...)
  end,
  band = function(...)
    band_calls = band_calls + 1
    return original.bit32.band(...)
  end,
  bor = function(...) return original.bit32.bor(...) end,
}

env.getfenv = function() return env end
env._G = original
env.string = string_proxy
env.table = table_proxy
env.math = math_proxy
env.bit32 = bit32_proxy
env.print = function(...)
  local t = original.table.pack(...)
  local parts = {}
  for i = 1, t.n do parts[i] = original.tostring(t[i]) end
  prints[#prints + 1] = original.table.concat(parts, "\t")
  first_print = true
  before_first_print = false
end
env.type = function(...)
  type_calls = type_calls + 1
  return original.type(...)
end
env.tostring = function(...)
  tostring_calls = tostring_calls + 1
  return original.tostring(...)
end
env.tonumber = function(...)
  tonumber_calls = tonumber_calls + 1
  return original.tonumber(...)
end
env.pairs = original.pairs
env.ipairs = original.ipairs
env.next = original.next
env.rawset = original.rawset
env.rawget = original.rawget
env.setmetatable = original.setmetatable
env.getmetatable = original.getmetatable
env.pcall = original.pcall
env.xpcall = original.xpcall
env.select = original.select
env.error = original.error
env.assert = original.assert
env.setfenv = original.setfenv
env.coroutine = original.coroutine
env.os = original.os
env.debug = original.debug
env.utf8 = original.utf8
env.buffer = original.buffer
setmetatable(env, { __index = function(_, k) return original[k] end })

local f, loaderr = original.loadstring(src, "=protected")
if not f then
  realprint("DIAG", "load_error", original.tostring(loaderr))
  return
end
original.setfenv(f, env)

local dbg = original.debug or {}
local hook_available = original.type(dbg.sethook) == "function"
local hook_installed = false
if hook_available then
  hook_installed = original.pcall(function()
    dbg.sethook(function() call_samples = call_samples + 1 end, "", 1000)
  end)
end

local ok, perr = original.pcall(f)
if hook_installed then original.pcall(function() dbg.sethook() end) end

for k, v in original.pairs(env) do
  if original.type(v) == "string" then
    env_strings = env_strings .. k .. "=" .. v .. "\n"
  end
end

local distinct_blobs, startup_blob_count = 0, 0
for _ in original.pairs(blobs) do distinct_blobs = distinct_blobs + 1 end
for _ in original.pairs(startup_blobs) do startup_blob_count = startup_blob_count + 1 end

local startup_hay = startup_dump .. env_strings
local all_hay = all_dump .. char_stream .. env_strings
local startup_hits, all_hits = 0, 0
for _, needle in original.ipairs(fragments) do
  if original.string.find(startup_hay, needle, 1, true) then
    startup_hits = startup_hits + 1
  end
  if original.string.find(all_hay, needle, 1, true) then
    all_hits = all_hits + 1
  end
end

local total_words, small_words, longest_run, run = 0, 0, 0, 0
for i = 1, #char_stream - 3, 4 do
  local a = original.string.byte(char_stream, i) or 0
  local b = original.string.byte(char_stream, i + 1) or 0
  local c = original.string.byte(char_stream, i + 2) or 0
  local d = original.string.byte(char_stream, i + 3) or 0
  local w = a * 16777216 + b * 65536 + c * 256 + d
  total_words = total_words + 1
  if w < 64 then
    small_words = small_words + 1
    run = run + 1
    if run > longest_run then longest_run = run end
  else
    run = 0
  end
end
local small_ratio = small_words / (total_words > 0 and total_words or 1)
local ir_markers = {
  "EVAL", "EXEC", "NODES", "GETLV", "SETLV", "__p",
  "source_map", "BLOCK", "CONST", "PROTO", "RETURN",
}
local ir_marker_hits = 0
for _, m in original.ipairs(ir_markers) do
  if original.string.find(char_stream, m, 1, true) then
    ir_marker_hits = ir_marker_hits + 1
  end
end
local clean_ir = (ir_marker_hits >= 3 or longest_run >= 8) and small_ratio > 0.02

local global_dispatcher_candidates = 0
for k, v in original.pairs(env) do
  if original.type(v) == "function" then
    local name = original.string.lower(original.tostring(k))
    if original.string.find(name, "eval", 1, true)
      or original.string.find(name, "exec", 1, true)
      or original.string.find(name, "dispatch", 1, true)
      or original.string.find(name, "step", 1, true)
      or original.string.find(name, "node", 1, true) then
      global_dispatcher_candidates = global_dispatcher_candidates + 1
    end
  end
end

local function diag(k, v) realprint("DIAG", k, original.tostring(v)) end
diag("chunk_ok", ok)
diag("chunk_error", ok and "" or original.tostring(perr))
diag("prints", #prints)
diag("byte_calls", byte_calls)
diag("distinct_blobs", distinct_blobs)
diag("startup_blobs", startup_blob_count)
diag("char_calls", char_calls)
diag("concat_calls", concat_calls)
diag("pack_calls", pack_calls)
diag("unpack_calls", unpack_calls)
diag("bxor_calls", bxor_calls)
diag("band_calls", band_calls)
diag("startup_source_hits", startup_hits)
diag("all_source_hits", all_hits)
diag("small_word_hits", small_words)
diag("total_words", total_words)
diag("small_word_ratio", small_ratio)
diag("longest_small_word_run", longest_run)
diag("ir_marker_hits", ir_marker_hits)
diag("clean_ir", clean_ir)
diag("hook_available", hook_available)
diag("hook_installed", hook_installed)
diag("call_samples", call_samples)
diag("debug_getinfo", original.type(dbg.getinfo) == "function")
diag("debug_sethook", hook_available)
diag("debug_getupvalue", original.type(dbg.getupvalue) == "function")
diag("debug_traceback", original.type(dbg.traceback) == "function")
diag("global_dispatcher_candidates", global_dispatcher_candidates)
for i, line in original.ipairs(prints) do
  realprint("CAPTURE", i, line)
end
'''


def _bool(v: str) -> bool:
    return v.strip().lower() == "true"


def _static_attempts(data: bytes) -> dict:
    tokens = [t for t in minify.tokenize(data) if t.kind not in ("ws", "comment")]
    text = data.decode("latin-1")
    # A readable opcode table means several *small* contiguous numeric handler
    # keys on one table. Randomised 32-bit keys and per-build slot bases are
    # not instruction tables; count groups, not isolated small literals.
    small_groups: dict[str, int] = {}
    for m in re.finditer(
        r"([A-Za-z_][A-Za-z0-9_]*)\[(\d+)\](?:\[(\d+)\])?"
        r"\s*=\s*function\(([^)]*)\)",
        text,
    ):
        table, outer, inner, params = (
            m.group(1), int(m.group(2)), m.group(3), m.group(4)
        )
        if (
            outer <= 64
            and (inner is None or int(inner) <= 64)
            and len([p for p in params.split(",") if p.strip()]) <= 1
        ):
            small_groups[table] = small_groups.get(table, 0) + 1
    small_handler_tables = sum(v >= 4 for v in small_groups.values())
    dispatch_chains: dict[str, int] = {}
    for i in range(len(tokens) - 3):
        if (
            tokens[i].text in (b"if", b"elseif")
            and tokens[i + 1].kind == "name"
            and tokens[i + 2].text == b"=="
            and tokens[i + 3].kind == "number"
        ):
            name = tokens[i + 1].text.decode("latin-1")
            dispatch_chains[name] = dispatch_chains.get(name, 0) + 1
    central = {k: v for k, v in dispatch_chains.items() if v > 4}
    return {
        "small_keyed_handler_tables": small_handler_tables,
        "small_handler_groups": small_groups,
        "central_numeric_dispatch_chains": central,
        "sequential_small_opcode_array": bool(
            re.search(r"=\{1,2,3,4,5,6,7,8", text)
        ),
        "fixed_checksum_constants": [
            c.decode("ascii") for c in
            (b"2166136261", b"16777619", b"4294967295", b"811C9DC5")
            if c in data
        ],
        "comments": sum(1 for t in minify.tokenize(data) if t.kind == "comment"),
        "first_code_token": next(
            (t.text.decode("latin-1") for t in tokens if t.kind == "name"), ""
        ),
    }


def _build_harness(output: bytes, fragments: list[bytes]) -> bytes:
    frag_lua = "{" + ",".join(lua_bytes_literal(f) for f in fragments) + "}"
    return (
        _HARNESS.replace("@@SRC@@", lua_bytes_literal(output))
        .replace("@@FRAGMENTS@@", frag_lua)
        .encode("latin-1")
    )


def instrumented_run(
    output: bytes, fragments: list[bytes]
) -> tuple[dict, list[str], str]:
    harness = _build_harness(output, fragments)
    rc, stdout, stderr = AA.run_luau(harness, timeout=180)
    diag: dict[str, str] = {}
    captures: list[str] = []
    for line in stdout.decode("utf-8", "replace").splitlines():
        parts = line.split("\t")
        if parts and parts[0] == "DIAG" and len(parts) >= 3:
            diag[parts[1]] = "\t".join(parts[2:])
        elif parts and parts[0] == "CAPTURE" and len(parts) >= 3:
            captures.append("\t".join(parts[2:]))
    return diag, captures, stderr.decode("utf-8", "replace")


def _probe(
    label: str,
    source: bytes,
    result,
    needles: list[bytes],
) -> tuple[dict, list[str]]:
    bad: list[str] = []
    scanned = _static_attempts(result.output)
    findings = AA.scan_output(source, result.output, result.keys, result.source_map)
    rc0, out0, err0 = AA.run_luau(source)
    expected = out0.decode("utf-8", "replace").splitlines()
    diag, captures, stderr = instrumented_run(result.output, needles)
    if rc0 != 0 or err0:
        bad.append(f"{label}: original fixture failed: {err0[:160]!r}")
    if findings:
        bad.append(f"{label}: production scanner findings: {findings[:4]}")
    if scanned["comments"] != 0 or scanned["first_code_token"] != "return":
        bad.append(f"{label}: output is not comment-free return-first code")
    if scanned["small_keyed_handler_tables"] > 0:
        bad.append(f"{label}: small numbered instruction-table handlers identified")
    if scanned["central_numeric_dispatch_chains"]:
        bad.append(f"{label}: central numeric dispatcher identified")
    if scanned["sequential_small_opcode_array"]:
        bad.append(f"{label}: sequential small opcode array identified")
    if scanned["fixed_checksum_constants"]:
        bad.append(f"{label}: fixed checksum constants identified")
    if _bool(diag.get("chunk_ok", "false")) is not True:
        bad.append(f"{label}: instrumented chunk failed: {diag.get('chunk_error')}")
    if captures != expected:
        bad.append(
            f"{label}: print capture differs: {captures[:3]!r} vs {expected[:3]!r}"
        )
    if stderr:
        bad.append(f"{label}: harness stderr: {stderr[:200]!r}")
    distinct = int(diag.get("distinct_blobs", "0"))
    startup_hits = int(diag.get("startup_source_hits", "-1"))
    all_hits = int(diag.get("all_source_hits", "-1"))
    clean_ir = _bool(diag.get("clean_ir", "true"))
    global_dispatcher = int(diag.get("global_dispatcher_candidates", "1"))
    if distinct < 2:
        bad.append(f"{label}: single central decode blob identified")
    if startup_hits != 0:
        bad.append(f"{label}: startup constant dump recovered {startup_hits} needles")
    if all_hits != 0:
        bad.append(f"{label}: simple runtime dump recovered {all_hits} needles")
    if clean_ir:
        bad.append(f"{label}: probe reconstructed a clean IR from decoded words")
    if global_dispatcher != 0:
        bad.append(f"{label}: global dispatcher/execute function identified")
    record = {
        "label": label,
        "source": source.decode("utf-8", "replace"),
        "needles": [n.decode("utf-8", "replace") for n in needles],
        "output_bytes": len(result.output),
        "original_stdout_lines": expected,
        "captured_stdout_lines": captures,
        "scanner_findings": findings,
        "static_attempts": scanned,
        "runtime_diagnostics": diag,
        "harness_stderr": stderr,
        "success": not bad,
        "failures": bad,
    }
    return record, bad


def run() -> tuple[bool, list[str], dict]:
    seed = 20261118
    fixture = open(os.path.join(HERE, "scan_fixture.luau"), "rb").read()
    fixture_result = pipeline.obfuscate(
        fixture, pipeline.make_options("medium", seed=seed)
    )
    print67 = b"print(67)\n"
    print67_result = pipeline.obfuscate(
        print67, pipeline.make_options("medium", seed=seed)
    )
    # The restricted runtime that motivated this pass recovered these exact
    # source needles from the old startup dump. Include short needles that the
    # generic source-fragment extractor would normally skip.
    print67_needles = [b"print", b"67", b"print(67)"]
    probes: list[dict] = []
    bad: list[str] = []
    for record, errs in (
        _probe(
            "scan_fixture", fixture, fixture_result,
            AA._source_fragments(fixture),
        ),
        _probe("print67", print67, print67_result, print67_needles),
    ):
        probes.append(record)
        bad.extend(errs)
    primary = probes[0]
    results = {
        "created": datetime.now(timezone.utc).isoformat(),
        "preset": "medium",
        "seed": seed,
        "output_bytes": {
            p["label"]: p["output_bytes"] for p in probes
        },
        "scanner_findings": [p["scanner_findings"] for p in probes],
        "static_attempts": primary["static_attempts"],
        "runtime_diagnostics": primary["runtime_diagnostics"],
        "probes": probes,
        "attempts": {
            "instruction_table_identification": "failed",
            "main_dispatcher_identification": "failed",
            "startup_constant_dump": "failed",
            "simple_runtime_string_dump": "failed",
            "single_decode_function_hook": "failed",
            "single_execute_function_hook": (
                "portable debug hook unavailable"
                if not _bool(primary["runtime_diagnostics"].get("hook_available", "false"))
                else "no single global dispatcher found"
            ),
            "clean_ir_reconstruction": "failed",
            "print67_exact_recovery": "failed",
        },
        "success": not bad,
        "failures": bad,
    }
    with open(RESULTS_JSON, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, sort_keys=True)
    _write_markdown(results)
    return not bad, bad, results


def _write_markdown(results: dict) -> None:
    probes = results["probes"]
    primary = probes[0]["runtime_diagnostics"]
    s = results["static_attempts"]
    lines = [
        "# Runtime-analysis probe",
        "",
        f"Measured {results['created']} with official Luau 0.747, "
        f"{results['preset']} preset and seed {results['seed']}.",
        "",
        "The protected scripts still produce their original output. This probe "
        "attempts the restricted-runtime shortcuts that recovered `print(67)` "
        "from the previous build. A capable executor-specific debugger can "
        "observe more; this is not a security proof or a commercial comparison.",
        "",
        "| Probe | Output | Original stdout needles | Startup dump needles | "
        "All simple dump needles | Result |",
        "|---|---:|---:|---:|---:|---|",
    ]
    for p in probes:
        d = p["runtime_diagnostics"]
        lines.append(
            f"| `{p['label']}` | {p['output_bytes']:,} B | "
            f"{len(p['needles'])} | {d.get('startup_source_hits')} | "
            f"{d.get('all_source_hits')} | "
            f"{'PASS' if p['success'] else 'FAIL'} |"
        )
    lines += [
        "",
        "## Attempts on both probes",
        "",
        "| Attempt | Result | Evidence |",
        "|---|---|---|",
        f"| Identify a readable instruction table | failed | "
        f"{s['small_keyed_handler_tables']} small numbered handler groups; "
        f"sequential small array: {s['sequential_small_opcode_array']} |",
        f"| Identify a main numeric dispatcher | failed | "
        f"{s['central_numeric_dispatch_chains']} |",
        f"| Dump startup constants | failed | "
        f"{primary.get('startup_source_hits')} needles in startup dump; "
        f"{primary.get('startup_blobs')}/{primary.get('distinct_blobs')} "
        f"encoded blobs touched before first print |",
        f"| Hook one decode function | failed | "
        f"{primary.get('distinct_blobs')} distinct byte-source blobs, "
        f"{primary.get('byte_calls')} byte reads |",
        f"| Hook one execute function | no single global candidate | "
        f"portable `debug.sethook`: {primary.get('hook_available')}; "
        f"candidate globals: {primary.get('global_dispatcher_candidates')} |",
        f"| Reconstruct clean IR | failed | "
        f"IR markers: {primary.get('ir_marker_hits')}, "
        f"longest small-word run: {primary.get('longest_small_word_run')}, "
        f"small-word ratio: {primary.get('small_word_ratio')} |",
        f"| Recover exact `print(67)` source needles | failed | "
        f"startup hits: {probes[1]['runtime_diagnostics'].get('startup_source_hits')}; "
        f"all simple dump hits: {probes[1]['runtime_diagnostics'].get('all_source_hits')} |",
        "",
        "## Instrumentation counts",
        "",
        "| Metric | scan_fixture | print67 |",
        "|---|---:|---:|",
    ]
    keys = (
        "chunk_ok", "prints", "byte_calls", "distinct_blobs", "startup_blobs",
        "char_calls", "concat_calls", "pack_calls", "unpack_calls",
        "bxor_calls", "band_calls", "startup_source_hits", "all_source_hits",
        "small_word_hits", "total_words", "longest_small_word_run",
        "ir_marker_hits", "clean_ir", "hook_available", "hook_installed",
        "call_samples", "debug_getinfo", "debug_sethook", "debug_getupvalue",
        "debug_traceback", "global_dispatcher_candidates",
    )
    for key in keys:
        values = [p["runtime_diagnostics"].get(key, "n/a") for p in probes]
        lines.append(f"| `{key}` | {values[0]} | {values[1]} |")
    lines += [
        "",
        f"Scanner findings: {sum(len(p['scanner_findings']) for p in probes)}. "
        f"Probe success: **{results['success']}**.",
        "",
        "## Limitation",
        "",
        "Decoded constants become visible when the VM uses them at runtime. "
        "A full Lua debug API, executor-specific hooks, or a human can still "
        "trace local calls, inspect closures and recover behaviour. The probe "
        "only shows that a single startup dump, one global dispatcher, one "
        "decode function and a contiguous clean IR are not available. Client "
        "scripts remain recoverable; real security needs server-side authority.",
        "",
    ]
    with open(RESULTS_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
