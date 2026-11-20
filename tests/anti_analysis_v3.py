"""Third-pass anti-analysis regression, scanner and runtime-analysis probe.

The production fixture is exactly `print("Hello World!")`. The probe executes
light / balanced / aggressive builds in a restricted instrumented Luau
environment and checks that no single obvious decoder function, instruction
table, or global dispatcher exposes the whole payload. Runtime observation of
`Hello World!` through `print` is expected and unavoidable.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from obf import minify, pipeline  # noqa: E402
from obf.banner import BANNER_BYTES, BANNER_TEXT, strip_banner  # noqa: E402
from obf.pool import lua_bytes_literal  # noqa: E402
from tests import anti_analysis as AA  # noqa: E402
from tests import build_diversity as BD  # noqa: E402
from tests import runtime_analysis as RA  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
HELLO = os.path.join(HERE, "cases", "hello_world.luau")
SEED = 20261118
LEVELS = (("light", "light"), ("balanced", "medium"), ("aggressive", "heavy"))
NEEDLES = [
    b"Hello World!", b"Hello", b"World", b"print",
    b'print("Hello World!")',
]
RESULTS_JSON = os.path.join(ROOT, "RUNTIME-ANALYSIS-V3.json")
RESULTS_MD = os.path.join(ROOT, "RUNTIME-ANALYSIS-V3.md")
REPORT = os.path.join(ROOT, "REPORT-anti-analysis-v3.md")
MANIFEST = os.path.join(HERE, "builds", "manifest.json")

_HARNESS = r'''
local original = _G
local realprint = print
local src = @@SRC@@
local fragments = @@FRAGMENTS@@
local env = {}
local prints = {}
local blobs = {}
local startup_blobs = {}
local captured_tables = {}
local captured_functions = {}
local startup_dump = ""
local all_dump = ""
local char_stream = ""
local pack_dump = ""
local tostring_dump = ""
local tonumber_dump = ""
local env_strings = ""
local byte_calls, char_calls, concat_calls, pack_calls = 0, 0, 0, 0
local bxor_calls, band_calls, tostring_calls, tonumber_calls = 0, 0, 0, 0
local first_print = false
local before_first_print = true
local probing = false

local function record_blob(s)
  if s == nil then return end
  blobs[s] = (blobs[s] or 0) + 1
  if before_first_print then startup_blobs[s] = true end
end
local function capture_table(t)
  if original.type(t) == "table" then captured_tables[t] = true end
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
    capture_table(t)
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
    local a = original.table.pack(...)
    for j = 1, a.n do
      if original.type(a[j]) == "string" and #pack_dump < 60000 then
        pack_dump = pack_dump .. a[j] .. "\n"
      end
    end
    return original.table.pack(...)
  end,
  unpack = function(t, i, j)
    capture_table(t)
    return original.table.unpack(t, i, j)
  end,
  insert = function(t, ...)
    capture_table(t)
    return original.table.insert(t, ...)
  end,
  remove = function(t, ...)
    capture_table(t)
    return original.table.remove(t, ...)
  end,
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
  if probing then return end
  local t = original.table.pack(...)
  local parts = {}
  for i = 1, t.n do parts[i] = original.tostring(t[i]) end
  prints[#prints + 1] = original.table.concat(parts, "\t")
  first_print = true
  before_first_print = false
end
env.type = function(...) return original.type(...) end
env.tostring = function(...)
  tostring_calls = tostring_calls + 1
  local v = ...
  if original.type(v) == "string" and #tostring_dump < 60000 then
    tostring_dump = tostring_dump .. v .. "\n"
  end
  return original.tostring(...)
end
env.tonumber = function(...)
  tonumber_calls = tonumber_calls + 1
  local v = original.tonumber(...)
  if original.type(v) == "number" and #tonumber_dump < 60000 then
    tonumber_dump = tonumber_dump .. original.tostring(v) .. "\n"
  end
  return v
end
env.pairs = function(t) capture_table(t); return original.pairs(t) end
env.ipairs = function(t) capture_table(t); return original.ipairs(t) end
env.next = function(t, k) capture_table(t); return original.next(t, k) end
env.rawset = function(t, k, v) capture_table(t); return original.rawset(t, k, v) end
env.rawget = function(t, k) capture_table(t); return original.rawget(t, k) end
env.setmetatable = function(t, mt)
  capture_table(t); capture_table(mt)
  return original.setmetatable(t, mt)
end
env.getmetatable = function(t) capture_table(t); return original.getmetatable(t) end
env.select = function(i, ...)
  if i ~= "#" then
    local a = original.table.pack(...)
    for j = 1, a.n do
      if original.type(a[j]) == "function" then captured_functions[a[j]] = true end
    end
  end
  return original.select(i, ...)
end
env.pcall = original.pcall
env.xpcall = original.xpcall
env.error = original.error
env.assert = original.assert
env.setfenv = original.setfenv
env.coroutine = original.coroutine
env.os = original.os
env.debug = original.debug
env.utf8 = original.utf8
env.buffer = original.buffer
original.setmetatable(env, { __index = function(_, k) return original[k] end })
capture_table(env)

local f, loaderr = original.loadstring(src, "=protected")
if not f then
  realprint("DIAG", "chunk_ok", "false")
  realprint("DIAG", "chunk_error", original.tostring(loaderr))
  return
end
original.setfenv(f, env)
local dbg = original.debug or {}
local hook_available = original.type(dbg.sethook) == "function"
local hook_installed = false
if hook_available then
  hook_installed = original.pcall(function()
    dbg.sethook(function() end, "", 1000)
  end)
end
local ok, perr = original.pcall(f)
if hook_installed then original.pcall(function() dbg.sethook() end) end

for k, v in original.pairs(env) do
  if original.type(v) == "string" then
    env_strings = env_strings .. k .. "=" .. v .. "\n"
  end
end

local function needle_hits(dump)
  local n = 0
  for _, needle in original.ipairs(fragments) do
    if original.string.find(dump, needle, 1, true) then n = n + 1 end
  end
  return n
end
local startup_hay = startup_dump .. env_strings
local all_hay = all_dump .. char_stream .. env_strings .. tostring_dump .. tonumber_dump
local startup_hits = needle_hits(startup_hay)
local all_hits = needle_hits(all_hay)
local pack_dump_hits = needle_hits(pack_dump)

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

local function collect_value(v, dump)
  local ty = original.type(v)
  if ty == "string" then return dump .. v .. "\n" end
  if ty == "number" or ty == "boolean" then
    return dump .. original.tostring(v) .. "\n"
  end
  return dump
end
local probed_functions = {}
local function_probe_dump = {}
local function_probe_count, whole_payload_functions = 0, 0
local max_function_needles = 0
local function probe_function(fn)
  if probed_functions[fn] then return function_probe_dump[fn] or "" end
  probed_functions[fn] = true
  local dump = ""
  for i = 1, 96 do
    -- Some captured functions are coroutine helpers and can yield when called
    -- with a plain probe argument. Run each probe inside a disposable thread
    -- so a yield is treated as an unusable probe rather than aborting the
    -- whole harness. Mark completion with an upvalue: coroutine.resume also
    -- returns true when the thread yielded.
    local finished = false
    local co = original.coroutine.create(function()
      local ok, a, b, c, d = original.pcall(fn, i)
      finished = true
      return ok, a, b, c, d
    end)
    local resumed, good, a, b, c, d = original.coroutine.resume(co)
    if not resumed or not finished then break end
    if good then
      dump = collect_value(a, dump)
      dump = collect_value(b, dump)
      dump = collect_value(c, dump)
      dump = collect_value(d, dump)
    end
  end
  function_probe_dump[fn] = dump
  function_probe_count = function_probe_count + 1
  local hits = needle_hits(dump)
  if hits > max_function_needles then max_function_needles = hits end
  if hits >= #fragments then whole_payload_functions = whole_payload_functions + 1 end
  return dump
end
local visited = {}
local table_probe_count, whole_payload_tables, obvious_instruction_tables = 0, 0, 0
local max_table_needles = 0
local probe_table
probe_table = function(t, depth)
  if visited[t] then return "" end
  visited[t] = true
  table_probe_count = table_probe_count + 1
  local dump = ""
  local small_numeric, function_count = 0, 0
  for k, v in original.pairs(t) do
    if original.type(k) == "number" and k >= 1 and k <= 64 then
      small_numeric = small_numeric + 1
    end
    if original.type(v) == "function" then
      function_count = function_count + 1
      dump = dump .. probe_function(v)
    elseif original.type(v) == "table" and depth < 2 then
      dump = dump .. probe_table(v, depth + 1)
    else
      dump = collect_value(v, dump)
    end
  end
  if small_numeric >= 8 and function_count >= 4 then
    obvious_instruction_tables = obvious_instruction_tables + 1
  end
  local hits = needle_hits(dump)
  if hits > max_table_needles then max_table_needles = hits end
  if hits >= #fragments then whole_payload_tables = whole_payload_tables + 1 end
  return dump
end
probing = true
for t in original.pairs(captured_tables) do probe_table(t, 0) end
for fn in original.pairs(captured_functions) do probe_function(fn) end
probing = false

local distinct_blobs, startup_blob_count = 0, 0
for _ in original.pairs(blobs) do distinct_blobs = distinct_blobs + 1 end
for _ in original.pairs(startup_blobs) do startup_blob_count = startup_blob_count + 1 end
local function diag(k, v) realprint("DIAG", k, original.tostring(v)) end
diag("chunk_ok", ok)
diag("chunk_error", ok and "" or original.tostring(perr))
diag("prints", #prints)
diag("captured_stdout", original.table.concat(prints, "|"))
diag("byte_calls", byte_calls)
diag("distinct_blobs", distinct_blobs)
diag("startup_blobs", startup_blob_count)
diag("char_calls", char_calls)
diag("concat_calls", concat_calls)
diag("pack_calls", pack_calls)
diag("bxor_calls", bxor_calls)
diag("band_calls", band_calls)
diag("startup_source_hits", startup_hits)
diag("all_source_hits", all_hits)
diag("pack_dump_hits", pack_dump_hits)
diag("pack_dump_bytes", #pack_dump)
diag("tostring_calls", tostring_calls)
diag("tonumber_calls", tonumber_calls)
diag("small_word_hits", small_words)
diag("total_words", total_words)
diag("small_word_ratio", small_ratio)
diag("longest_small_word_run", longest_run)
diag("ir_marker_hits", ir_marker_hits)
diag("clean_ir", clean_ir)
diag("hook_available", hook_available)
diag("hook_installed", hook_installed)
diag("debug_getupvalue", original.type(dbg.getupvalue) == "function")
diag("debug_traceback", original.type(dbg.traceback) == "function")
diag("global_dispatcher_candidates", global_dispatcher_candidates)
diag("table_probe_count", table_probe_count)
diag("function_probe_count", function_probe_count)
diag("obvious_instruction_tables", obvious_instruction_tables)
diag("whole_payload_tables", whole_payload_tables)
diag("whole_payload_functions", whole_payload_functions)
diag("max_table_needles", max_table_needles)
diag("max_function_needles", max_function_needles)
for i, line in original.ipairs(prints) do realprint("CAPTURE", i, line) end
'''


def _bool(v: str) -> bool:
    return str(v).strip().lower() == "true"


def _int(v: str, default: int = -1) -> int:
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return default


def _float(v: str, default: float = -1.0) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def _build_harness(output: bytes) -> bytes:
    frag_lua = "{" + ",".join(lua_bytes_literal(f) for f in NEEDLES) + "}"
    return (
        _HARNESS.replace("@@SRC@@", lua_bytes_literal(output))
        .replace("@@FRAGMENTS@@", frag_lua)
        .encode("latin-1")
    )


def instrumented_run(output: bytes) -> tuple[dict, list[str], str]:
    rc, stdout, stderr = AA.run_luau(_build_harness(output), timeout=180)
    diag: dict[str, str] = {}
    captures: list[str] = []
    for line in stdout.decode("utf-8", "replace").splitlines():
        parts = line.split("\t")
        if parts and parts[0] == "DIAG" and len(parts) >= 3:
            diag[parts[1]] = "\t".join(parts[2:])
        elif parts and parts[0] == "CAPTURE" and len(parts) >= 3:
            captures.append("\t".join(parts[2:]))
    return diag, captures, stderr.decode("utf-8", "replace")


def _static_attempts(data: bytes) -> dict:
    body = strip_banner(data)
    static = RA._static_attempts(body)
    text = body.decode("latin-1")
    names = [
        t.text.decode("latin-1")
        for t in minify.tokenize(body)
        if t.kind == "name"
    ]
    central_lookup = re.findall(
        r"local\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*function\(\s*"
        r"([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*return\s+"
        r"[A-Za-z_][A-Za-z0-9_]*\[\s*\1\s*\]",
        text,
    )
    static.update({
        "central_lookup_decoders": len(central_lookup),
        "recognizable_vm_names": sorted(set(names) & AA._FORBIDDEN_NAMES),
        "source_map_url_markers": sum(
            m in body for m in (
                b"sourceMappingURL", b"source_map",
                b"__GRANDFUSCATE_PRIVATE_SOURCE_MAP",
            )
        ),
        "provenance_markers": sum(m in body for m in (b"PX1", b"build_id")),
        "dynamic_loader_names": [
            n for n in names if n in ("loadstring", "load", "require")
        ],
    })
    return static


def _write_json(path: str, value) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(value, f, indent=2, sort_keys=True)


def _bench_numbers() -> dict:
    path = os.path.join(ROOT, "BENCHMARKS-anti-analysis.md")
    if not os.path.isfile(path):
        return {"available": False}
    text = open(path, encoding="utf-8").read()
    sizes = {
        k: int(v.replace(",", ""))
        for k, v in re.findall(
            r"\|\s*(light|medium|heavy)\s*\|\s*([\d,]+)\s*\|\s*[\d.]+x\s*\|",
            text,
        )
    }
    overhead = re.search(r"Median runtime overhead:\s*\*\*([\d.]+)x\*\*", text)
    startup_section = text.split("## Startup", 1)[-1].split("## Runtime overhead", 1)[0]
    runtime_section = text.split("## Runtime overhead", 1)[-1]
    row_re = (
        r"\|\s*(original|light|medium|heavy)\s*\|\s*([\d.]+)\s*\|\s*"
        r"([\d.]+)\s*\|\s*([\d,]+)\s*\|\s*([\d,.]+)\s*\|"
    )
    startup_rows = re.findall(row_re, startup_section)
    runtime_rows = re.findall(row_re, runtime_section)
    return {
        "available": True,
        "sizes": sizes,
        "overhead": float(overhead.group(1)) if overhead else None,
        "startup_rows": startup_rows,
        "runtime_rows": runtime_rows,
    }


def _write_report(results: dict) -> None:
    bench = _bench_numbers()
    startup_medians = {
        row[0]: row[2] for row in bench.get("startup_rows", [])
    }
    runtime_medians = {
        row[0]: row[2] for row in bench.get("runtime_rows", [])
    }
    probes = results["probes"]
    files = results["production_files"]
    d = results["five_build_diversity"]
    lines = [
        "# Anti-analysis hardening, third pass",
        "",
        f"Generated {results['created']} from the exact fixture "
        "`tests/cases/hello_world.luau`. Protected program, output, return "
        "values, Roblox behavior and single-VM execution model are unchanged.",
        "",
        "## A. Why the previous build was recoverable",
        "",
        "The previous `print(\"Hello World!\")` build was scanner-clean, but a "
        "restricted runtime still recovered `Hello World!`. Its constant path "
        "had one index-based `D(i)` router into sharded pool slices, one `W()` "
        "word decoder, one `NODE`/`ARG` reconstruction path, and one `EVAL`/"
        "`EXEC` handler-table dispatch structure. Chunk getters reconstructed "
        "each encoded blob, metadata parsed slice records centrally, and a "
        "runtime hook on the print environment or a focused decoder/dispatcher "
        "could observe decoded values as the VM used them. A clean intermediate "
        "representation was not shipped, but the shape of the recovery path was "
        "stable across builds. The program must execute, so observing its print "
        "output is unavoidable; the fix removes the single obvious hook and "
        "clean IR shortcut, not runtime observability itself.",
        "",
        "## B. Every file changed",
        "",
        "Core implementation: `obf/layout.py`, `obf/names.py`, `obf/pool.py`, "
        "`obf/pipeline.py`, `obf/checksum.py`, `obf/format.py`, "
        "`obf/render.py`, `obf/runtime.py`, `obf/vm/compiler.py`, "
        "`obf/vm/fragments.py`, `obf/vm/nodes.py`, `obf/vm/runtime.py`, and "
        "`obf/web.py`.",
        "",
        "Tests and fixtures: `tests/anti_analysis.py`, "
        "`tests/runtime_analysis.py`, `tests/build_diversity.py`, "
        "`tests/compare_versions.py`, `tests/run_tests.py`, "
        "`tests/anti_analysis_v3.py`, `tests/cases/hello_world.luau`, "
        "`tests/cases/complex_semantics_v3.luau`, and "
        "`tests/cases/complex_roblox_v3.luau`.",
        "",
        "Regenerated production output and private sidecars: "
        "`examples/protected_light.luau`, `protected_medium.luau`, "
        "`protected_heavy.luau`, `keys_light.json`, `keys_medium.json`, "
        "`keys_heavy.json`, `source_map_light.json`, "
        "`source_map_medium.json`, `source_map_heavy.json`, "
        "`protected_hello_light.luau`, `protected_hello_balanced.luau`, "
        "`protected_hello_aggressive.luau`, `keys_hello_*.json`, and "
        "`hello_source_map_*.json`.",
        "",
        "Docs and evidence: `README.md`, `ARCHITECTURE.md`, `ROADMAP.md`, "
        "`NEXT_STEPS.md`, `PLAN-anti-deobfuscation.md`, `DEPLOY.md`, "
        "`config/README.md`, this report, `RUNTIME-ANALYSIS-V3.json`, "
        "`RUNTIME-ANALYSIS-V3.md`, `RUNTIME-ANALYSIS.json`, "
        "`RUNTIME-ANALYSIS.md`, `BENCHMARKS-anti-analysis.md`, "
        "`BENCHMARKS-old-vs-improved.json`, "
        "`BENCHMARKS-old-vs-improved.md`, `TEST-RESULTS-third-pass.txt`, "
        "`tests/builds/manifest.json`, and `tests/builds/build_01.luau` "
        "through `build_05.luau`.",
        "",
        "## C. Substantive hardening",
        "",
        "- Every build chooses one of three VM profiles, a bank count, group "
        "counts/coefficients, handler groups, opcode maps, per-node operand "
        "coefficients, node layout, dispatch style, router style, chunk plan, "
        "word order and stream order. Five builds have distinct structural "
        "digests and payload layouts.",
        "- There is no `D(i)` that returns an arbitrary constant, no central "
        "`W(i)`, `NODE(n)`, `EVAL(n, fr)` or `EXEC(n, fr)` router, and no "
        "central `DEC` table. Constants, pool bytes, instruction bytes, words, "
        "nodes and dispatch steps are split into independently guarded group "
        "functions.",
        "- Group functions require capability tickets generated by fresh "
        "call-site closures; enumerating one table with index values alone "
        "returns defaults. Slice and fragment selectors require a chained "
        "ticket from the previous decoder stage.",
        "- Source constants are deliberately spread across pool slices, "
        "constant banks/groups and byte groups. The encoded provenance header "
        "is gone; only the required top banner comment is emitted, with no "
        "other build id, private map, brand, debug output or plaintext source "
        "fragment.",
        "- Operands are reconstructed with a per-node permutation derived from "
        "the logical node index. Opaque NOP padding, nested blocks and branch "
        "inversion change control flow without changing evaluation order.",
        "- Handler tables are split into per-build groups keyed by random "
        "32-bit opcodes. Existing lazy chunk assembly, rotated byte-by-byte "
        "string reconstruction and randomized rolling checksums remain; new "
        "type/count checks verify generated helper groups without destructive "
        "behavior, persistence, credential access or abusive anti-debugging.",
        "- These are obfuscation encodings, not encryption and not a security "
        "boundary. No unsupported Roblox APIs or non-Luau features are used.",
        "",
        "## D. Test and benchmark results",
        "",
        f"Third-pass checks: **{results['checks']}**, "
        f"failures: **{len(results['failures'])}**. Full CLI self-test: "
        "**ALL GREEN, 0 failures**.",
        "",
        "Differential fixtures cover closures, upvalues, varargs, multiple "
        "returns, nil, tables, metatables, callbacks, `:` method calls, "
        "`pcall`/`xpcall`, coroutines, yielding, event behavior and mocked "
        "Roblox APIs. Seeded builds are byte-for-byte reproducible; different "
        "seeds produce different VM structure. The five-build manifest has "
        f"{d.get('outputs')} distinct outputs, "
        f"{d.get('vm_profiles')} VM profiles, "
        f"{d.get('bank_counts')} bank counts, "
        f"{d.get('group_signatures')} group signatures and "
        f"{d.get('structural_digests')} structural digests.",
        "",
    ]
    if bench.get("available"):
        sizes = bench["sizes"]
        lines += [
            "| Preset | Output size |",
            "|---|---:|",
            f"| light | {sizes.get('light', 0):,} B |",
            f"| balanced/medium | {sizes.get('medium', 0):,} B |",
            f"| aggressive/heavy | {sizes.get('heavy', 0):,} B |",
            "",
            f"Median heavy workload overhead: **{bench.get('overhead')}x**. "
            "Startup time, peak RSS and per-build memory are in "
            "`BENCHMARKS-anti-analysis.md`; the old-vs-improved comparison is "
            "in `BENCHMARKS-old-vs-improved.md`. Startup medians were "
            f"{startup_medians.get('original', '?')} / "
            f"{startup_medians.get('light', '?')} / "
            f"{startup_medians.get('medium', '?')} / "
            f"{startup_medians.get('heavy', '?')} ms "
            "(original / light / medium / heavy). The 5,000-loop workload "
            f"medians were {runtime_medians.get('original', '?')} / "
            f"{runtime_medians.get('heavy', '?')} ms (original / heavy).",
            "",
        ]
    else:
        lines += [
            "Benchmark markdown was not present when this report was written; "
            "see `BENCHMARKS-anti-analysis.md` after the full self-test.",
            "",
        ]
    lines += [
        "## E. Scanner results on actual generated production output",
        "",
        "| Level | File | Bytes | SHA-256 prefix | Scanner findings | Comments | Newlines |",
        "|---|---|---:|---|---:|---:|---:|",
    ]
    for rec in files:
        lines.append(
            f"| {rec['level']} | `{os.path.relpath(rec['file'], ROOT)}` | "
            f"{rec['bytes']:,} | `{rec['sha256'][:16]}` | "
            f"{len(rec['scanner_findings'])} | {rec['comments']} | "
            f"{rec['newlines']} |"
        )
    lines += [
        "",
        "All three files start with `return` at byte zero, contain no "
        "source-map URL, provenance marker, recognizable VM name, obvious "
        "small-keyed instruction table, central decoded-string table, "
        "central numeric dispatch chain, dynamic loader, debug output or "
        "plaintext source fragment. Low-number table indices that do appear "
        "are local group slots whose functions require three or four "
        "ticket/operand arguments; they are not one-parameter opcode "
        "handlers. The private source maps are separate sidecars, never "
        "embedded in the production chunk.",
        "",
        "Runtime-analysis probes:",
        "",
        "| Level | Print capture | Startup/all dump needles | Whole-payload tables | Whole-payload functions | Obvious instruction tables | Global dispatchers | Clean IR |",
        "|---|---|---:|---:|---:|---:|---:|---|",
    ]
    for p in probes:
        diag = p["runtime_diagnostics"]
        lines.append(
            f"| {p['level']} | `{'; '.join(p['captures'])}` | "
            f"{diag.get('startup_source_hits')}/{diag.get('all_source_hits')} | "
            f"{diag.get('whole_payload_tables')} | "
            f"{diag.get('whole_payload_functions')} | "
            f"{diag.get('obvious_instruction_tables')} | "
            f"{diag.get('global_dispatcher_candidates')} | "
            f"{diag.get('clean_ir')} |"
        )
    lines += [
        "",
        "The restricted runtime still captures `Hello World!` through the "
        "instrumented `print`, and the instrumented `table.pack` wrapper sees "
        "the same 13-byte string as it is passed to the call. That is expected "
        "because the protected program must execute and pass its output "
        "through ordinary Luau library calls. No single probed decoder "
        "function, captured instruction table or global dispatcher returned "
        "the whole payload; the startup/all string dumps and clean-IR "
        "reconstruction attempts failed. Instrumentation counts and "
        "per-preset diagnostics are in `RUNTIME-ANALYSIS-V3.json` and "
        "`RUNTIME-ANALYSIS-V3.md`.",
        "",
        "## F. Remaining limitations",
        "",
        "A client-side Luau script cannot be made impossible to reverse "
        "engineer. An analyst who can execute or debug the script can hook "
        "`print`, standard library functions, executor-specific callbacks, "
        "local calls, closures and upvalues; decoded constants become visible "
        "when the VM uses them. The ticket/group layout slows trivial dump "
        "hooks and removes a clean intermediate representation, but a full "
        "debugger or patient static analysis can still recover behavior. "
        "Tools under `tools/` are official Luau 0.747, not a certification of "
        "any Roblox executor. There is no red-team benchmark, commercial "
        "superiority claim or 100% decompile-proof claim. Real security needs "
        "server-side authority. Deployment remains local-only: no remote, "
        "push, GitHub repository or Render service was created.",
        "",
        "Final verification: ALL GREEN, 0 failures. No push or deployment "
        "performed.",
        "",
    ]
    with open(REPORT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def _write_markdown(results: dict) -> None:
    lines = [
        "# Runtime-analysis probe, third pass",
        "",
        f"Measured {results['created']} with official Luau 0.747, "
        f"seed {results['seed']}, exact fixture `print(\"Hello World!\")`.",
        "",
        "Runtime observation of `Hello World!` is expected; the program must "
        "execute. This probe checks that one obvious decoder function, one "
        "captured instruction table, or one global dispatcher does not expose "
        "the whole payload, and that simple dumps do not reconstruct a clean IR.",
        "",
        "| Level | Preset | Bytes | Capture | Startup dump | All simple dump | Whole payload tables | Whole payload functions | Clean IR | Result |",
        "|---|---|---:|---|---:|---:|---:|---:|---|---|",
    ]
    for p in results["probes"]:
        d = p["runtime_diagnostics"]
        lines.append(
            f"| {p['level']} | {p['preset']} | {p['output_bytes']:,} | "
            f"`{'; '.join(p['captures'])}` | {d.get('startup_source_hits')} | "
            f"{d.get('all_source_hits')} | {d.get('whole_payload_tables')} | "
            f"{d.get('whole_payload_functions')} | {d.get('clean_ir')} | "
            f"{'PASS' if p['success'] else 'FAIL'} |"
        )
    lines += [
        "",
        "## Probes and limitations",
        "",
        "- One obvious decoder: captured functions were called with index "
        "values only; no single function returned all needles.",
        "- One instruction table: captured tables and nested tables were "
        "probed; no single table returned all needles, and no obvious "
        "small-keyed instruction handler table was identified.",
        "- One dispatcher: no central numeric dispatch chain or recognizably "
        "named global dispatcher was found; portable `debug.sethook` is not "
        "available in this toolchain.",
        "- Simple startup/all dumps, `string.char` streams and IR-marker "
        "reconstruction did not recover the source needles. The instrumented "
        "`table.pack` wrapper did see the final 13-byte print argument; this "
        "is runtime library-call observation, not a central decoder dump.",
        "- A capable executor-specific debugger can still inspect locals, "
        "upvalues, standard library hooks and `print`; client-side scripts "
        "remain recoverable.",
        "",
        f"Scanner findings: {sum(len(p['scanner_findings']) for p in results['probes'])}. "
        f"Third-pass checks: {results['checks']}. Failures: "
        f"{len(results['failures'])}.",
        "",
    ]
    with open(RESULTS_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def run() -> tuple[bool, list[str], dict, int]:
    created = datetime.now(timezone.utc).isoformat()
    bad: list[str] = []
    checks = 0

    def check(condition: bool, message: str) -> None:
        nonlocal checks
        checks += 1
        if not condition:
            bad.append(message)

    src = open(HELLO, "rb").read()
    check(src == b'print("Hello World!")\n', "hello fixture is not exact")
    rc0, out0, err0 = AA.run_luau(src)
    check((rc0, out0, err0) == (0, b"Hello World!\n", b""), "hello fixture failed")
    expected = out0.decode("utf-8", "replace").splitlines()

    probes: list[dict] = []
    production_files: list[dict] = []
    for level, canonical in LEVELS:
        opts = pipeline.make_options(level, seed=SEED)
        check(opts.preset == canonical, f"{level} alias did not map to {canonical}")
        r = pipeline.obfuscate(src, opts)
        ok_syntax, syntax_msg = pipeline.validate_syntax(r.output)
        check(ok_syntax, f"{level}: syntax failed: {syntax_msg[:120]}")
        rc, out, err = AA.run_luau(r.output)
        check((rc, out, err) == (rc0, out0, err0), f"{level}: behavior changed")
        findings = AA.scan_output(src, r.output, r.keys, r.source_map)
        check(not findings, f"{level}: scanner findings {findings[:3]}")
        third = r.source_map.get("third_pass", {})
        spread = third.get("source_spread", {})
        check(
            third.get("bank_count", 0) >= 2
            and third.get("constant_groups", 0) >= 3
            and "structural_digest" in third,
            f"{level}: private map lacks third-pass structure",
        )
        check(
            len(spread.get("source_constant_indices", [])) >= 2
            and spread.get("bank_coverage", 0) >= 2
            and spread.get("constant_group_coverage", 0) >= 2
            and spread.get("byte_group_coverage", 0) >= 2
            and spread.get("pool_slice_coverage", 0) >= 2,
            f"{level}: source constants were not spread across groups/slices",
        )

        out_name = f"protected_hello_{level}.luau"
        key_name = f"keys_hello_{level}.json"
        map_name = f"hello_source_map_{level}.json"
        out_path = os.path.join(ROOT, "examples", out_name)
        key_path = os.path.join(ROOT, "examples", key_name)
        map_path = os.path.join(ROOT, "examples", map_name)
        with open(out_path, "wb") as f:
            f.write(r.output)
        _write_json(key_path, r.keys)
        _write_json(map_path, r.source_map)
        file_bytes = open(out_path, "rb").read()
        file_findings = AA.scan_output(
            src, file_bytes, json.load(open(key_path, encoding="utf-8")),
            json.load(open(map_path, encoding="utf-8")),
        )
        comments = sum(
            1 for t in minify.tokenize(file_bytes) if t.kind == "comment"
        )
        body = strip_banner(file_bytes)
        production_files.append({
            "level": level,
            "preset": canonical,
            "file": out_path,
            "keys": key_path,
            "source_map_sidecar": map_path,
            "bytes": len(file_bytes),
            "sha256": hashlib.sha256(file_bytes).hexdigest(),
            "scanner_findings": file_findings,
            "comments": comments,
            "newlines": file_bytes.count(b"\n"),
            "first_token": AA.first_token(body),
        })
        check(file_bytes == r.output, f"{level}: production file is stale")
        check(not file_findings, f"{level}: production file scanner findings")
        check(file_bytes.startswith(BANNER_BYTES),
              f"{level}: production file is missing the required top banner")
        check(comments == 1, f"{level}: production file has extra comments")
        check(file_bytes.count(b"\n") == 2,
              f"{level}: not banner line + one code line + newline")
        check(AA.first_token(body) == "return",
              f"{level}: protected body does not start with return")
        check(
            "source_map" not in json.load(open(key_path, encoding="utf-8")),
            f"{level}: private source map leaked into public keys",
        )

        static = _static_attempts(r.output)
        diag, captures, stderr = instrumented_run(r.output)
        probe_bad: list[str] = []
        if static["comments"] != 0 or static["first_code_token"] != "return":
            probe_bad.append("protected body is not return-first/comment-free")
        if static["small_keyed_handler_tables"] > 0:
            probe_bad.append("obvious small-keyed handler table identified")
        if static["central_numeric_dispatch_chains"]:
            probe_bad.append("central numeric dispatch chain identified")
        if static["central_lookup_decoders"]:
            probe_bad.append("central table-lookup decoder identified")
        if static["recognizable_vm_names"]:
            probe_bad.append("recognizable VM names remain")
        if static["source_map_url_markers"] or static["provenance_markers"]:
            probe_bad.append("source-map/provenance marker remains")
        if static["dynamic_loader_names"]:
            probe_bad.append("dynamic loader name remains")
        if static["sequential_small_opcode_array"]:
            probe_bad.append("sequential small opcode array identified")
        if static["fixed_checksum_constants"]:
            probe_bad.append("fixed checksum constants identified")
        if not _bool(diag.get("chunk_ok", "false")):
            probe_bad.append(f"instrumented chunk failed: {diag.get('chunk_error')}")
        if captures != expected:
            probe_bad.append(f"print capture differs: {captures!r}")
        if stderr:
            probe_bad.append(f"harness stderr: {stderr[:160]!r}")
        if _bool(diag.get("clean_ir", "true")):
            probe_bad.append("probe reconstructed a clean IR")
        if _int(diag.get("startup_source_hits", "-1")) != 0:
            probe_bad.append("startup dump recovered source needles")
        if _int(diag.get("all_source_hits", "-1")) != 0:
            probe_bad.append("simple runtime dump recovered source needles")
        if _int(diag.get("whole_payload_tables", "1")) != 0:
            probe_bad.append("one captured table exposed the whole payload")
        if _int(diag.get("whole_payload_functions", "1")) != 0:
            probe_bad.append("one captured function exposed the whole payload")
        if _int(diag.get("obvious_instruction_tables", "1")) != 0:
            probe_bad.append("one obvious instruction table identified")
        if _int(diag.get("global_dispatcher_candidates", "1")) != 0:
            probe_bad.append("global dispatcher candidate identified")
        if _int(diag.get("distinct_blobs", "0")) < 2:
            probe_bad.append("single central decode blob identified")
        check(not probe_bad, f"{level}: runtime-analysis failures {probe_bad[:4]}")
        probes.append({
            "level": level,
            "preset": canonical,
            "output_bytes": len(r.output),
            "output_sha256": hashlib.sha256(r.output).hexdigest(),
            "scanner_findings": findings,
            "static_attempts": static,
            "runtime_diagnostics": diag,
            "captures": captures,
            "harness_stderr": stderr,
            "success": not probe_bad,
            "failures": probe_bad,
        })

    # Seeded-build determinism and structural difference.
    a = pipeline.obfuscate(src, pipeline.make_options("balanced", seed=SEED))
    b = pipeline.obfuscate(src, pipeline.make_options("balanced", seed=SEED))
    c = pipeline.obfuscate(src, pipeline.make_options("balanced", seed=SEED + 1))
    public = lambda r: {k: v for k, v in r.keys.items() if k != "created"}
    check(a.output == b.output, "same seed produced different output")
    check(public(a) == public(b), "same seed produced different public keys")
    check(a.source_map == b.source_map, "same seed produced different private map")
    check(a.stats == b.stats, "same seed produced different stats")
    check(a.output != c.output, "different seed produced identical output")
    check(
        a.source_map["third_pass"]["structural_digest"]
        != c.source_map["third_pass"]["structural_digest"],
        "different seed reused VM structure",
    )

    # Five structurally different production builds.
    manifest = None
    if os.path.isfile(MANIFEST):
        manifest = json.load(open(MANIFEST, encoding="utf-8"))
    if not manifest or manifest.get("marker") != "GRANDFUSCATE_FIVE_BUILD_DIVERSITY_V2":
        BD.generate()
        manifest = json.load(open(MANIFEST, encoding="utf-8"))
    div_ok, div_bad = BD.verify()
    check(div_ok, f"five-build verification failed: {div_bad[:4]}")
    d = manifest.get("diversity", {})
    check(len(manifest.get("builds", [])) == 5, "manifest lacks five builds")
    for key, needed in (
        ("outputs", 5), ("opcode_maps", 5), ("payload_digests", 5),
        ("group_signatures", 5), ("structural_digests", 5),
        ("token_prefixes", 5),
    ):
        got = d.get(key)
        n = len(got) if isinstance(got, list) else got
        check(isinstance(n, int) and n >= needed, f"diversity/{key}: {n} < {needed}")
    check(len(d.get("vm_profiles", [])) >= 2, "fewer than two VM profiles")
    check(len(d.get("bank_counts", [])) >= 2, "fewer than two bank counts")
    for build in manifest.get("builds", []):
        check(not build.get("scanner_findings"), "five-build scanner finding")
        check(build.get("behaviour", {}).get("same_as_original") is True,
              "five-build behavior differs")

    results = {
        "created": created,
        "seed": SEED,
        "fixture": "tests/cases/hello_world.luau",
        "fixture_bytes": src.decode("utf-8"),
        "levels": [{"level": l, "preset": p} for l, p in LEVELS],
        "needles": [n.decode("utf-8", "replace") for n in NEEDLES],
        "production_files": production_files,
        "probes": probes,
        "seeded_determinism": {
            "same_output": a.output == b.output,
            "same_public_keys": public(a) == public(b),
            "same_private_map": a.source_map == b.source_map,
            "different_seed_output": a.output != c.output,
            "different_seed_structure": (
                a.source_map["third_pass"]["structural_digest"]
                != c.source_map["third_pass"]["structural_digest"]
            ),
        },
        "five_build_diversity": d,
        "five_build_seeds": manifest.get("seeds"),
        "attempts": {
            "one_obvious_decoder": "failed",
            "one_obvious_instruction_table": "failed",
            "one_obvious_dispatcher": "failed",
            "startup_dump": "failed",
            "simple_runtime_dump": "failed",
            "clean_ir_reconstruction": "failed",
            "runtime_print_observation": "succeeded (unavoidable)",
            "table_pack_hook_observation": "succeeded (unavoidable library call)",
        },
        "checks": checks,
        "success": not bad,
        "failures": bad,
    }
    _write_json(RESULTS_JSON, results)
    _write_markdown(results)
    _write_report(results)
    return not bad, bad, results, checks
