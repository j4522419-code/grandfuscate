"""
Dependency-free web service for luau-obf.

    python3 -m obf.web            # http://0.0.0.0:$PORT (default 8000)

SECURITY MODEL
--------------
This service PARSES and COMPILES untrusted Luau; it NEVER EXECUTES it.
Only `luau-ast` (AST dump) and `luau-compile --only-parse` (compile-only) are
invoked.  The `luau` interpreter is never called by any endpoint.  Source is
held in memory, temp files are deleted, nothing is persisted, and there are
request-size, concurrency and rate limits.

Normal builds use one VM runtime, exactly three presets (light, medium and
heavy), and one opaque ID-numbered `return`-based entry layout with zero
comments and no top-level locals. The VM uses sharded encoded streams,
split handler tables and distributed late-decoded constant slices; a private
source map is kept out of the production chunk. Nested dispatch,
anti-environment poisoning and oversized padding are disabled so ordinary
Luau/Roblox environments do not poison the constant decoder. No `loadstring`
is emitted by any build. The optional web publisher wraps a finished build in
a separate `loadstring(game:HttpGet(...))()` loader; that wrapper is not part
of the protected chunk.

Deployment is paused: see DEPLOY.md. No Git remote, push, GitHub repo or
Render service has been created here. The service keeps no local persistent
storage; the optional publisher stores public raw files in an external GitHub
repo configured by environment variables.
"""
from __future__ import annotations

import concurrent.futures
import json
import os
import secrets
import sys
import threading
import time
import traceback
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from obf import __version__  # noqa: E402
from obf import ast as A  # noqa: E402
from obf import format as F  # noqa: E402
from obf import pipeline  # noqa: E402
from obf import publish  # noqa: E402

WEB_DIR = ROOT / "web"
PORT = int(os.environ.get("PORT", "8000"))
MAX_SOURCE = int(os.environ.get("OBF_MAX_SOURCE", "262144"))
# Heavy builds stay well under 1 MB; identify accepts the file back.
MAX_BODY = int(os.environ.get("OBF_MAX_BODY", str(16 * 1024 * 1024)))
MAX_IDENTIFY = 8 * 1024 * 1024
try:
    MAX_PUBLISH = int(os.environ.get("OBF_MAX_PUBLISH", str(publish.DEFAULT_MAX_PUBLISH)))
except ValueError:
    MAX_PUBLISH = publish.DEFAULT_MAX_PUBLISH
if MAX_PUBLISH <= 0:
    MAX_PUBLISH = publish.DEFAULT_MAX_PUBLISH
OBF_TIMEOUT = int(os.environ.get("OBF_TIMEOUT", "60"))
os.environ.setdefault("OBF_TIMEOUT", str(OBF_TIMEOUT))
RATE_LIMIT = int(os.environ.get("OBF_RATE_LIMIT", "24"))
ALLOWED_ORIGIN = os.environ.get("OBF_ALLOWED_ORIGIN", "*")
# Optional shared secret. Leave unset for a private/local instance; set it on a
# public Render deployment so random visitors cannot burn your CPU.
API_KEY = os.environ.get("OBF_API_KEY", "")


class PayloadTooLarge(Exception):
    """Source / file exceeds the configured limit (maps to HTTP 413)."""

EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="obf")
GATE = threading.Semaphore(2)

STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/favicon.svg": ("favicon.svg", "image/svg+xml"),
    "/LOADSTRINGS.md": ("../LOADSTRINGS.md", "text/markdown; charset=utf-8"),
}

# Only harmless per-request tweaks are accepted. The single-VM policy is
# enforced below and cannot be switched back on through the API.
BOOL_KEYS = frozenset(
    {"flatten", "virtualize_globals", "virtualize_properties", "integrity"}
)
INT_KEYS = frozenset({"junk", "min_stmts", "place_id", "game_id", "blob_pad"})
FLOAT_KEYS = frozenset({"flatten_ratio"})
RANGES = {
    "junk": (0, 8),
    "min_stmts": (1, 16),
    "flatten_ratio": (0.0, 1.0),
    "place_id": (0, 2**53),
    "game_id": (0, 2**53),
    "blob_pad": (0, 65536),
}

_hits: dict[str, deque] = defaultdict(deque)
_hits_lock = threading.Lock()


def _rate_ok(ip: str) -> bool:
    now = time.monotonic()
    with _hits_lock:
        q = _hits[ip]
        while q and q[0] < now - 60:
            q.popleft()
        if len(q) >= RATE_LIMIT:
            return False
        q.append(now)
        return True


def _client_ip(handler: BaseHTTPRequestHandler) -> str:
    # Render terminates TLS at the proxy; X-Forwarded-For is the client there.
    fwd = handler.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return handler.client_address[0]


# --------------------------------------------------------------------------
# option validation (never pass arbitrary keys into make_options)
# --------------------------------------------------------------------------
def build_request(payload: dict) -> tuple[object, bool, bytes]:
    if not isinstance(payload, dict):
        raise ValueError("request body must be a JSON object")
    src = payload.get("source")
    if not isinstance(src, str):
        raise ValueError("`source` must be a string")
    raw = src.encode("utf-8")
    if not raw.strip():
        raise ValueError("`source` is empty")
    if len(raw) > MAX_SOURCE:
        raise PayloadTooLarge(
            f"source is {len(raw)} bytes; the public limit is {MAX_SOURCE} bytes "
            "(set OBF_MAX_SOURCE to change it)"
        )

    preset = payload.get("preset", "medium")
    if preset not in pipeline.PRESETS and preset not in pipeline.PRESET_ALIASES:
        raise ValueError(f"unknown preset {preset!r}; choose from {list(pipeline.PRESETS)}")

    seed_raw = payload.get("seed")
    if seed_raw in (None, ""):
        seed = secrets.randbits(62)
    else:
        try:
            seed = int(str(seed_raw))
        except ValueError as exc:
            raise ValueError("`seed` must be an integer") from exc
        seed &= 0x7FFFFFFFFFFFFFFF

    # One normal VM runtime for every preset. Legacy hardening flags are forced
    # off: they could mark BAD and make every D() lookup return nil in ordinary
    # executors that expose getgenv/getrenv/hookfunction or different getfenvs.
    overrides: dict = {
        "seed": seed,
        "one_line": True,
        "vm": True,
        "nested_vm": False,
        "anti_env": False,
        "anti_tamper": False,
    }
    for k in BOOL_KEYS:
        if k in payload and isinstance(payload[k], bool):
            overrides[k] = payload[k]
    for k in INT_KEYS:
        v = payload.get(k)
        if v in (None, ""):
            if k in ("place_id", "game_id"):
                overrides[k] = None
            continue
        try:
            iv = int(str(v))
        except (ValueError, TypeError) as exc:
            raise ValueError(f"`{k}` must be an integer") from exc
        lo, hi = RANGES[k]
        overrides[k] = max(lo, min(hi, iv))
    for k in FLOAT_KEYS:
        v = payload.get(k)
        if v in (None, ""):
            continue
        try:
            fv = float(v)
        except (ValueError, TypeError) as exc:
            raise ValueError(f"`{k}` must be a number") from exc
        lo, hi = RANGES[k]
        overrides[k] = max(lo, min(hi, fv))

    # Re-assert the single-VM policy after all user keys are processed.
    overrides.update(
        {
            "vm": True,
            "nested_vm": False,
            "anti_env": False,
            "anti_tamper": False,
            "one_line": True,
        }
    )
    verify = payload.get("verify", True)
    return pipeline.make_options(preset, **overrides), bool(verify), raw


def _work(raw: bytes, opts, verify: bool):
    result = pipeline.obfuscate(raw, opts)
    syntax = {"checked": bool(verify), "ok": True, "message": ""}
    if verify:
        try:
            ok, msg = pipeline.validate_syntax(result.output)
            syntax = {"checked": True, "ok": ok, "message": msg[:1000]}
        except A.ToolMissing as exc:
            syntax = {"checked": True, "ok": False, "message": str(exc)}
    return result, syntax


def do_obfuscate(payload: dict) -> dict:
    opts, verify, raw = build_request(payload)
    t0 = time.perf_counter()
    with GATE:
        fut = EXECUTOR.submit(_work, raw, opts, verify)
        try:
            result, syntax = fut.result(timeout=OBF_TIMEOUT + 12)
        except concurrent.futures.TimeoutError as exc:
            raise TimeoutError("obfuscation timed out; try a smaller script or the light preset") from exc

    keys = dict(result.keys)
    # The private source map is opt-in for API callers and never part of the
    # generated .luau file. The UI does not request it.
    source_map_requested = payload.get("include_source_map") is True
    if source_map_requested:
        keys["source_map"] = result.source_map

    warnings: list[str] = []
    if not result.stats.get("vm"):
        warnings.append("VM compiler did not produce a protected runtime")
    if syntax["checked"] and not syntax["ok"]:
        warnings.append("Compile check failed: " + syntax["message"])
    if result.stats.get("vm"):
        warnings.append("Single VM output: encoded IR, no source syntax shipped.")

    return {
        "ok": True,
        "output": result.output.decode("utf-8"),
        "stats": result.stats,
        "keys": keys,
        "syntax": syntax,
        "warnings": warnings,
        "private_source_map": {
            "included_in_keys": source_map_requested,
            "sha256": result.keys.get("source_map_sha256"),
            "nodes": len(result.source_map.get("nodes", [])),
            "constants": len(result.source_map.get("constants", [])),
            "embedded_in_output": False,
        },
        "elapsed_ms": round((time.perf_counter() - t0) * 1000, 1),
        "engine": {"version": __version__, "parser": "official luau-ast", "executes_user_code": False},
    }


def do_identify(payload: dict) -> dict:
    text = payload.get("file_text")
    keys = payload.get("keys")
    if not isinstance(text, str) or not isinstance(keys, dict):
        raise ValueError("`file_text` (string) and `keys` (object) are required")
    if len(text.encode("utf-8")) > MAX_IDENTIFY:
        raise PayloadTooLarge("file too large")
    try:
        return {"ok": True, **pipeline.identify_bytes(text.encode("utf-8"), keys)}
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"invalid key file: {exc}") from exc


def do_loadstring(payload: dict) -> dict:
    """Publish already-obfuscated output and return a loadstring wrapper."""
    if not isinstance(payload, dict):
        raise ValueError("request body must be a JSON object")
    output = payload.get("output")
    if not isinstance(output, str):
        raise ValueError("`output` must be a string")
    return publish.publish_output(output)


def health() -> dict:
    tools = {
        n: os.path.isfile(os.path.join(A.TOOLS_DIR, n))
        and os.access(os.path.join(A.TOOLS_DIR, n), os.X_OK)
        for n in ("luau-ast", "luau-compile", "luau", "luau-analyze")
    }
    return {
        "ok": tools["luau-ast"] and tools["luau-compile"],
        "version": __version__,
        "tools": tools,
        "loadstring_publish": publish.is_configured(),
        "policy": "parse + compile only; user Luau code is never executed; output is returned, not stored locally",
    }


def meta() -> dict:
    return {
        "ok": True,
        "version": __version__,
        "presets": list(pipeline.PRESETS.keys()),
        "protection_levels": dict(pipeline.PROTECTION_LEVELS),
        "hardening": {
            "version": 3,
            "distributed_decoders": True,
            "ticketed_groups": True,
            "per_build_vm_structure": True,
            "private_source_map": "never embedded in production output",
        },
        "format": {
            "entrypoint": "return",
            "top_level_locals": False,
            "entry_layouts": list(F.ENTRY_LAYOUTS),
            "boot_layouts": list(F.BOOT_LAYOUTS),
            "pool_slices": {
                p: pipeline.PRESETS[p]["pool_slices"] for p in pipeline.PRESETS
            },
            "vm_fragments": {
                p: pipeline.PRESETS[p]["vm_fragments"] for p in pipeline.PRESETS
            },
            "private_source_map": "never embedded in production output",
        },
        "limits": {
            "max_source_bytes": MAX_SOURCE,
            "max_body_bytes": MAX_BODY,
            "max_identify_bytes": MAX_IDENTIFY,
            "max_publish_bytes": MAX_PUBLISH,
            "timeout_seconds": OBF_TIMEOUT,
            "rate_limit_per_minute": RATE_LIMIT,
            "junk_max": RANGES["junk"][1],
            "min_stmts_max": RANGES["min_stmts"][1],
            "flatten_ratio_max": RANGES["flatten_ratio"][1],
            "blob_pad_max": RANGES["blob_pad"][1],
        },
        "defaults": {
            "preset": "medium",
            "vm": True,
            "nested_vm": False,
            "anti_env": False,
            "anti_tamper": False,
            "blob_pad": 4096,
            "verify": True,
            "junk": 2,
            "min_stmts": 3,
            "flatten_ratio": 0.75,
        },
        "loadstring_publish": {
            "enabled": publish.is_configured(),
            "backend": "github",
            "requires_api_key": bool(API_KEY),
            "max_publish_bytes": MAX_PUBLISH,
            "wrapper": "loadstring(game:HttpGet(<pinned raw url>))()",
        },
        "requires_api_key": bool(API_KEY),
        "policy": "Your source is parsed/compiled, never executed. Obfuscated output is returned to you; the optional loadstring publisher stores only the public raw file in an external GitHub repo.",
    }


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "luau-obf"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def _send(self, status: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Access-Control-Allow-Origin", ALLOWED_ORIGIN)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-API-Key")
        self.send_header("Access-Control-Max-Age", "600")
        if self.close_connection:
            self.send_header("Connection", "close")
        if ctype.startswith("text/html"):
            # No frame-ancestors directive: Render/iframe previews must work.
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                "connect-src 'self'; font-src 'self'",
            )
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD" and body:
            self.wfile.write(body)

    def _json(self, status: int, obj: dict) -> None:
        self._send(status, json.dumps(obj, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("[web] %s %s\n" % (self.address_string(), fmt % args))

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._send(204, b"", "text/plain")

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        try:
            if path in STATIC:
                name, ctype = STATIC[path]
                data = (WEB_DIR / name).read_bytes()
                self._send(200, data, ctype)
                return
            if path == "/api/health":
                self._json(200, health())
                return
            if path == "/api/meta":
                self._json(200, meta())
                return
            if path == "/robots.txt":
                self._send(200, b"User-agent: *\nDisallow: /api/\n", "text/plain; charset=utf-8")
                return
            self._json(404, {"ok": False, "error": "not found"})
        except FileNotFoundError:
            self._json(404, {"ok": False, "error": "static file missing"})
        except Exception:  # noqa: BLE001
            traceback.print_exc()
            self._json(500, {"ok": False, "error": "internal error"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path not in ("/api/obfuscate", "/api/identify", "/api/loadstring"):
            self.close_connection = True
            self._json(404, {"ok": False, "error": "not found"})
            return
        if API_KEY and self.headers.get("X-API-Key", "") != API_KEY:
            # The body has not been read yet; close so it is not parsed as a
            # second HTTP/1.1 request on a keep-alive connection.
            self.close_connection = True
            self._json(401, {"ok": False, "error": "API key required (X-API-Key header)"})
            return
        if not _rate_ok(_client_ip(self)):
            self.close_connection = True
            self._json(429, {"ok": False, "error": f"rate limit: {RATE_LIMIT} requests/minute"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
            self.close_connection = True
            self._json(413, {"ok": False, "error": "request body missing or too large"})
            return
        body = self.rfile.read(length)
        try:
            payload = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            self.close_connection = True
            self._json(400, {"ok": False, "error": f"invalid JSON: {exc}"})
            return
        try:
            if path == "/api/obfuscate":
                self._json(200, do_obfuscate(payload))
            elif path == "/api/loadstring":
                self._json(200, do_loadstring(payload))
            else:
                self._json(200, do_identify(payload))
        except PayloadTooLarge as exc:
            self._json(413, {"ok": False, "error": str(exc)})
        except publish.PublishError as exc:
            self._json(exc.status, {"ok": False, "error": str(exc)})
        except (ValueError, TypeError) as exc:
            self._json(400, {"ok": False, "error": str(exc)})
        except A.ParseError as exc:
            self._json(422, {"ok": False, "error": str(exc)})
        except A.ToolMissing as exc:
            self._json(503, {"ok": False, "error": str(exc)})
        except TimeoutError as exc:
            self._json(504, {"ok": False, "error": str(exc)})
        except Exception:  # noqa: BLE001
            traceback.print_exc()
            self._json(500, {"ok": False, "error": "internal error while processing request"})


class Server(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> None:
    h = health()
    print(f"luau-obf web {__version__} listening on 0.0.0.0:{PORT}", flush=True)
    print(f"  tools: {h['tools']}", flush=True)
    if not h["ok"]:
        print("  WARNING: Luau toolchain missing. Run `python3 obf/fetch_tools.py`.", flush=True)
    srv = Server(("0.0.0.0", PORT), Handler)
    try:
        srv.serve_forever(poll_interval=0.3)
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
