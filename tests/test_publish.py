"""Mocked tests for the optional GitHub raw loadstring publisher.

No real GitHub calls, tokens, repositories or Render services are used here.
"""
from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path
from urllib import error

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from obf import publish  # noqa: E402
from obf import web  # noqa: E402


class FakeResponse:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *args) -> bool:
        return False

    def read(self) -> bytes:
        return self.payload


def check(failures: list[str], condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


def _github_response(commit_sha: str = "a" * 40) -> bytes:
    return json.dumps(
        {
            "content": {
                "download_url": "https://raw.githubusercontent.com/testowner/testrepo/main/placeholder.luau"
            },
            "commit": {"sha": commit_sha},
        }
    ).encode("utf-8")


def run(failures: list[str]) -> int:
    total = 0
    cfg = publish.Config(
        token="testtoken",
        owner="testowner",
        repo="testrepo",
        branch="main",
        path_prefix="loadstrings",
        max_publish=1024,
    )

    # 1. Happy path: Base64 body, pinned raw URL, exact loadstring.
    total += 1
    captured: dict = {}
    def opener(req, timeout=None):
        captured["req"] = req
        captured["timeout"] = timeout
        return FakeResponse(_github_response())
    output = 'return print("hello")\n'
    try:
        result = publish.publish_output(output, config=cfg, opener=opener)
        expected_url = publish.build_raw_url(cfg, result["path"], "a" * 40)
        expected_loader = "loadstring(game:HttpGet(" + publish.lua_quote(expected_url) + "))()"
        body = json.loads(captured["req"].data.decode("utf-8"))
        headers = {k.lower(): v for k, v in captured["req"].header_items()}
        ok = (
            result["ok"] is True
            and result["raw_url"] == expected_url
            and result["loadstring"] == expected_loader
            and result["pinned"] is True
            and result["bytes"] == len(output.encode("utf-8"))
            and result["backend"] == "github"
            and captured["req"].get_method() == "PUT"
            and "/repos/testowner/testrepo/contents/loadstrings/" in captured["req"].full_url
            and headers.get("authorization") == "Bearer testtoken"
            and headers.get("x-github-api-version") == publish.API_VERSION
            and body.get("branch") == "main"
            and base64.b64decode(body.get("content", "")).decode("utf-8") == output
            and captured["timeout"] == cfg.timeout
        )
        check(failures, ok, "mocked GitHub publish did not produce the expected request/response")
    except Exception as exc:  # noqa: BLE001
        check(failures, False, f"mocked GitHub publish raised {exc!r}")

    # 2. Lua string escaping is safe.
    total += 1
    quoted = publish.lua_quote('a"b\\c\nd\te\x01f')
    expected_quoted = r'"a\"b\\c\nd\te\001f"'
    check(failures, quoted == expected_quoted, f"lua_quote escaping failed: {quoted!r}")

    # 3. Missing configuration is a clean 503.
    total += 1
    try:
        publish.Config(token="", owner="testowner", repo="testrepo").validate()
        check(failures, False, "missing token did not raise PublishNotConfigured")
    except publish.PublishNotConfigured as exc:
        check(failures, exc.status == 503, "PublishNotConfigured status is not 503")
    except Exception as exc:  # noqa: BLE001
        check(failures, False, f"missing token raised unexpected {exc!r}")

    # 4. Invalid config values are rejected without leaking into URLs.
    total += 1
    try:
        publish.Config(token="t", owner="../bad", repo="testrepo").validate()
        check(failures, False, "unsafe owner was accepted")
    except publish.PublishError as exc:
        check(failures, exc.status == 500, "unsafe owner did not map to HTTP 500")
    except Exception as exc:  # noqa: BLE001
        check(failures, False, f"unsafe owner raised unexpected {exc!r}")

    # 5. Oversized output is a clean 413 and never calls GitHub.
    total += 1
    called = {"n": 0}
    def counting_opener(req, timeout=None):
        called["n"] += 1
        return FakeResponse(_github_response())
    small = publish.Config(
        token="testtoken", owner="testowner", repo="testrepo", max_publish=4
    )
    try:
        publish.publish_output("return 12345\n", config=small, opener=counting_opener)
        check(failures, False, "oversized output did not raise PublishTooLarge")
    except publish.PublishTooLarge as exc:
        check(failures, exc.status == 413 and called["n"] == 0, "PublishTooLarge status or no-network rule failed")
    except Exception as exc:  # noqa: BLE001
        check(failures, False, f"oversized output raised unexpected {exc!r}")

    # 6. Empty output is a clean 400.
    total += 1
    try:
        publish.publish_output("   \n", config=cfg, opener=counting_opener)
        check(failures, False, "empty output did not raise PublishBadRequest")
    except publish.PublishBadRequest as exc:
        check(failures, exc.status == 400, "PublishBadRequest status is not 400")
    except Exception as exc:  # noqa: BLE001
        check(failures, False, f"empty output raised unexpected {exc!r}")

    # 7. GitHub HTTP errors map to a safe upstream error with no token leak.
    total += 1
    def http_403(req, timeout=None):
        raise error.HTTPError(req.full_url, 403, "Forbidden", {}, None)
    try:
        publish.publish_output(output, config=cfg, opener=http_403)
        check(failures, False, "HTTP 403 did not raise PublishError")
    except publish.PublishError as exc:
        msg = str(exc)
        check(
            failures,
            exc.status == 502 and "403" in msg and "testtoken" not in msg,
            "HTTP 403 mapping leaked a token or used the wrong status",
        )
    except Exception as exc:  # noqa: BLE001
        check(failures, False, f"HTTP 403 raised unexpected {exc!r}")

    # 8. Network errors map to a clean 502.
    total += 1
    def url_error(req, timeout=None):
        raise error.URLError("offline")
    try:
        publish.publish_output(output, config=cfg, opener=url_error)
        check(failures, False, "URLError did not raise PublishError")
    except publish.PublishError as exc:
        check(failures, exc.status == 502 and "Could not reach" in str(exc), "URLError mapping failed")
    except Exception as exc:  # noqa: BLE001
        check(failures, False, f"URLError raised unexpected {exc!r}")

    # 9. Branch raw URL fallback is explicit and warned about.
    total += 1
    branch_only = json.dumps(
        {
            "content": {
                "download_url": "https://raw.githubusercontent.com/testowner/testrepo/main/placeholder.luau"
            }
        }
    ).encode("utf-8")
    def branch_opener(req, timeout=None):
        return FakeResponse(branch_only)
    try:
        fallback = publish.publish_output(output, config=cfg, opener=branch_opener)
        check(
            failures,
            fallback["pinned"] is False and "warning" in fallback,
            "branch raw URL fallback was not flagged",
        )
    except Exception as exc:  # noqa: BLE001
        check(failures, False, f"branch raw URL fallback raised {exc!r}")

    # 10. web.do_loadstring validates the payload and delegates to the publisher.
    total += 1
    original = web.publish.publish_output
    seen = {}
    def fake_publish(text):
        seen["text"] = text
        return {"ok": True, "loadstring": "loadstring(game:HttpGet(\"x\"))()"}
    web.publish.publish_output = fake_publish
    try:
        routed = web.do_loadstring({"output": output})
        check(
            failures,
            routed["ok"] is True and seen.get("text") == output,
            "web.do_loadstring did not delegate to the publisher",
        )
        try:
            web.do_loadstring({"output": 123})
            check(failures, False, "web.do_loadstring accepted a non-string output")
        except ValueError:
            pass
    finally:
        web.publish.publish_output = original

    # 11. Meta/health expose the feature without exposing secrets.
    total += 1
    m = web.meta()
    h = web.health()
    check(
        failures,
        m["loadstring_publish"]["backend"] == "github"
        and m["limits"]["max_publish_bytes"] == web.MAX_PUBLISH
        and "loadstring_publish" in h
        and "testtoken" not in json.dumps(m),
        "meta/health did not expose loadstring_publish safely",
    )

    # 12. is_configured reads only server-side env vars.
    total += 1
    keys = ("OBF_GITHUB_TOKEN", "OBF_GITHUB_OWNER", "OBF_GITHUB_REPO")
    saved = {k: os.environ.get(k) for k in keys}
    try:
        for k in keys:
            os.environ.pop(k, None)
        missing = publish.is_configured()
        os.environ["OBF_GITHUB_TOKEN"] = "env-token"
        os.environ["OBF_GITHUB_OWNER"] = "env-owner"
        os.environ["OBF_GITHUB_REPO"] = "env-repo"
        present = publish.is_configured()
        check(failures, not missing and present, "is_configured env detection failed")
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    # 13. UI, route, Blueprint and setup guide markers all exist.
    total += 1
    ui = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
    server = (ROOT / "obf" / "web.py").read_text(encoding="utf-8")
    blueprint = (ROOT / "render.yaml").read_text(encoding="utf-8")
    guide = ROOT / "LOADSTRINGS.md"
    markers = (
        'id="makeLoadstring"' in ui
        and "make it a loadstring!" in ui
        and 'id="copyLoadstring"' in ui
        and "/api/loadstring" in ui
        and "clearLoadstring" in ui
        and "/api/loadstring" in server
        and "do_loadstring" in server
        and "OBF_GITHUB_TOKEN" in blueprint
        and "OBF_MAX_PUBLISH" in blueprint
        and guide.is_file()
        and "self.close_connection = True" in server
    )
    check(failures, markers, "loadstring UI/route/Blueprint/guide markers are incomplete")

    ok = not failures
    print(f"{'loadstring publisher':<24} {'OK' if ok else 'FAIL':<8} {total} checks")
    return total


if __name__ == "__main__":
    bad: list[str] = []
    n = run(bad)
    if bad:
        print("FAILURES:")
        for item in bad:
            print(" -", item)
        raise SystemExit(1)
    print(f"ALL GREEN ({n} checks)")
