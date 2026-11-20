"""Optional GitHub raw publisher for the web loadstring button.

The obfuscator itself never emits a dynamic loader. This module publishes a
finished protected chunk to a public GitHub repository and returns a separate
executor-style wrapper, also starting with the required Luau comment:

    --protected by grand6_7 (on discord)
    loadstring(game:HttpGet("https://raw.githubusercontent.com/..."))()

Only the Python standard library is used. All secrets stay in server-side
environment variables; nothing is written to the local filesystem.
"""
from __future__ import annotations

import base64
import json
import os
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib import error, parse, request

from .banner import BANNER_TEXT

API_ROOT = "https://api.github.com"
RAW_ROOT = "https://raw.githubusercontent.com"
API_VERSION = "2026-03-10"
DEFAULT_MAX_PUBLISH = 16 * 1024 * 1024
DEFAULT_TIMEOUT = 15.0
SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9._-]+$")
SAFE_REF = re.compile(r"^[A-Za-z0-9._/-]+$")
SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")


class PublishError(Exception):
    """Publishing failed; ``status`` is the HTTP status to return to the UI."""

    def __init__(self, message: str, status: int = 502) -> None:
        super().__init__(message)
        self.status = status


class PublishNotConfigured(PublishError):
    def __init__(self, message: str) -> None:
        super().__init__(message, 503)


class PublishTooLarge(PublishError):
    def __init__(self, message: str) -> None:
        super().__init__(message, 413)


class PublishBadRequest(PublishError):
    def __init__(self, message: str) -> None:
        super().__init__(message, 400)


@dataclass(frozen=True)
class Config:
    token: str
    owner: str
    repo: str
    branch: str = "main"
    path_prefix: str = "loadstrings"
    max_publish: int = DEFAULT_MAX_PUBLISH
    timeout: float = DEFAULT_TIMEOUT

    @classmethod
    def from_env(cls, env: dict | None = None) -> "Config":
        env = os.environ if env is None else env
        try:
            max_publish = int(env.get("OBF_MAX_PUBLISH", str(DEFAULT_MAX_PUBLISH)))
        except (TypeError, ValueError) as exc:
            raise PublishError("OBF_MAX_PUBLISH must be a positive integer", 500) from exc
        if max_publish <= 0:
            raise PublishError("OBF_MAX_PUBLISH must be a positive integer", 500)
        return cls(
            token=env.get("OBF_GITHUB_TOKEN", "").strip(),
            owner=env.get("OBF_GITHUB_OWNER", "").strip(),
            repo=env.get("OBF_GITHUB_REPO", "").strip(),
            branch=env.get("OBF_GITHUB_BRANCH", "main").strip() or "main",
            path_prefix=env.get("OBF_GITHUB_PATH", "loadstrings").strip() or "loadstrings",
            max_publish=max_publish,
        )

    def validate(self) -> "Config":
        if not self.token or not self.owner or not self.repo:
            raise PublishNotConfigured(
                "Loadstring publishing is not configured. Set OBF_GITHUB_TOKEN, "
                "OBF_GITHUB_OWNER and OBF_GITHUB_REPO in the Render Environment."
            )
        if not self.token.isascii() or any(ord(c) < 32 or ord(c) == 127 for c in self.token):
            raise PublishError("OBF_GITHUB_TOKEN contains control characters", 500)
        for label, value in (("OWNER", self.owner), ("REPO", self.repo)):
            if not SAFE_SEGMENT.fullmatch(value):
                raise PublishError(f"OBF_GITHUB_{label} contains unsafe characters", 500)
        if not SAFE_REF.fullmatch(self.branch) or ".." in self.branch:
            raise PublishError("OBF_GITHUB_BRANCH contains unsafe characters", 500)
        segments = [s for s in self.path_prefix.split("/") if s]
        if not segments or any(not SAFE_SEGMENT.fullmatch(s) or s in (".", "..") for s in segments):
            raise PublishError("OBF_GITHUB_PATH contains unsafe characters", 500)
        return self


def is_configured(env: dict | None = None) -> bool:
    """Report whether the publisher has its required server-side settings."""
    try:
        Config.from_env(env).validate()
        return True
    except PublishError:
        return False


def lua_quote(value: str) -> str:
    """Quote a Python string as a safe Lua double-quoted string literal."""
    out: list[str] = []
    for ch in value:
        code = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif code < 32 or code == 127:
            out.append(f"\\{code:03d}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def build_loadstring(raw_url: str) -> str:
    return (
        BANNER_TEXT + "\n"
        + "loadstring(game:HttpGet(" + lua_quote(raw_url) + "))()"
    )


def new_path(prefix: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    name = f"{stamp}-{secrets.token_hex(8)}.luau"
    clean = "/".join(s for s in prefix.strip("/").split("/") if s)
    return f"{clean}/{name}" if clean else name


def build_raw_url(cfg: Config, path: str, commit_sha: str) -> str:
    owner = parse.quote(cfg.owner, safe="")
    repo = parse.quote(cfg.repo, safe="")
    sha = parse.quote(commit_sha, safe="")
    quoted_path = parse.quote(path, safe="/")
    return f"{RAW_ROOT}/{owner}/{repo}/{sha}/{quoted_path}"


def _raw_url_from_response(cfg: Config, path: str, response: dict) -> tuple[str, str, bool]:
    commit = response.get("commit") if isinstance(response, dict) else None
    sha = commit.get("sha") if isinstance(commit, dict) else None
    if isinstance(sha, str) and SHA_RE.fullmatch(sha):
        return sha, build_raw_url(cfg, path, sha), True
    content = response.get("content") if isinstance(response, dict) else None
    url = content.get("download_url") if isinstance(content, dict) else None
    if isinstance(url, str) and url.startswith(RAW_ROOT + "/"):
        return "", url, False
    raise PublishError("GitHub response did not include a commit SHA or raw download URL", 502)


def _github_http_error(code: int) -> PublishError:
    messages = {
        401: "GitHub rejected the token (401). Check OBF_GITHUB_TOKEN.",
        403: "GitHub denied the request (403). Check token permissions, repository access, or rate limits.",
        404: "GitHub returned 404. Check OBF_GITHUB_OWNER, OBF_GITHUB_REPO and the branch.",
        409: "GitHub reported a conflict (409). Try again.",
        422: "GitHub rejected the upload (422). The repo may be empty, the branch may be missing, or the content may be invalid.",
        429: "GitHub rate limit reached (429). Wait and try again.",
    }
    return PublishError(messages.get(code, f"GitHub API returned HTTP {code}."), 502)


def publish_output(
    output: str,
    config: Config | None = None,
    opener=None,
) -> dict:
    """Publish ``output`` and return the loadstring plus raw URL metadata.

    ``opener`` is injectable so the test suite can mock GitHub without network
    access or secrets.
    """
    if not isinstance(output, str):
        raise PublishBadRequest("`output` must be a string")
    raw = output.encode("utf-8")
    if not raw.strip():
        raise PublishBadRequest("output is empty; obfuscate first")
    cfg = (config or Config.from_env()).validate()
    if len(raw) > cfg.max_publish:
        raise PublishTooLarge(
            f"output is {len(raw)} bytes; publish limit is {cfg.max_publish} bytes"
        )

    path = new_path(cfg.path_prefix)
    body = json.dumps(
        {
            "message": f"Publish {path.rsplit('/', 1)[-1]}",
            "content": base64.b64encode(raw).decode("ascii"),
            "branch": cfg.branch,
        },
        ensure_ascii=False,
    ).encode("utf-8")
    url = (
        f"{API_ROOT}/repos/{parse.quote(cfg.owner, safe='')}/"
        f"{parse.quote(cfg.repo, safe='')}/contents/{parse.quote(path, safe='/')}"
    )
    req = request.Request(
        url,
        data=body,
        method="PUT",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {cfg.token}",
            "Content-Type": "application/json",
            "User-Agent": "grandfuscate-loadstring-publisher",
            "X-GitHub-Api-Version": API_VERSION,
        },
    )
    opener = opener or request.urlopen
    try:
        with opener(req, timeout=cfg.timeout) as resp:
            payload = resp.read()
        response = json.loads(payload.decode("utf-8"))
    except error.HTTPError as exc:
        raise _github_http_error(exc.code) from exc
    except error.URLError as exc:
        raise PublishError(f"Could not reach GitHub API: {exc.reason}", 502) from exc
    except TimeoutError as exc:
        raise PublishError("GitHub API request timed out", 502) from exc
    except (UnicodeDecodeError, ValueError) as exc:
        raise PublishError("GitHub returned invalid JSON", 502) from exc
    except OSError as exc:
        raise PublishError(f"Could not reach GitHub API: {exc}", 502) from exc

    sha, raw_url, pinned = _raw_url_from_response(cfg, path, response)
    result = {
        "ok": True,
        "loadstring": build_loadstring(raw_url),
        "raw_url": raw_url,
        "path": path,
        "sha": sha,
        "pinned": pinned,
        "bytes": len(raw),
        "backend": "github",
    }
    if not pinned:
        result["warning"] = (
            "GitHub did not return a commit SHA; using the branch raw URL, "
            "which may change if the branch is updated."
        )
    return result
