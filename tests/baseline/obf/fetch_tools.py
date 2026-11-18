"""Download the official Luau toolchain used for parsing / verification.

Run once:  python3 obf/fetch_tools.py

Used by the Render/Docker build step.  It hits GitHub's stable
`releases/latest/download/...` URL first (no API rate limit), and only falls
back to the releases API if that is unavailable.
"""
from __future__ import annotations

import io
import json
import os
import stat
import time
import urllib.request
import zipfile

TOOLS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools")
ASSET = "luau-ubuntu.zip"
DIRECT = f"https://github.com/luau-lang/luau/releases/latest/download/{ASSET}"
API = "https://api.github.com/repos/luau-lang/luau/releases/latest"
EXPECTED = ("luau", "luau-ast", "luau-compile", "luau-analyze")


def _download(url: str, timeout: int = 180) -> bytes:
    last: Exception | None = None
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "luau-obf/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except Exception as exc:  # noqa: BLE001 - retry any transient failure
            last = exc
            print(f"  download attempt {attempt + 1} failed: {exc}")
            time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"could not download Luau toolchain: {last}")


def main() -> None:
    os.makedirs(TOOLS_DIR, exist_ok=True)
    blob = None
    try:
        print(f"Fetching {DIRECT}")
        blob = _download(DIRECT)
    except Exception as exc:  # noqa: BLE001
        print(f"  direct download failed ({exc}); trying releases API")
        with urllib.request.urlopen(API, timeout=30) as r:
            rel = json.load(r)
        url = next(a["browser_download_url"] for a in rel["assets"] if a["name"] == ASSET)
        print(f"  Luau {rel['tag_name']}: {url}")
        blob = _download(url)

    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        for name in z.namelist():
            target = os.path.join(TOOLS_DIR, os.path.basename(name))
            with open(target, "wb") as f:
                f.write(z.read(name))
            os.chmod(target, os.stat(target).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            print("  installed", target)

    missing = [n for n in EXPECTED if not os.path.isfile(os.path.join(TOOLS_DIR, n))]
    if missing:
        raise RuntimeError(f"toolchain incomplete, missing: {missing}")
    print("Luau toolchain ready.")


if __name__ == "__main__":
    main()
