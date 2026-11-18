"""Fetch the official Luau 0.747 Windows toolchain for local Windows use.

The normal Render/Docker build uses `obf/fetch_tools.py` and Linux binaries.
This helper is only for running Grandfuscate locally on native Windows. It
writes both `luau-ast.exe` and extensionless `luau-ast` copies because the
Python front end calls `tool_path("luau-ast")`.
"""
from __future__ import annotations

import hashlib
import io
import os
import stat
import urllib.request
import zipfile

ROOT = os.path.dirname(os.path.abspath(__file__))
TOOLS_DIR = os.path.join(ROOT, "tools")
URL = "https://github.com/luau-lang/luau/releases/download/0.747/luau-windows.zip"
SHA256 = "16bbd26575e9a6a3ecd2bd5fc772a81f3232520b56a40a86f2b47fec576d7cc7"
ASSETS = ("luau.exe", "luau-ast.exe", "luau-compile.exe", "luau-analyze.exe")


def main() -> None:
    req = urllib.request.Request(URL, headers={"User-Agent": "grandfuscate-windows/1.0"})
    print(f"Fetching {URL}")
    with urllib.request.urlopen(req, timeout=180) as response:
        blob = response.read()
    digest = hashlib.sha256(blob).hexdigest()
    if digest != SHA256:
        raise RuntimeError(f"Luau Windows zip SHA-256 mismatch: {digest}")
    os.makedirs(TOOLS_DIR, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        names = set(archive.namelist())
        missing = [name for name in ASSETS if name not in names]
        if missing:
            raise RuntimeError(f"Luau Windows zip is missing: {missing}")
        for asset in ASSETS:
            data = archive.read(asset)
            base = asset[:-4]
            for name in (asset, base):
                path = os.path.join(TOOLS_DIR, name)
                with open(path, "wb") as f:
                    f.write(data)
                os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                print("installed", path)
    print("Luau 0.747 Windows toolchain ready.")


if __name__ == "__main__":
    main()
