"""Run a Luau chunk and capture stdout plus its top-level return values."""
from __future__ import annotations

import os
import re
import subprocess
import tempfile

from obf import ast as A


def _write_tmp(data: bytes) -> str:
    fd, path = tempfile.mkstemp(suffix=".luau")
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return path


def run(data: bytes, timeout: int = 90) -> tuple[int, bytes, bytes]:
    text = data.decode("latin-1")
    longest = max((len(x) for x in re.findall(r"\](=*)\]", text)), default=0)
    eq = "=" * (longest + 1)
    driver = f'''local src = [{eq}[{text}]{eq}]
local f, e = loadstring(src, "=return_probe")
if not f then print("LOADFAIL", tostring(e)) return end
local t = table.pack(pcall(f))
print("PROBE_OK", tostring(t[1]))
print("RET_N", t.n - 1)
for i = 2, t.n do print("RET", i - 1, tostring(t[i])) end
'''
    path = _write_tmp(driver.encode("latin-1"))
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
