"""Required first-line Luau comment for generated outputs.

The user explicitly asked for this exact comment at the very top of every
output. It is a Luau line comment, so it does not change the program body.
``strip_banner`` lets scanners and tests inspect the protected chunk that
follows without counting the required banner as a policy violation.
"""
from __future__ import annotations

BANNER_TEXT = "--protected by grand6_7 (on discord)"
BANNER_BYTES = (BANNER_TEXT + "\n").encode("utf-8")


def strip_banner(data: bytes) -> bytes:
    """Return ``data`` without its required top banner, if present."""
    if data.startswith(BANNER_BYTES):
        return data[len(BANNER_BYTES):]
    return data


def banner_prefixed_text(text: str) -> str:
    """Return a string with the required banner as its first line."""
    return BANNER_TEXT + "\n" + text
