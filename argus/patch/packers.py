from __future__ import annotations

"""Packer helpers (UPX detect + unpack)."""

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional


def is_upx(path: str) -> bool:
    raw = Path(path).read_bytes()[:0x400]
    return b"UPX!" in raw or b"UPX0" in raw or b"UPX1" in raw


def maybe_upx_unpack(path: str) -> Optional[str]:
    """If UPX-packed and `upx` on PATH, unpack to temp file and return path."""
    if not is_upx(path):
        return None
    upx = shutil.which("upx")
    if not upx:
        return None
    out = tempfile.NamedTemporaryFile(delete=False, suffix=".unupx")
    out.close()
    try:
        subprocess.run(
            [upx, "-d", "-o", out.name, path],
            check=True,
            capture_output=True,
            timeout=60,
        )
        return out.name
    except Exception:
        Path(out.name).unlink(missing_ok=True)
        return None
