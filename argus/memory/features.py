"""Binary feature extraction for memory reports."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict, Optional

from argus import __version__


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"


def extract_binary_features(path: str | Path, *, discover: Optional[dict] = None) -> Dict[str, Any]:
    from argus.binary import load_binary
    from argus.deobf import detect_protection
    from argus.discover import license_needle_score

    p = Path(path)
    img = load_binary(str(p))
    prot = detect_protection(img)
    needle = license_needle_score(p)
    linked_count = len((discover or {}).get("linked") or [])
    return {
        "binary_hash": sha256_file(p),
        "binary_name": p.name,
        "format": img.fmt if img.fmt in ("elf", "pe") else "unknown",
        "arch": img.arch if img.arch in ("x86_64", "x86", "aarch64", "arm64", "arm") else "unknown",
        "protection": prot.kind,
        "features": {
            "stripped": prot.kind == "stripped",
            "needle_score": needle,
            "linked_count": linked_count,
            "confidence": prot.confidence,
        },
        "client_version": __version__,
    }
