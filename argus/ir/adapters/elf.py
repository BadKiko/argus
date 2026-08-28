"""ELF → Argus IR adapter (thin wrapper over binary loader)."""

from __future__ import annotations

from pathlib import Path
from typing import List

from argus.binary import load_binary
from argus.ir import Artifact, Module, String


def load_elf_artifact(path: str | Path) -> Artifact:
    """Wrap ELF loader output into a minimal IR Artifact."""
    p = Path(path)
    img = load_binary(str(p))
    fmt = getattr(img, "format", None) or "elf"
    arch = getattr(img, "arch", None) or "unknown"

    strings: List[String] = []
    for sec in getattr(img, "sections", []) or []:
        data = getattr(sec, "data", None)
        if not data:
            continue
        addr = int(getattr(sec, "addr", 0) or getattr(sec, "vaddr", 0) or 0)
        # crude ASCII scan — full string recovery lives in find.py
        chunk = data[: min(len(data), 256 * 1024)]
        i = 0
        while i < len(chunk):
            if chunk[i] < 0x20 or chunk[i] > 0x7E:
                i += 1
                continue
            start = i
            while i < len(chunk) and 0x20 <= chunk[i] <= 0x7E:
                i += 1
            if i - start >= 4:
                strings.append(String(va=addr + start, text=chunk[start:i].decode("ascii", errors="replace")))

    mod = Module(path=str(p.resolve()), format=str(fmt), arch=str(arch), strings=strings[:512])
    return Artifact(path=str(p.resolve()), format=str(fmt), arch=str(arch), modules=[mod])
