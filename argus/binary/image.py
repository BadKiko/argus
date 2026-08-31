from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class Section:
    name: str
    addr: int
    size: int
    data: bytes
    executable: bool = False
    writable: bool = False
    readable: bool = True


@dataclass
class Symbol:
    name: str
    addr: int
    size: int = 0
    is_function: bool = False
    is_import: bool = False


class SparseMemory:
    """Zero-allocation sparse memory view over sections with an overlay for writes."""

    def __init__(self, sections: List[Section], overrides: Optional[Dict[int, int]] = None):
        self.sections = sections
        self.overrides: Dict[int, int] = overrides if overrides is not None else {}

    def get(self, addr: int, default: int = 0) -> int:
        if addr in self.overrides:
            return self.overrides[addr]
        for s in self.sections:
            if s.data and s.addr <= addr < s.addr + len(s.data):
                return s.data[addr - s.addr]
        return default

    def __getitem__(self, addr: int) -> int:
        if addr in self.overrides:
            return self.overrides[addr]
        for s in self.sections:
            if s.data and s.addr <= addr < s.addr + len(s.data):
                return s.data[addr - s.addr]
        raise KeyError(addr)

    def __setitem__(self, addr: int, val: int) -> None:
        self.overrides[addr] = val & 0xFF

    def __contains__(self, addr: int) -> bool:
        if addr in self.overrides:
            return True
        for s in self.sections:
            if s.data and s.addr <= addr < s.addr + len(s.data):
                return True
        return False

    def setdefault(self, addr: int, default: int = 0) -> int:
        if addr in self:
            return self[addr]
        self.overrides[addr] = default & 0xFF
        return default & 0xFF

    def items(self):
        for s in self.sections:
            if not s.data:
                continue
            for i, b in enumerate(s.data):
                addr = s.addr + i
                yield addr, self.overrides.get(addr, b)
        for addr, b in self.overrides.items():
            if not any(s.data and s.addr <= addr < s.addr + len(s.data) for s in self.sections):
                yield addr, b

    def keys(self):
        for addr, _ in self.items():
            yield addr

    def values(self):
        for _, b in self.items():
            yield b

    def copy(self) -> SparseMemory:
        return SparseMemory(list(self.sections), dict(self.overrides))

    def __len__(self) -> int:
        return sum(len(s.data) for s in self.sections if s.data) + len(self.overrides)


@dataclass
class BinaryImage:
    path: str
    fmt: str  # "elf" | "pe"
    arch: str  # "x86_64" | "x86"
    bits: int
    entry: int
    sections: List[Section] = field(default_factory=list)
    symbols: Dict[str, Symbol] = field(default_factory=dict)
    imports: Dict[int, str] = field(default_factory=dict)  # plt/iat addr -> name
    # Sparse memory image for analysis / emulation
    memory: Any = field(default_factory=dict)

    def read_bytes(self, addr: int, size: int) -> bytes:
        if size <= 0:
            return b""
        sec = self.section_at(addr)
        if sec and sec.data and sec.addr <= addr and addr + size <= sec.addr + len(sec.data):
            offset = addr - sec.addr
            chunk = bytearray(sec.data[offset : offset + size])
            overrides = getattr(self.memory, "overrides", None)
            if overrides:
                for i in range(size):
                    a = addr + i
                    if a in overrides:
                        chunk[i] = overrides[a]
            elif isinstance(self.memory, dict) and self.memory:
                for i in range(size):
                    a = addr + i
                    if a in self.memory:
                        chunk[i] = self.memory[a]
            return bytes(chunk)

        out = bytearray(size)
        for i in range(size):
            out[i] = self.memory.get(addr + i, 0)
        return bytes(out)

    def write_bytes(self, addr: int, data: bytes) -> None:
        for i, b in enumerate(data):
            self.memory[addr + i] = b

    def section_at(self, addr: int) -> Optional[Section]:
        for s in self.sections:
            if s.addr <= addr < s.addr + max(s.size, len(s.data) if s.data else 0):
                return s
        return None

    def symbol_addr(self, name: str) -> Optional[int]:
        sym = self.symbols.get(name)
        return sym.addr if sym else None

    def find_string(self, needle: bytes) -> List[int]:
        hits: List[int] = []
        # Scan mapped memory ranges by section
        for s in self.sections:
            if not s.data:
                continue
            start = 0
            while True:
                idx = s.data.find(needle, start)
                if idx < 0:
                    break
                hits.append(s.addr + idx)
                start = idx + 1
        return hits


def load_binary(path: str | Path) -> BinaryImage:
    path = Path(path)
    key = str(path.resolve())
    try:
        mtime = path.stat().st_mtime
    except OSError:
        mtime = None
    if mtime is not None and key in _BINARY_CACHE:
        cached_mtime, cached = _BINARY_CACHE[key]
        if cached_mtime == mtime:
            return cached
    raw = path.read_bytes()
    if raw[:4] == b"\x7fELF":
        from .elf import load_elf

        img = load_elf(path)
    elif raw[:2] == b"MZ":
        from .pe import load_pe

        img = load_pe(path)
    else:
        raise ValueError(f"Unsupported binary format: {path}")
    if mtime is not None:
        _BINARY_CACHE[key] = (mtime, img)
    return img


_BINARY_CACHE: Dict[str, tuple[float, BinaryImage]] = {}


def clear_binary_cache() -> None:
    _BINARY_CACHE.clear()
