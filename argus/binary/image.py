from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


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
    # Flat sparse memory image for analysis / emulation
    memory: Dict[int, int] = field(default_factory=dict)

    def read_bytes(self, addr: int, size: int) -> bytes:
        out = bytearray()
        for i in range(size):
            out.append(self.memory.get(addr + i, 0))
        return bytes(out)

    def write_bytes(self, addr: int, data: bytes) -> None:
        for i, b in enumerate(data):
            self.memory[addr + i] = b

    def section_at(self, addr: int) -> Optional[Section]:
        for s in self.sections:
            if s.addr <= addr < s.addr + max(s.size, len(s.data)):
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
    raw = path.read_bytes()
    if raw[:4] == b"\x7fELF":
        from .elf import load_elf

        return load_elf(path)
    if raw[:2] == b"MZ":
        from .pe import load_pe

        return load_pe(path)
    raise ValueError(f"Unsupported binary format: {path}")
