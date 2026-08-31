from __future__ import annotations

from pathlib import Path
from typing import Dict

import pefile

from .image import BinaryImage, Section, Symbol, SparseMemory


def load_pe(path: Path) -> BinaryImage:
    pe = pefile.PE(str(path), fast_load=True)
    pe.parse_data_directories(
        directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"],
        ]
    )

    is_64 = pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]
    bits = 64 if is_64 else 32
    arch = "x86_64" if is_64 else "x86"
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    entry = image_base + int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)

    sections: list[Section] = []
    for s in pe.sections:
        name = s.Name.decode("utf-8", errors="ignore").strip("\x00")
        addr = image_base + int(s.VirtualAddress)
        data = s.get_data()
        size = max(int(s.Misc_VirtualSize), len(data))
        chars = int(s.Characteristics)
        sections.append(
            Section(
                name=name,
                addr=addr,
                size=size,
                data=data,
                executable=bool(chars & 0x20000000),
                writable=bool(chars & 0x80000000),
                readable=bool(chars & 0x40000000),
            )
        )

    symbols: Dict[str, Symbol] = {}
    imports: Dict[int, str] = {}

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry_imp in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry_imp.imports:
                if imp.name is None or imp.address is None:
                    continue
                name = imp.name.decode("utf-8", errors="ignore")
                addr = int(imp.address)
                imports[addr] = name
                symbols[name] = Symbol(name=name, addr=addr, is_function=True, is_import=True)

    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if not exp.name:
                continue
            name = exp.name.decode("utf-8", errors="ignore")
            addr = image_base + int(exp.address)
            symbols[name] = Symbol(name=name, addr=addr, is_function=True)

    # Windows x64 .pdata: exact runtime functions table (O(1) function recovery)
    if hasattr(pe, "DIRECTORY_ENTRY_EXCEPTION"):
        for entry_exc in pe.DIRECTORY_ENTRY_EXCEPTION:
            st = getattr(entry_exc, "struct", None)
            if not st:
                continue
            begin = image_base + int(st.BeginAddress)
            end = image_base + int(st.EndAddress)
            name = f"sub_{begin:x}"
            if name not in symbols:
                symbols[name] = Symbol(name=name, addr=begin, size=max(1, end - begin), is_function=True)

    pe.close()
    return BinaryImage(
        path=str(path),
        fmt="pe",
        arch=arch,
        bits=bits,
        entry=entry,
        sections=sections,
        symbols=symbols,
        imports=imports,
        memory=SparseMemory(sections),
    )


def list_pe_dependent_dlls(path: Path | str) -> list[str]:
    """Return imported DLL basenames (order-preserved, case-insensitive unique)."""
    pe = pefile.PE(str(path), fast_load=True)
    try:
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
        names: list[str] = []
        seen: set[str] = set()
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry_imp in pe.DIRECTORY_ENTRY_IMPORT:
                raw = entry_imp.dll
                if not raw:
                    continue
                name = raw.decode("utf-8", errors="ignore") if isinstance(raw, bytes) else str(raw)
                key = name.lower()
                if key in seen:
                    continue
                seen.add(key)
                names.append(name)
        return names
    finally:
        pe.close()
