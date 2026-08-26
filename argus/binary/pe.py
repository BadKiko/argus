from __future__ import annotations

from pathlib import Path
from typing import Dict

import pefile

from .image import BinaryImage, Section, Symbol


def load_pe(path: Path) -> BinaryImage:
    pe = pefile.PE(str(path), fast_load=True)
    pe.parse_data_directories(
        directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
        ]
    )

    is_64 = pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]
    bits = 64 if is_64 else 32
    arch = "x86_64" if is_64 else "x86"
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    entry = image_base + int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)

    sections: list[Section] = []
    memory: Dict[int, int] = {}
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
        for i, b in enumerate(data):
            memory[addr + i] = b

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
        memory=memory,
    )
