from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Union

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

from .image import BinaryImage, Section, Symbol


def load_elf(path: Path) -> BinaryImage:
    with path.open("rb") as f:
        elf = ELFFile(f)
        if elf.get_machine_arch() not in ("x64", "x86"):
            raise ValueError(f"Unsupported ELF arch: {elf.get_machine_arch()}")

        bits = 64 if elf.elfclass == 64 else 32
        arch = "x86_64" if bits == 64 else "x86"
        entry = int(elf.header["e_entry"])

        sections: list[Section] = []
        memory: Dict[int, int] = {}

        for sec in elf.iter_sections():
            name = sec.name or ""
            addr = int(sec["sh_addr"])
            size = int(sec["sh_size"])
            flags = int(sec["sh_flags"])
            data = sec.data() if sec["sh_type"] != "SHT_NOBITS" else b""
            executable = bool(flags & 0x4)
            writable = bool(flags & 0x1)
            readable = True
            if size == 0 and not data:
                continue
            sections.append(
                Section(
                    name=name,
                    addr=addr,
                    size=size,
                    data=data,
                    executable=executable,
                    writable=writable,
                    readable=readable,
                )
            )
            if data and addr:
                for i, b in enumerate(data):
                    memory[addr + i] = b

        # Also map PT_LOAD segments (covers gaps / BSS zeroing intent)
        for seg in elf.iter_segments():
            if seg["p_type"] != "PT_LOAD":
                continue
            vaddr = int(seg["p_vaddr"])
            data = seg.data()
            for i, b in enumerate(data):
                memory.setdefault(vaddr + i, b)

        symbols: Dict[str, Symbol] = {}
        for sec in elf.iter_sections():
            if not isinstance(sec, SymbolTableSection):
                continue
            for sym in sec.iter_symbols():
                name = sym.name
                if not name:
                    continue
                addr = int(sym["st_value"])
                size = int(sym["st_size"])
                st_info = sym["st_info"]
                is_func = st_info.get("type") == "STT_FUNC"
                shndx = sym["st_shndx"]
                is_import = shndx in ("SHN_UNDEF", 0)
                prev = symbols.get(name)
                if prev and not prev.is_import and is_import:
                    continue
                if prev and prev.is_import and not is_import:
                    pass  # replace import stub with defined symbol
                symbols[name] = Symbol(
                    name=name,
                    addr=addr,
                    size=size,
                    is_function=is_func,
                    is_import=bool(is_import),
                )

        imports = _resolve_plt_imports(elf, symbols)

        return BinaryImage(
            path=str(path),
            fmt="elf",
            arch=arch,
            bits=bits,
            entry=entry,
            sections=sections,
            symbols=symbols,
            imports=imports,
            memory=memory,
        )


def _resolve_plt_imports(elf: ELFFile, symbols: Dict[str, Symbol]) -> Dict[int, str]:
    """Map PLT stub addresses -> imported function names when possible."""
    imports: Dict[int, str] = {}

    # Prefer .rela.plt / .rel.plt relocation targets (GOT entries), then find PLT stubs
    rela = elf.get_section_by_name(".rela.plt") or elf.get_section_by_name(".rel.plt")
    dynsym = elf.get_section_by_name(".dynsym")
    if rela is None or dynsym is None or not isinstance(rela, RelocationSection):
        # Fallback: use known symbol addresses if present as PLT labels (rare)
        return imports

    got_to_name: Dict[int, str] = {}
    for reloc in rela.iter_relocations():
        sym = dynsym.get_symbol(reloc["r_info_sym"])
        if sym and sym.name:
            got_to_name[int(reloc["r_offset"])] = sym.name

    plt = elf.get_section_by_name(".plt")
    if plt is None:
        return imports

    plt_addr = int(plt["sh_addr"])
    plt_data = plt.data()
    # Classic x86_64 PLT entry is 16 bytes; first entry is resolver
    entry_size = 16
    # Each PLT entry (after 0) typically: jmp *GOT; push imm; jmp resolver
    # GOT pointer is encoded in the jmp rip-relative.
    for off in range(entry_size, len(plt_data), entry_size):
        stub = plt_addr + off
        chunk = plt_data[off : off + 6]
        # ff 25 xx xx xx xx  = jmp QWORD PTR [rip+disp]
        if len(chunk) >= 6 and chunk[0:2] == b"\xff\x25":
            disp = int.from_bytes(chunk[2:6], "little", signed=True)
            got = stub + 6 + disp
            name = got_to_name.get(got)
            if name:
                imports[stub] = name
        else:
            # Some PLTs use different layout; try sequential match by order
            pass

    # If rip-relative parse failed, assign by relocation order
    if not imports and got_to_name:
        names = list(got_to_name.values())
        for i, name in enumerate(names):
            imports[plt_addr + entry_size * (i + 1)] = name

    return imports


def list_elf_needed(path: Union[Path, str]) -> List[str]:
    """Return DT_NEEDED sonames from the dynamic section."""
    names: List[str] = []
    seen: set[str] = set()
    with Path(path).open("rb") as f:
        elf = ELFFile(f)
        for seg in elf.iter_segments():
            if seg["p_type"] != "PT_DYNAMIC":
                continue
            for tag in seg.iter_tags():
                if tag.entry.d_tag != "DT_NEEDED":
                    continue
                name = tag.needed
                if not name or name in seen:
                    continue
                seen.add(name)
                names.append(name)
            break
    return names
