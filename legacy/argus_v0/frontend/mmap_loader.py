# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Memory-Mapped Streaming Binary Loader.
Enables low-memory on-demand paging and RVA-to-offset reading for large binaries (100MB - 1GB+).
"""
import mmap
import os
from typing import Optional, Tuple, Dict, Any

class MmapBinaryLoader:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.file_size = os.path.getsize(filepath)
        self._file = open(filepath, "rb")
        self._mmap = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)
        self.sections: Dict[str, Dict[str, int]] = {}

    def add_section_mapping(self, name: str, virtual_address: int, virtual_size: int, raw_offset: int, raw_size: int):
        """Registers a section's RVA and file offset for translation."""
        self.sections[name] = {
            "rva": virtual_address,
            "virtual_size": virtual_size,
            "raw_offset": raw_offset,
            "raw_size": raw_size
        }

    def rva_to_file_offset(self, rva: int) -> Optional[int]:
        """Translates an RVA address into a physical file offset."""
        for sec in self.sections.values():
            if sec["rva"] <= rva < sec["rva"] + sec["virtual_size"]:
                return sec["raw_offset"] + (rva - sec["rva"])
        return None

    def read_rva_bytes(self, rva: int, length: int) -> bytes:
        """Reads bytes directly from memory-mapped view using RVA."""
        offset = self.rva_to_file_offset(rva)
        if offset is not None:
            return self.read_raw_bytes(offset, length)
        return b""

    def read_raw_bytes(self, offset: int, length: int) -> bytes:
        """Reads raw bytes at a physical file offset via mmap."""
        if offset + length > self.file_size:
            length = max(0, self.file_size - offset)
        return self._mmap[offset:offset + length]

    def close(self):
        if hasattr(self, "_mmap") and self._mmap:
            self._mmap.close()
        if hasattr(self, "_file") and self._file:
            self._file.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
