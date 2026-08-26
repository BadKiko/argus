# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Dynamic Memory Overlay & W^X Page Snapshot Engine.
Handles JIT, self-modifying code, and runtime unpacked pages by tracking Write -> Execute page transitions,
capturing memory snapshots, and overlaying dynamic sections onto PEParser virtual memory space.
"""
from typing import Dict, List, Tuple, Optional, Any
import numpy as np

class MemoryPage:
    PAGE_READ = 0x01
    PAGE_WRITE = 0x02
    PAGE_EXECUTE = 0x04
    PAGE_RWX = PAGE_READ | PAGE_WRITE | PAGE_EXECUTE

    def __init__(self, base_addr: int, size: int = 4096, permissions: int = PAGE_READ | PAGE_WRITE):
        self.base_addr = base_addr
        self.size = size
        self.permissions = permissions
        self.data = bytearray(size)
        self.has_been_written = False
        self.has_transitioned_to_exec = False

    def write_bytes(self, offset: int, data_bytes: bytes):
        if not (self.permissions & self.PAGE_WRITE):
            raise PermissionError(f"MemoryPage at 0x{self.base_addr:x} is not writable")
        end = offset + len(data_bytes)
        if end > self.size:
            raise ValueError("Buffer overflow in MemoryPage write")
        self.data[offset:end] = data_bytes
        self.has_been_written = True

    def set_permissions(self, new_permissions: int) -> bool:
        """
        Updates permissions. Detects Write-XOR-Execute (W^X) transition into executable code.
        Returns True if a W^X transition occurred (code unpacking event).
        """
        old_perms = self.permissions
        self.permissions = new_permissions
        if self.has_been_written and (new_permissions & self.PAGE_EXECUTE) and not (old_perms & self.PAGE_EXECUTE):
            self.has_transitioned_to_exec = True
            return True
        return False

    def read_bytes(self, offset: int, length: int) -> bytes:
        return bytes(self.data[offset:offset + length])

class DynamicOverlayEngine:
    def __init__(self):
        self.pages: Dict[int, MemoryPage] = {}
        self.captured_snapshots: List[Dict[str, Any]] = []

    def allocate_page(self, base_addr: int, size: int = 4096, perms: int = MemoryPage.PAGE_READ | MemoryPage.PAGE_WRITE) -> MemoryPage:
        page = MemoryPage(base_addr, size, perms)
        self.pages[base_addr] = page
        return page

    def write_memory(self, virtual_addr: int, data: bytes):
        page_base = virtual_addr & ~0xFFF
        offset = virtual_addr & 0xFFF
        if page_base not in self.pages:
            self.allocate_page(page_base)
        self.pages[page_base].write_bytes(offset, data)

    def protect_memory(self, virtual_addr: int, permissions: int) -> Optional[Dict[str, Any]]:
        page_base = virtual_addr & ~0xFFF
        if page_base in self.pages:
            page = self.pages[page_base]
            is_wx_transition = page.set_permissions(permissions)
            if is_wx_transition:
                snapshot = {
                    "base_addr": page.base_addr,
                    "size": page.size,
                    "data": bytes(page.data),
                    "entropy": self._calculate_entropy(page.data)
                }
                self.captured_snapshots.append(snapshot)
                return snapshot
        return None

    def read_memory(self, virtual_addr: int, length: int) -> bytes:
        page_base = virtual_addr & ~0xFFF
        offset = virtual_addr & 0xFFF
        if page_base in self.pages:
            return self.pages[page_base].read_bytes(offset, length)
        return b"\x00" * length

    def _calculate_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        probs = counts[counts > 0] / len(data)
        return -float(np.sum(probs * np.log2(probs)))
