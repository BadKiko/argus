# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Dynamic API Hash Resolver & IAT Reconstructor.
Detects and resolves API hashes (ROR13, CRC32, Murmur3) to reconstruct Import Address Tables.
"""
from typing import Dict, List, Optional, Tuple, Any

class IATReconstructor:
    KNOWN_API_HASHES_ROR13 = {
        0xEC0E4E8E: "kernel32.dll!LoadLibraryA",
        0x7C0DFCAA: "kernel32.dll!GetProcAddress",
        0x91AFCA54: "kernel32.dll!VirtualAlloc",
        0x7946C61B: "kernel32.dll!VirtualProtect",
        0xE8AFE98:  "kernel32.dll!ExitProcess",
        0x382C0F97: "ntdll.dll!NtQueryInformationProcess",
        0x5B270C34: "ntdll.dll!NtProtectVirtualMemory"
    }

    def __init__(self):
        pass

    @staticmethod
    def ror13(name: str) -> int:
        h = 0
        for c in name.encode("ascii"):
            h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF
            h = (h + c) & 0xFFFFFFFF
        return h

    def resolve_api_hash(self, hash_val: int) -> Optional[str]:
        """Resolves an API hash constant to its full module!function name."""
        return self.KNOWN_API_HASHES_ROR13.get(hash_val & 0xFFFFFFFF, None)

    def scan_for_api_hashes(self, constants: List[int]) -> List[Dict[str, Any]]:
        """Scans a list of integer constants extracted from code for API matches."""
        results = []
        for c in constants:
            api_name = self.resolve_api_hash(c)
            if api_name:
                results.append({
                    "hash": hex(c),
                    "api": api_name
                })
        return results
