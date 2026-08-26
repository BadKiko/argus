# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
PE32+ x64 Exception Directory (.pdata) Function Boundary Parser.
Extracts RUNTIME_FUNCTION entries (BeginAddress, EndAddress, UnwindInfoAddress)
to instantly catalog functions without heuristic prologue scanning.
"""
import struct
from typing import List, Dict, Any, Tuple, Optional

class RuntimeFunctionEntry:
    def __init__(self, begin_rva: int, end_rva: int, unwind_rva: int):
        self.begin_rva = begin_rva
        self.end_rva = end_rva
        self.unwind_rva = unwind_rva
        self.size = end_rva - begin_rva

    def to_dict(self) -> Dict[str, Any]:
        return {
            "begin_rva": hex(self.begin_rva),
            "end_rva": hex(self.end_rva),
            "size": self.size,
            "unwind_rva": hex(self.unwind_rva)
        }

class PDataParser:
    ENTRY_SIZE = 12 # 3 x uint32

    def __init__(self):
        pass

    def parse_pdata_raw(self, pdata_bytes: bytes) -> List[RuntimeFunctionEntry]:
        """
        Parses raw .pdata section bytes into a list of RuntimeFunctionEntry objects.
        """
        entries = []
        total_entries = len(pdata_bytes) // self.ENTRY_SIZE

        for i in range(total_entries):
            offset = i * self.ENTRY_SIZE
            begin_rva, end_rva, unwind_rva = struct.unpack_from("<III", pdata_bytes, offset)
            if begin_rva != 0 and end_rva > begin_rva:
                entries.append(RuntimeFunctionEntry(begin_rva, end_rva, unwind_rva))

        return entries

    def get_function_at_rva(self, entries: List[RuntimeFunctionEntry], rva: int) -> Optional[Dict[str, Any]]:
        """Binary search / lookup for a function containing a given RVA."""
        for e in entries:
            if e.begin_rva <= rva < e.end_rva:
                return e.to_dict()
        return None
