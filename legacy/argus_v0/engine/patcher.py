# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
PE Binary Patcher & Code Rewriting Engine.
Translates RVAs to raw file offsets, applies in-place byte modifications,
NOP-sleds, branch inversions, and updates PE Header Checksums.
"""
from typing import Dict, List, Tuple, Optional, Any
import os
import pefile

class BinaryPatcher:
    def __init__(self, target_pe_path: str):
        self.target_pe_path = target_pe_path
        if not os.path.exists(target_pe_path):
            raise FileNotFoundError(f"Target binary not found: {target_pe_path}")
        with open(target_pe_path, "rb") as f:
            self.data = bytearray(f.read())
        self.pe = pefile.PE(data=self.data)
        self.patches_applied: List[Dict[str, Any]] = []

    def rva_to_offset(self, rva: int) -> Optional[int]:
        """
        Converts a Relative Virtual Address (RVA) to physical file byte offset.
        """
        return self.pe.get_offset_from_rva(rva)

    def patch_rva(self, rva: int, new_bytes: bytes, description: str = "") -> bool:
        """
        Overwrites bytes at the specified RVA.
        """
        offset = self.rva_to_offset(rva)
        if offset is None or offset + len(new_bytes) > len(self.data):
            return False
        
        old_bytes = bytes(self.data[offset:offset + len(new_bytes)])
        self.data[offset:offset + len(new_bytes)] = new_bytes
        
        self.patches_applied.append({
            "rva": hex(rva),
            "file_offset": hex(offset),
            "old_bytes": old_bytes.hex(),
            "new_bytes": new_bytes.hex(),
            "description": description
        })
        return True

    def nop_range(self, rva: int, length: int, description: str = "NOP-sled fill") -> bool:
        """
        Fills a range of instructions with NOP (0x90) bytes.
        """
        return self.patch_rva(rva, b"\x90" * length, description=description)

    def invert_conditional_branch(self, rva: int) -> bool:
        """
        Inverts short conditional jumps:
        JZ / JE (0x74) <-> JNZ / JNE (0x75)
        JA / JNBE (0x77) <-> JBE / JNA (0x76)
        """
        offset = self.rva_to_offset(rva)
        if offset is None:
            return False
        opcode = self.data[offset]
        inversions = {
            0x74: 0x75, # JZ -> JNZ
            0x75: 0x74, # JNZ -> JZ
            0x76: 0x77, # JBE -> JA
            0x77: 0x76, # JA -> JBE
        }
        if opcode in inversions:
            new_opcode = inversions[opcode]
            return self.patch_rva(rva, bytes([new_opcode]), description=f"Invert branch (0x{opcode:02X} -> 0x{new_opcode:02X})")
        return False

    def save_patched_binary(self, output_path: str) -> str:
        """
        Recalculates PE checksum and writes the patched binary to disk.
        """
        # Re-parse modified buffer in pefile to recalculate checksum
        patched_pe = pefile.PE(data=self.data)
        patched_pe.OPTIONAL_HEADER.CheckSum = patched_pe.generate_checksum()
        final_data = patched_pe.write()
        
        with open(output_path, "wb") as f:
            f.write(final_data)
        
        patched_pe.close()
        return output_path
