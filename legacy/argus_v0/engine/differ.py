# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Binary & Basic Block Differ.
Compares original binary bytes vs patched binary bytes and presents a visual diff.
"""
from typing import List, Dict, Any
import capstone

class BinaryDiffer:
    def __init__(self, bit_size: int = 64):
        self.bit_size = bit_size
        mode = capstone.CS_MODE_64 if bit_size == 64 else capstone.CS_MODE_32
        self.md = capstone.Cs(capstone.CS_ARCH_X86, mode)

    def diff_buffers(self, orig_bytes: bytes, patched_bytes: bytes, base_address: int = 0x1000) -> List[Dict[str, Any]]:
        """
        Compares two byte buffers and detects changed bytes and disassembled instruction modifications.
        """
        diffs = []
        min_len = min(len(orig_bytes), len(patched_bytes))
        
        i = 0
        while i < min_len:
            if orig_bytes[i] != patched_bytes[i]:
                # Find contiguous modified chunk
                start = i
                while i < min_len and orig_bytes[i] != patched_bytes[i]:
                    i += 1
                chunk_len = i - start
                
                orig_chunk = orig_bytes[start:start + chunk_len]
                patched_chunk = patched_bytes[start:start + chunk_len]
                
                addr = base_address + start
                
                # Disassemble if possible
                orig_ins = [f"{ins.mnemonic} {ins.op_str}" for ins in self.md.disasm(orig_chunk, addr)]
                patched_ins = [f"{ins.mnemonic} {ins.op_str}" for ins in self.md.disasm(patched_chunk, addr)]

                diffs.append({
                    "address": hex(addr),
                    "length": chunk_len,
                    "orig_hex": orig_chunk.hex(),
                    "patched_hex": patched_chunk.hex(),
                    "orig_disasm": orig_ins or ["raw bytes"],
                    "patched_disasm": patched_ins or ["raw bytes"]
                })
            else:
                i += 1
        return diffs
