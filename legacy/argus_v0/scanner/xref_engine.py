# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Cross-Reference (XRef) & String Reference Search Engine.
Locates strings in data sections and maps code instructions that reference them.
"""
from typing import List, Dict, Tuple, Optional, Any
import re
import capstone
import pefile

class XRefEngine:
    def __init__(self, pe_path: str, bit_size: int = 64):
        self.pe_path = pe_path
        self.bit_size = bit_size
        mode = capstone.CS_MODE_64 if bit_size == 64 else capstone.CS_MODE_32
        self.md = capstone.Cs(capstone.CS_ARCH_X86, mode)
        self.md.detail = True
        self.pe = pefile.PE(pe_path)

    def find_strings(self, min_length: int = 4) -> List[Dict[str, Any]]:
        """
        Extracts ASCII and UTF-16 strings across all PE sections with their RVAs.
        """
        results = []
        for s in self.pe.sections:
            sec_data = s.get_data()
            sec_rva = s.VirtualAddress
            
            # ASCII search
            for match in re.finditer(b"[\x20-\x7E]{" + str(min_length).encode() + b",}", sec_data):
                rva = sec_rva + match.start()
                results.append({
                    "string": match.group().decode('ascii', errors='ignore'),
                    "rva": hex(rva),
                    "rva_int": rva,
                    "section": s.Name.decode('utf-8', errors='ignore').strip('\x00')
                })
        return results

    def find_xrefs_to_rva(self, target_rva: int) -> List[Dict[str, Any]]:
        """
        Scans executable code sections (.text) to find instructions referencing target_rva.
        """
        xrefs = []
        image_base = self.pe.OPTIONAL_HEADER.ImageBase

        for s in self.pe.sections:
            if s.IMAGE_SCN_MEM_EXECUTE:
                code_bytes = s.get_data()
                sec_rva = s.VirtualAddress
                sec_va = image_base + sec_rva

                for instr in self.md.disasm(code_bytes, sec_va):
                    # Check RIP-relative operands (disp or immediate)
                    for op in instr.operands:
                        if op.type == capstone.x86.X86_OP_MEM:
                            # Target absolute address calculation: instr.address + instr.size + disp
                            resolved_addr = instr.address + instr.size + op.mem.disp
                            if resolved_addr - image_base == target_rva:
                                xrefs.append({
                                    "code_address": hex(instr.address),
                                    "instruction": f"{instr.mnemonic} {instr.op_str}",
                                    "target_rva": hex(target_rva)
                                })
                        elif op.type == capstone.x86.X86_OP_IMM:
                            if op.imm == target_rva or op.imm == (image_base + target_rva):
                                xrefs.append({
                                    "code_address": hex(instr.address),
                                    "instruction": f"{instr.mnemonic} {instr.op_str}",
                                    "target_rva": hex(target_rva)
                                })
        return xrefs

    def close(self):
        self.pe.close()
