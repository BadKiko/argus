# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Recursive Descent Disassembler Engine.
Follows execution control flow instead of linear sweep, robustly bypassing
overlapping instructions (e.g. JMP $+1, EB FF C0 tricks) and junk data paddings.
"""
from typing import Dict, List, Set, Tuple, Optional, Any
import capstone

class RecursiveDescentDisassembler:
    def __init__(self, is_64bit: bool = True):
        mode = capstone.CS_MODE_64 if is_64bit else capstone.CS_MODE_32
        self.cs = capstone.Cs(capstone.CS_ARCH_X86, mode)
        self.cs.detail = True

    def disassemble_flow(self, code_bytes: bytes, base_address: int) -> List[Dict[str, Any]]:
        """
        Recursively explores valid basic blocks following branch targets.
        """
        visited_addresses: Set[int] = set()
        queue: List[int] = [base_address]
        disassembled_instructions: List[Dict[str, Any]] = []

        code_len = len(code_bytes)

        while queue:
            curr_addr = queue.pop(0)
            if curr_addr in visited_addresses:
                continue

            offset = curr_addr - base_address
            if offset < 0 or offset >= code_len:
                continue

            # Disassemble instruction stream from current address
            for instr in self.cs.disasm(code_bytes[offset:], curr_addr):
                if instr.address in visited_addresses:
                    break

                visited_addresses.add(instr.address)
                instr_dict = {
                    "address": hex(instr.address),
                    "mnemonic": instr.mnemonic,
                    "op_str": instr.op_str,
                    "bytes": instr.bytes.hex(),
                    "size": instr.size
                }
                disassembled_instructions.append(instr_dict)

                # Control flow handling
                if instr.mnemonic.startswith("j"): # Jump instructions
                    # Direct conditional/unconditional jumps
                    if instr.op_str.startswith("0x"):
                        try:
                            target = int(instr.op_str, 16)
                            if target not in visited_addresses:
                                queue.append(target)
                        except ValueError:
                            pass
                    
                    if instr.mnemonic == "jmp":
                        # Unconditional jump terminates linear block
                        break
                elif instr.mnemonic in ["ret", "hlt"]:
                    break

        # Sort by address
        disassembled_instructions.sort(key=lambda x: int(x["address"], 16))
        return disassembled_instructions
