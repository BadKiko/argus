# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Binary Function Boundary & Branch Sink Scanner.
Identifies potential validation routines, authentication endpoints, and conditional sinks.
"""
from typing import List, Dict, Tuple, Optional, Any
import capstone

class FunctionScanner:
    def __init__(self, bit_size: int = 64):
        self.bit_size = bit_size
        mode = capstone.CS_MODE_64 if bit_size == 64 else capstone.CS_MODE_32
        self.md = capstone.Cs(capstone.CS_ARCH_X86, mode)
        self.md.detail = True

    def scan_functions_in_bytes(self, code_bytes: bytes, base_address: int = 0x1000) -> List[Dict[str, Any]]:
        """
        Scans raw machine code bytes to detect function prologues, branch sinks, and arithmetic density.
        """
        instructions = list(self.md.disasm(code_bytes, base_address))
        functions = []
        current_func = {
            "start_address": hex(base_address),
            "instructions": [],
            "crypto_density_score": 0.0,
            "has_conditional_branch": False,
            "is_potential_validator": False
        }

        crypto_opcodes = {"xor", "rol", "ror", "and", "or", "add", "sub", "imul", "not"}
        branch_opcodes = {"je", "jne", "jz", "jnz", "ja", "jb", "jae", "jbe", "jg", "jl"}

        for instr in instructions:
            current_func["instructions"].append(f"0x{instr.address:X}: {instr.mnemonic} {instr.op_str}")

            if instr.mnemonic.lower() in crypto_opcodes:
                current_func["crypto_density_score"] += 1.0

            if instr.mnemonic.lower() in branch_opcodes:
                current_func["has_conditional_branch"] = True

            # Function Epilogue: ret
            if instr.mnemonic.lower() in ["ret", "retn"]:
                total_ins = len(current_func["instructions"])
                if total_ins > 0:
                    current_func["crypto_density_score"] /= total_ins
                    current_func["is_potential_validator"] = (
                        current_func["has_conditional_branch"] and current_func["crypto_density_score"] > 0.10
                    )
                current_func["instruction_count"] = total_ins
                functions.append(current_func)
                
                # Start next function candidate
                current_func = {
                    "start_address": hex(instr.address + instr.size),
                    "instructions": [],
                    "crypto_density_score": 0.0,
                    "has_conditional_branch": False,
                    "is_potential_validator": False
                }

        if current_func["instructions"]:
            current_func["instruction_count"] = len(current_func["instructions"])
            functions.append(current_func)

        return functions
