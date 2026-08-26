# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
x86_64 Machine Code Lifter & Symbolic Translator using Capstone Disassembler.
Lifts raw assembly instructions into symbolic Z3 BitVector ASTs.
"""
from typing import Dict, List, Tuple, Any, Optional
import capstone as cs
import z3

class X86Lifter:
    def __init__(self, bit_size: int = 64):
        self.bit_size = bit_size
        self.md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
        self.md.detail = True

    def _normalize_reg(self, reg_name: str) -> str:
        # Standardize register names across 32/64 bit
        mapping = {
            "eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
            "esi": "rsi", "edi": "rdi", "ebp": "rbp", "esp": "rsp",
            "r8d": "r8", "r9d": "r9", "r10d": "r10", "r11d": "r11"
        }
        return mapping.get(reg_name.lower(), reg_name.lower())

    def _parse_operand(self, op_str: str, env: Dict[str, z3.BitVecRef]) -> z3.BitVecRef:
        op_str = op_str.strip()
        if op_str.startswith("0x") or op_str.isdigit() or (op_str.startswith("-0x")):
            val = int(op_str, 0)
            return z3.BitVecVal(val, self.bit_size)
        
        reg_key = self._normalize_reg(op_str)
        if reg_key not in env:
            env[reg_key] = z3.BitVec(reg_key, self.bit_size)
        return env[reg_key]

    def lift_code_bytes(self, raw_bytes: bytes, initial_regs: Optional[List[str]] = None) -> Tuple[Dict[str, z3.BitVecRef], List[str]]:
        """
        Disassembles raw binary machine code and computes symbolic output states for all modified registers.
        """
        env: Dict[str, z3.BitVecRef] = {}
        if initial_regs:
            for r in initial_regs:
                norm = self._normalize_reg(r)
                env[norm] = z3.BitVec(norm, self.bit_size)

        disasm_log: List[str] = []

        for instr in self.md.disasm(raw_bytes, 0x1000):
            mnemonic = instr.mnemonic.lower()
            op_str = instr.op_str
            disasm_log.append(f"0x{instr.address:04X}: {mnemonic:<6} {op_str}")

            parts = [p.strip() for p in op_str.split(",")] if op_str else []
            if not parts:
                continue

            dest_reg = self._normalize_reg(parts[0])
            if dest_reg not in env:
                env[dest_reg] = z3.BitVec(dest_reg, self.bit_size)

            if mnemonic == "mov":
                if len(parts) >= 2:
                    src_val = self._parse_operand(parts[1], env)
                    env[dest_reg] = src_val
            elif mnemonic == "add":
                if len(parts) >= 2:
                    src_val = self._parse_operand(parts[1], env)
                    env[dest_reg] = env[dest_reg] + src_val
            elif mnemonic == "sub":
                if len(parts) >= 2:
                    src_val = self._parse_operand(parts[1], env)
                    env[dest_reg] = env[dest_reg] - src_val
            elif mnemonic == "xor":
                if len(parts) >= 2:
                    if parts[0] == parts[1]:
                        env[dest_reg] = z3.BitVecVal(0, self.bit_size)
                    else:
                        src_val = self._parse_operand(parts[1], env)
                        env[dest_reg] = env[dest_reg] ^ src_val
            elif mnemonic == "and":
                if len(parts) >= 2:
                    src_val = self._parse_operand(parts[1], env)
                    env[dest_reg] = env[dest_reg] & src_val
            elif mnemonic == "or":
                if len(parts) >= 2:
                    src_val = self._parse_operand(parts[1], env)
                    env[dest_reg] = env[dest_reg] | src_val
            elif mnemonic == "not":
                env[dest_reg] = ~env[dest_reg]
            elif mnemonic == "shl":
                if len(parts) >= 2:
                    shift = self._parse_operand(parts[1], env)
                    env[dest_reg] = env[dest_reg] << shift
            elif mnemonic == "shr":
                if len(parts) >= 2:
                    shift = self._parse_operand(parts[1], env)
                    env[dest_reg] = z3.LShR(env[dest_reg], shift)
            elif mnemonic == "rol":
                if len(parts) >= 2:
                    shift_val = int(parts[1], 0) if parts[1].startswith("0x") or parts[1].isdigit() else 2
                    val = env[dest_reg]
                    env[dest_reg] = (val << shift_val) | z3.LShR(val, self.bit_size - shift_val)

        # Simplify resulting register formulas
        simplified_env = {r: z3.simplify(expr) for r, expr in env.items()}
        return simplified_env, disasm_log
