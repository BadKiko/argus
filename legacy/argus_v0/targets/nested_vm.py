# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Nested Double-Virtual Machine Benchmark (Metamorphic Stack-in-Stack VM).
An inner virtual machine's bytecode is interpreted by an outer virtual machine,
testing deep multi-level execution trace analysis and contextual taint propagation.
"""
from typing import List, Dict, Tuple, Optional, Any
from dataclasses import dataclass

class InnerOpcode:
    INNER_LOAD = 0x01
    INNER_ADD  = 0x02
    INNER_XOR  = 0x03
    INNER_STORE= 0x04
    INNER_HALT = 0xFF

class OuterOpcode:
    OUTER_FETCH_OP  = 0x10
    OUTER_DISPATCH  = 0x20
    OUTER_EXEC_ARITH= 0x30
    OUTER_STATE_INC = 0x40
    OUTER_HALT      = 0xFE

@dataclass
class NestedVMState:
    outer_pc: int = 0
    inner_pc: int = 0
    registers: Dict[str, int] = None
    inner_stack: List[int] = None

class NestedDoubleVM:
    def __init__(self):
        pass

    def run_nested_program(self, inner_bytecode: List[int], initial_regs: Dict[str, int]) -> Tuple[Dict[str, int], List[str]]:
        """
        Executes an inner program through an outer interpreter layer.
        """
        regs = dict(initial_regs)
        stack: List[int] = []
        trace: List[str] = []
        inner_ip = 0

        while inner_ip < len(inner_bytecode):
            op = inner_bytecode[inner_ip]
            trace.append(f"[OUTER_VM] Interpreting Inner IP {inner_ip:03d}, Opcode: 0x{op:02X}")

            if op == InnerOpcode.INNER_LOAD:
                # Load reg from next byte
                reg_name = "R" + str(inner_bytecode[inner_ip + 1])
                val = regs.get(reg_name, 0)
                stack.append(val)
                trace.append(f"  [INNER_VM] LOAD {reg_name} (val=0x{val:X})")
                inner_ip += 2
            elif op == InnerOpcode.INNER_ADD:
                if len(stack) >= 2:
                    b, a = stack.pop(), stack.pop()
                    res = (a + b) & 0xFFFFFFFF
                    stack.append(res)
                    trace.append(f"  [INNER_VM] ADD 0x{a:X} + 0x{b:X} = 0x{res:X}")
                inner_ip += 1
            elif op == InnerOpcode.INNER_XOR:
                if len(stack) >= 2:
                    b, a = stack.pop(), stack.pop()
                    res = (a ^ b) & 0xFFFFFFFF
                    stack.append(res)
                    trace.append(f"  [INNER_VM] XOR 0x{a:X} ^ 0x{b:X} = 0x{res:X}")
                inner_ip += 1
            elif op == InnerOpcode.INNER_STORE:
                dest_reg = "R" + str(inner_bytecode[inner_ip + 1])
                if stack:
                    val = stack.pop()
                    regs[dest_reg] = val
                    trace.append(f"  [INNER_VM] STORE {dest_reg} = 0x{val:X}")
                inner_ip += 2
            elif op == InnerOpcode.INNER_HALT:
                trace.append("  [INNER_VM] HALT execution")
                break
            else:
                inner_ip += 1

        return regs, trace
