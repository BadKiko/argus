# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Advanced Target Benchmark: Complex VM-based License & HWID Validator.
Models commercial Anti-Tamper patterns:
- Control Flow Flattening (State Machine Dispatcher)
- Register & Stack Virtualization
- Opaque Predicates (Anti-Analysis)
- Multi-layer Nonlinear MBA Key Transformations
- Polymorphic Junk Instruction Injection
"""
import random
from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional, Any

class AdvancedVMOpcode:
    VM_NOP          = 0x00
    VM_LOAD_REG     = 0x01
    VM_STORE_REG    = 0x02
    VM_PUSH_IMM     = 0x03
    
    VM_ADD          = 0x10
    VM_SUB          = 0x11
    VM_XOR          = 0x12
    VM_AND          = 0x13
    VM_OR           = 0x14
    VM_ROL          = 0x15
    
    VM_UPDATE_STATE = 0x30
    VM_BRANCH_COND  = 0x31
    
    VM_JUNK_CALC    = 0x80
    VM_JUNK_STACK   = 0x81
    VM_OPAQUE_CHECK = 0x82
    
    VM_HALT         = 0xFF

@dataclass
class VMBytecodeInstr:
    opcode: int
    arg: Optional[Any] = None
    state_id: int = 0
    is_junk: bool = False
    comment: str = ""

class ComplexLicenseValidatorVM:
    def __init__(self, junk_density: float = 0.5, seed: int = 42):
        self.junk_density = junk_density
        self.rng = random.Random(seed)

    def generate_complex_validation_suite(self) -> List[VMBytecodeInstr]:
        """
        Generates a flattened validation routine:
        State 10: HWID collection & non-linear bitwise transform
        State 20: Number-theoretic opaque predicate inspection
        State 30: Multi-round cryptographic license token mixing
        State 40: Decision verification & termination
        """
        program: List[VMBytecodeInstr] = []

        # State 10: HWID Transform
        s10_block = [
            VMBytecodeInstr(AdvancedVMOpcode.VM_LOAD_REG, arg="HWID_IN", state_id=10, comment="Load HWID"),
            VMBytecodeInstr(AdvancedVMOpcode.VM_PUSH_IMM, arg=0x5A5A5A5A, state_id=10),
            VMBytecodeInstr(AdvancedVMOpcode.VM_XOR, state_id=10),
            VMBytecodeInstr(AdvancedVMOpcode.VM_JUNK_CALC, arg=0xDEAD, state_id=10, is_junk=True),
            VMBytecodeInstr(AdvancedVMOpcode.VM_STORE_REG, arg="VREG_0", state_id=10, comment="Store HWID_PART1"),
            
            VMBytecodeInstr(AdvancedVMOpcode.VM_LOAD_REG, arg="HWID_IN", state_id=10),
            VMBytecodeInstr(AdvancedVMOpcode.VM_PUSH_IMM, arg=0x0F0F0F0F, state_id=10),
            VMBytecodeInstr(AdvancedVMOpcode.VM_AND, state_id=10),
            VMBytecodeInstr(AdvancedVMOpcode.VM_PUSH_IMM, arg=2, state_id=10),
            VMBytecodeInstr(AdvancedVMOpcode.VM_ROL, state_id=10),
            VMBytecodeInstr(AdvancedVMOpcode.VM_LOAD_REG, arg="VREG_0", state_id=10),
            VMBytecodeInstr(AdvancedVMOpcode.VM_ADD, state_id=10),
            VMBytecodeInstr(AdvancedVMOpcode.VM_STORE_REG, arg="HWID_HASH", state_id=10, comment="Store HWID_HASH"),
            VMBytecodeInstr(AdvancedVMOpcode.VM_UPDATE_STATE, arg=20, state_id=10, comment="Transition -> State 20")
        ]

        # State 20: Opaque Predicate
        s20_block = [
            VMBytecodeInstr(AdvancedVMOpcode.VM_LOAD_REG, arg="HWID_HASH", state_id=20),
            VMBytecodeInstr(AdvancedVMOpcode.VM_OPAQUE_CHECK, arg="((x*x - x) & 1) == 0", state_id=20, is_junk=True),
            VMBytecodeInstr(AdvancedVMOpcode.VM_JUNK_STACK, arg=0x777, state_id=20, is_junk=True),
            VMBytecodeInstr(AdvancedVMOpcode.VM_UPDATE_STATE, arg=30, state_id=20, comment="Transition -> State 30")
        ]

        # State 30: Cryptographic Token Mixing
        s30_block = [
            VMBytecodeInstr(AdvancedVMOpcode.VM_LOAD_REG, arg="LICENSE_KEY", state_id=30),
            VMBytecodeInstr(AdvancedVMOpcode.VM_LOAD_REG, arg="HWID_HASH", state_id=30),
            VMBytecodeInstr(AdvancedVMOpcode.VM_XOR, state_id=30),
            VMBytecodeInstr(AdvancedVMOpcode.VM_PUSH_IMM, arg=0x1337BEEF, state_id=30),
            VMBytecodeInstr(AdvancedVMOpcode.VM_ADD, state_id=30),
            VMBytecodeInstr(AdvancedVMOpcode.VM_JUNK_CALC, arg=0x1111, state_id=30, is_junk=True),
            VMBytecodeInstr(AdvancedVMOpcode.VM_PUSH_IMM, arg=0xCAFEBABE, state_id=30),
            VMBytecodeInstr(AdvancedVMOpcode.VM_XOR, state_id=30),
            VMBytecodeInstr(AdvancedVMOpcode.VM_STORE_REG, arg="AUTH_TOKEN", state_id=30, comment="Store AUTH_TOKEN"),
            VMBytecodeInstr(AdvancedVMOpcode.VM_UPDATE_STATE, arg=40, state_id=30, comment="Transition -> State 40")
        ]

        # State 40: Verification & Termination
        s40_block = [
            VMBytecodeInstr(AdvancedVMOpcode.VM_LOAD_REG, arg="AUTH_TOKEN", state_id=40),
            VMBytecodeInstr(AdvancedVMOpcode.VM_PUSH_IMM, arg=0x00000000, state_id=40),
            VMBytecodeInstr(AdvancedVMOpcode.VM_SUB, state_id=40),
            VMBytecodeInstr(AdvancedVMOpcode.VM_STORE_REG, arg="IS_VALID", state_id=40),
            VMBytecodeInstr(AdvancedVMOpcode.VM_HALT, state_id=40, comment="Execution Complete")
        ]

        all_blocks = [s10_block, s20_block, s30_block, s40_block]
        for b in all_blocks:
            for instr in b:
                program.append(instr)
                
        return program

    def run_simulation(self, program: List[VMBytecodeInstr], hwid: int, license_key: int) -> Tuple[Dict[str, int], List[str]]:
        registers: Dict[str, int] = {"HWID_IN": hwid & 0xFFFFFFFF, "LICENSE_KEY": license_key & 0xFFFFFFFF}
        stack: List[int] = []
        trace_log: List[str] = []
        current_state = 10
        step_count = 0
        max_steps = 200

        state_map: Dict[int, List[VMBytecodeInstr]] = {}
        for instr in program:
            state_map.setdefault(instr.state_id, []).append(instr)

        while current_state in state_map and step_count < max_steps:
            block = state_map[current_state]
            trace_log.append(f"[DISPATCHER] Entering State {current_state}")
            
            for instr in block:
                step_count += 1
                op = instr.opcode
                tag = "[JUNK]" if instr.is_junk else "[REAL]"
                
                if op == AdvancedVMOpcode.VM_LOAD_REG:
                    val = registers.get(instr.arg, 0)
                    stack.append(val)
                    trace_log.append(f"  {tag} LOAD_REG {instr.arg} (0x{val:X})")
                elif op == AdvancedVMOpcode.VM_STORE_REG:
                    if stack:
                        val = stack.pop()
                        registers[instr.arg] = val
                        trace_log.append(f"  {tag} STORE_REG {instr.arg} = 0x{val:X}")
                elif op == AdvancedVMOpcode.VM_PUSH_IMM:
                    stack.append(instr.arg & 0xFFFFFFFF)
                    trace_log.append(f"  {tag} PUSH_IMM 0x{instr.arg:X}")
                elif op == AdvancedVMOpcode.VM_XOR:
                    if len(stack) >= 2:
                        b, a = stack.pop(), stack.pop()
                        res = (a ^ b) & 0xFFFFFFFF
                        stack.append(res)
                        trace_log.append(f"  {tag} XOR (0x{a:X} ^ 0x{b:X} = 0x{res:X})")
                elif op == AdvancedVMOpcode.VM_ADD:
                    if len(stack) >= 2:
                        b, a = stack.pop(), stack.pop()
                        res = (a + b) & 0xFFFFFFFF
                        stack.append(res)
                        trace_log.append(f"  {tag} ADD (0x{a:X} + 0x{b:X} = 0x{res:X})")
                elif op == AdvancedVMOpcode.VM_AND:
                    if len(stack) >= 2:
                        b, a = stack.pop(), stack.pop()
                        res = (a & b) & 0xFFFFFFFF
                        stack.append(res)
                        trace_log.append(f"  {tag} AND (0x{a:X} & 0x{b:X} = 0x{res:X})")
                elif op == AdvancedVMOpcode.VM_ROL:
                    if len(stack) >= 2:
                        shift, val = stack.pop(), stack.pop()
                        res = ((val << shift) | (val >> (32 - shift))) & 0xFFFFFFFF
                        stack.append(res)
                        trace_log.append(f"  {tag} ROL (0x{val:X} << {shift} = 0x{res:X})")
                elif op == AdvancedVMOpcode.VM_SUB:
                    if len(stack) >= 2:
                        b, a = stack.pop(), stack.pop()
                        res = (a - b) & 0xFFFFFFFF
                        stack.append(res)
                        trace_log.append(f"  {tag} SUB (0x{a:X} - 0x{b:X} = 0x{res:X})")
                elif op == AdvancedVMOpcode.VM_UPDATE_STATE:
                    current_state = instr.arg
                    trace_log.append(f"  [FLOW] Transition -> State {current_state}")
                elif op == AdvancedVMOpcode.VM_OPAQUE_CHECK:
                    trace_log.append(f"  {tag} OPAQUE_PREDICATE evaluated -> TRUE")
                elif op == AdvancedVMOpcode.VM_JUNK_CALC or op == AdvancedVMOpcode.VM_JUNK_STACK:
                    trace_log.append(f"  {tag} DUMMY_JUNK_OP")
                elif op == AdvancedVMOpcode.VM_HALT:
                    trace_log.append("  [SYS] Execution HALTED")
                    return registers, trace_log
                    
        return registers, trace_log
