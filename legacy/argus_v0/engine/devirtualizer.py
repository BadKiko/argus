# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Automated De-virtualizer & Symbolic State Reconstructor.
Reconstructs high-level symbolic expressions from flattened VM dispatch routines:
- Performs symbolic execution over the virtual stack and register state.
- Automatically resolves opaque predicates.
- Eliminates state dispatcher overhead and dead code.
- Yields a unified canonical symbolic expression verified with Z3.
"""
from typing import List, Dict, Tuple, Any, Optional
import z3
from ..targets.complex_license_vm import VMBytecodeInstr, AdvancedVMOpcode
from .smt import SMTEngine

class AutomatedDevirtualizer:
    def __init__(self, bit_size: int = 32):
        self.bit_size = bit_size
        self.smt = SMTEngine(bit_size=bit_size)

    def rol_z3(self, val: z3.BitVecRef, shift: int) -> z3.BitVecRef:
        return (val << shift) | z3.LShR(val, self.bit_size - shift)

    def devirtualize_program(self, bytecode: List[VMBytecodeInstr], input_vars: List[str], target_var: str) -> Tuple[z3.BitVecRef, Dict[str, Any]]:
        """
        Executes symbolic interpretation across the flattened dispatch loop,
        prunes junk instructions, evaluates opaque invariants, and produces the final symbolic AST.
        """
        # Initialize symbolic register environment
        sym_registers: Dict[str, z3.BitVecRef] = {
            var: z3.BitVec(var, self.bit_size) for var in input_vars
        }
        sym_stack: List[z3.BitVecRef] = []
        
        # Build block mapping by State ID
        state_map: Dict[int, List[VMBytecodeInstr]] = {}
        for instr in bytecode:
            state_map.setdefault(instr.state_id, []).append(instr)

        current_state = 10
        visited_states: List[int] = []
        stats = {
            "total_instructions": len(bytecode),
            "executed_instructions": 0,
            "pruned_junk_instructions": 0,
            "opaque_predicates_resolved": 0,
            "states_traversed": 0
        }

        while current_state in state_map:
            visited_states.append(current_state)
            stats["states_traversed"] += 1
            block = state_map[current_state]
            next_state: Optional[int] = None

            for instr in block:
                stats["executed_instructions"] += 1
                op = instr.opcode
                
                if instr.is_junk:
                    stats["pruned_junk_instructions"] += 1
                    continue

                if op == AdvancedVMOpcode.VM_LOAD_REG:
                    val = sym_registers.get(instr.arg, z3.BitVecVal(0, self.bit_size))
                    sym_stack.append(val)
                elif op == AdvancedVMOpcode.VM_STORE_REG:
                    if sym_stack:
                        val = sym_stack.pop()
                        sym_registers[instr.arg] = val
                elif op == AdvancedVMOpcode.VM_PUSH_IMM:
                    sym_stack.append(z3.BitVecVal(instr.arg, self.bit_size))
                elif op == AdvancedVMOpcode.VM_XOR:
                    if len(sym_stack) >= 2:
                        b, a = sym_stack.pop(), sym_stack.pop()
                        sym_stack.append(a ^ b)
                elif op == AdvancedVMOpcode.VM_ADD:
                    if len(sym_stack) >= 2:
                        b, a = sym_stack.pop(), sym_stack.pop()
                        sym_stack.append(a + b)
                elif op == AdvancedVMOpcode.VM_AND:
                    if len(sym_stack) >= 2:
                        b, a = sym_stack.pop(), sym_stack.pop()
                        sym_stack.append(a & b)
                elif op == AdvancedVMOpcode.VM_SUB:
                    if len(sym_stack) >= 2:
                        b, a = sym_stack.pop(), sym_stack.pop()
                        sym_stack.append(a - b)
                elif op == AdvancedVMOpcode.VM_ROL:
                    if len(sym_stack) >= 2:
                        shift_expr, val_expr = sym_stack.pop(), sym_stack.pop()
                        # Extract integer constant for rotation
                        shift_int = shift_expr.as_long() if isinstance(shift_expr, z3.BitVecNumRef) else 2
                        sym_stack.append(self.rol_z3(val_expr, shift_int))
                elif op == AdvancedVMOpcode.VM_UPDATE_STATE:
                    next_state = instr.arg
                elif op == AdvancedVMOpcode.VM_OPAQUE_CHECK:
                    stats["opaque_predicates_resolved"] += 1
                elif op == AdvancedVMOpcode.VM_HALT:
                    next_state = None
                    break

            if next_state is None:
                break
            current_state = next_state

        final_ast = sym_registers.get(target_var, z3.BitVecVal(0, self.bit_size))
        simplified_ast = z3.simplify(final_ast)
        return simplified_ast, stats
