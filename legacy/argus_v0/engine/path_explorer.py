# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Goal-Driven Symbolic Path Exploration & Target Sink Solver.
Traverses symbolic branch constraints towards target win/success states,
solving for exact input buffers (passwords, tokens, license keys) using Z3 SMT.
"""
from typing import List, Dict, Tuple, Optional, Any
import z3

class SymbolicPathExplorer:
    def __init__(self, bit_size: int = 32):
        self.bit_size = bit_size
        self.solver = z3.Solver()
        self.path_constraints: List[z3.BoolRef] = []

    def create_symbolic_byte_buffer(self, name_prefix: str, length: int) -> List[z3.BitVecRef]:
        """
        Creates a list of 8-bit symbolic BitVectors representing an input string/buffer.
        """
        return [z3.BitVec(f"{name_prefix}_{i}", 8) for i in range(length)]

    def add_path_constraint(self, condition: z3.BoolRef):
        """
        Adds a branch condition constraint to the current symbolic execution path.
        """
        self.path_constraints.append(condition)
        self.solver.add(condition)

    def solve_for_target_sink(self, target_sink_condition: Optional[z3.BoolRef] = None) -> Tuple[bool, Optional[Dict[str, int]], Optional[bytes]]:
        """
        Queries the SMT solver for a satisfying assignment (model) that triggers the target sink state.
        Returns: (is_satisfiable, integer_assignments_dict, concrete_ascii_bytes)
        """
        if target_sink_condition is not None:
            self.solver.add(target_sink_condition)

        check_res = self.solver.check()
        if check_res == z3.sat:
            model = self.solver.model()
            assignments: Dict[str, int] = {}
            
            # Sort symbols by name to reconstruct sequential buffer bytes
            sorted_decls = sorted(model.decls(), key=lambda d: d.name())
            byte_values = []
            
            for decl in sorted_decls:
                val = model[decl].as_long()
                assignments[decl.name()] = val
                if val <= 0xFF:
                    byte_values.append(val)
            
            concrete_bytes = bytes(byte_values) if byte_values else None
            return True, assignments, concrete_bytes
        
        return False, None, None

    def reset(self):
        """
        Clears active solver state and path constraints.
        """
        self.solver.reset()
        self.path_constraints.clear()
