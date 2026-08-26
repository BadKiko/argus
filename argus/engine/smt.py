# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
SMT Solver Engine interfacing with the Z3 Theorem Prover.
Provides formal verification of semantic equivalence and opaque predicate analysis.
"""
from typing import Tuple, Optional
import z3

class SMTEngine:
    def __init__(self, bit_size: int = 32):
        self.bit_size = bit_size

    def create_bitvec(self, name: str) -> z3.BitVecRef:
        return z3.BitVec(name, self.bit_size)

    def prove_equivalence(self, expr_a: z3.BitVecRef, expr_b: z3.BitVecRef) -> Tuple[bool, Optional[z3.ModelRef]]:
        """
        Formally proves mathematical equivalence between two expressions across all 2^N states.
        Checks if there exists any input satisfying (expr_a != expr_b).
        If unsat -> identical.
        If sat -> non-equivalent (counterexample returned).
        """
        solver = z3.Solver()
        solver.add(expr_a != expr_b)
        
        res = solver.check()
        if res == z3.unsat:
            return True, None
        elif res == z3.sat:
            return False, solver.model()
        else:
            raise RuntimeError("SMT Solver returned unknown result")

    def check_opaque_predicate(self, predicate_expr: z3.BoolRef) -> str:
        """
        Evaluates the invariant condition of an opaque predicate:
        - ALWAYS_TRUE
        - ALWAYS_FALSE
        - DYNAMIC
        """
        s_true = z3.Solver()
        s_true.add(z3.Not(predicate_expr))
        is_never_false = (s_true.check() == z3.unsat)

        s_false = z3.Solver()
        s_false.add(predicate_expr)
        is_never_true = (s_false.check() == z3.unsat)

        if is_never_false:
            return "ALWAYS_TRUE"
        elif is_never_true:
            return "ALWAYS_FALSE"
        return "DYNAMIC"
