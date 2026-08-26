# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Algebraic & SMT-guided Simplifier for Mixed Boolean-Arithmetic (MBA) expressions.
"""
from typing import Tuple
import z3
from .smt import SMTEngine

class MBASimplifier:
    def __init__(self, bit_size: int = 32):
        self.smt = SMTEngine(bit_size=bit_size)
        self.bit_size = bit_size

    def simplify_ast(self, expr: z3.BitVecRef) -> z3.BitVecRef:
        return z3.simplify(expr)

    def simplify_and_verify(self, obfuscated_expr: z3.BitVecRef) -> Tuple[z3.BitVecRef, bool]:
        simplified = self.simplify_ast(obfuscated_expr)
        is_valid, _ = self.smt.prove_equivalence(obfuscated_expr, simplified)
        return simplified, is_valid

    def parse_python_mba_to_z3(self, mba_str: str, var_names: Tuple[str, ...]) -> z3.BitVecRef:
        z3_vars = {name: z3.BitVec(name, self.bit_size) for name in var_names}
        return eval(mba_str, {"__builtins__": None}, z3_vars)
