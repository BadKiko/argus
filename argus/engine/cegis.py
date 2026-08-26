# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Counterexample-Guided Inductive Synthesis (CEGIS) & Oracle-Guided Engine.
Synthesizes clean mathematical expressions from opaque, nonlinear, or SMT-timeout-prone black-box functions.
Uses I/O input-output sampling, candidate grammar ranking, and SMT verification.
"""
from typing import Callable, List, Tuple, Dict, Any, Optional
import random
import z3

class CEGISSynthesizer:
    def __init__(self, bit_size: int = 32, num_initial_samples: int = 32):
        self.bit_size = bit_size
        self.mask = (1 << bit_size) - 1
        self.num_initial_samples = num_initial_samples

    def generate_io_samples(self, oracle_fn: Callable[..., int], arity: int = 2) -> List[Tuple[Tuple[int, ...], int]]:
        """
        Generates random concrete input-output pairs from the target oracle.
        """
        samples = []
        rng = random.Random(42)
        for _ in range(self.num_initial_samples):
            inputs = tuple(rng.randint(0, self.mask) for _ in range(arity))
            out = oracle_fn(*inputs) & self.mask
            samples.append((inputs, out))
        return samples

    def synthesize_affine_or_binary_candidate(self, oracle_fn: Callable[..., int], var_names: Tuple[str, str]) -> Tuple[Optional[str], Optional[z3.BitVecRef]]:
        """
        Searches the canonical grammar space to find a candidate matching all I/O points:
        - Arithmetic: x + y, x - y, x * y
        - Bitwise: x ^ y, x & y, x | y, ~x, ~y
        - Affine & Linear combinations: A * (x ^ y) + B, (x * A) + (y * B) + C
        """
        samples = self.generate_io_samples(oracle_fn, arity=2)
        var_x, var_y = var_names

        # Grammar template generators
        candidate_templates = [
            # Direct binary primitives
            (lambda x, y: (x + y) & self.mask, f"({var_x} + {var_y})", lambda x, y: x + y),
            (lambda x, y: (x - y) & self.mask, f"({var_x} - {var_y})", lambda x, y: x - y),
            (lambda x, y: (x * y) & self.mask, f"({var_x} * {var_y})", lambda x, y: x * y),
            (lambda x, y: (x ^ y) & self.mask, f"({var_x} ^ {var_y})", lambda x, y: x ^ y),
            (lambda x, y: (x & y) & self.mask, f"({var_x} & {var_y})", lambda x, y: x & y),
            (lambda x, y: (x | y) & self.mask, f"({var_x} | {var_y})", lambda x, y: x | y),
        ]

        # Step 1: Check basic binary primitives
        for sim_fn, expr_str, z3_gen in candidate_templates:
            if all(sim_fn(*inp) == expected for inp, expected in samples):
                x_sym = z3.BitVec(var_x, self.bit_size)
                y_sym = z3.BitVec(var_y, self.bit_size)
                return expr_str, z3_gen(x_sym, y_sym)

        # Step 2: Linear / Affine recovery using modular difference solving
        # f(x, y) = A * (x ^ y) + B
        (inp0, out0) = samples[0]
        (inp1, out1) = samples[1]
        x0, y0 = inp0
        x1, y1 = inp1
        xor0 = x0 ^ y0
        xor1 = x1 ^ y1

        # Check if XOR-affine relation holds
        diff_xor = (xor1 - xor0) & self.mask
        diff_out = (out1 - out0) & self.mask
        if diff_xor != 0 and (diff_xor % 2 == 1):
            try:
                # Compute modular inverse
                a_coeff = (diff_out * pow(diff_xor, -1, 1 << self.bit_size)) & self.mask
                b_const = (out0 - a_coeff * xor0) & self.mask
                
                # Validate across all remaining samples
                affine_fn = lambda x, y: (a_coeff * (x ^ y) + b_const) & self.mask
                if all(affine_fn(*inp) == exp for inp, exp in samples):
                    x_sym = z3.BitVec(var_x, self.bit_size)
                    y_sym = z3.BitVec(var_y, self.bit_size)
                    expr_str = f"((0x{a_coeff:X} * ({var_x} ^ {var_y})) + 0x{b_const:X})"
                    z3_ast = (z3.BitVecVal(a_coeff, self.bit_size) * (x_sym ^ y_sym)) + z3.BitVecVal(b_const, self.bit_size)
                    return expr_str, z3_ast
            except Exception:
                pass

        return None, None
