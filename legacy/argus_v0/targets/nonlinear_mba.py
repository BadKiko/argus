# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Nonlinear Mixed Boolean-Arithmetic (MBA) & Affine Transform Generator.
Constructs high-degree algebraic expressions over Z_(2^32) that trigger SMT solver hardness barriers:
- Cross-product term expansions: (x | y) * (x ^ y)
- Polynomial composition with modular inverse coefficients
- Invertible affine transformations: f(x) = (A * x + B) mod 2^32, where gcd(A, 2) == 1
"""
import random
from typing import Tuple, Dict, Any
import z3

class NonlinearMBAGenerator:
    def __init__(self, seed: int = 42, bit_size: int = 32):
        self.rng = random.Random(seed)
        self.bit_size = bit_size
        self.modulus = 1 << bit_size

    def _get_odd_constant(self) -> int:
        """Returns a random odd constant (invertible in Z_2^32)."""
        val = self.rng.randint(0x1000, 0x7FFFFFFF)
        return val | 1

    def generate_nonlinear_product_mba(self, x_name: str = "x", y_name: str = "y") -> Tuple[str, str]:
        """
        Generates a nonlinear MBA identity:
        Identity: x * y == (x & y) * (x | y) + (x & ~y) * (~x & y)  (all mod 2^32)
        """
        obf = f"(({x_name} & {y_name}) * ({x_name} | {y_name}) + ({x_name} & ~{y_name}) * (~{x_name} & {y_name}))"
        ground_truth = f"({x_name} * {y_name})"
        return obf, ground_truth

    def generate_affine_masked_mba(self, x_name: str = "x", y_name: str = "y") -> Tuple[str, str]:
        """
        Constructs an affine permutation layer combined with linear MBA substitutions.
        f(x, y) = ((A * (x ^ y) + B) * C) mod 2^32
        """
        a = self._get_odd_constant()
        b = self.rng.randint(0x100, 0xFFFF)
        
        # Obfuscate (x ^ y) as ((x | y) - (x & y))
        obf = f"((0x{a:X} * (({x_name} | {y_name}) - ({x_name} & {y_name})) + 0x{b:X}))"
        ground_truth = f"((0x{a:X} * ({x_name} ^ {y_name}) + 0x{b:X}))"
        return obf, ground_truth
