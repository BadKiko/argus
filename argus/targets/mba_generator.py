# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Synthetic Mixed Boolean-Arithmetic (MBA) and Opaque Predicate Benchmark Generator.
Used as formal ground truth for evaluating de-obfuscation algorithms.
"""
import random
from typing import Tuple, List

class MBAGenerator:
    def __init__(self, seed: int = 42):
        self.rng = random.Random(seed)

    def generate_linear_mba_add(self, x: str = "x", y: str = "y") -> Tuple[str, str]:
        """
        Generates obfuscated MBA equivalents for (x + y).
        Identities:
        1. (x ^ y) + 2 * (x & y)
        2. (x | y) + (x & y)
        3. 2 * (x | y) - (x ^ y)
        """
        variants = [
            f"({x} ^ {y}) + 2 * ({x} & {y})",
            f"({x} | {y}) + ({x} & {y})",
            f"2 * ({x} | {y}) - ({x} ^ {y})",
        ]
        return self.rng.choice(variants), f"{x} + {y}"

    def generate_linear_mba_xor(self, x: str = "x", y: str = "y") -> Tuple[str, str]:
        """
        Generates obfuscated MBA equivalents for (x ^ y).
        Identities:
        1. (x | y) - (x & y)
        2. (x + y) - 2 * (x & y)
        3. 2 * (x | y) - (x + y)
        """
        variants = [
            f"({x} | {y}) - ({x} & {y})",
            f"({x} + {y}) - 2 * ({x} & {y})",
            f"2 * ({x} | {y}) - ({x} + {y})"
        ]
        return self.rng.choice(variants), f"{x} ^ {y}"

    def generate_opaque_predicate_always_true(self, x: str = "x") -> str:
        """
        Generates a number-theoretic opaque predicate invariant that is ALWAYS TRUE for any integer x.
        Identity: (x * (x - 1)) & 1 == 0
        """
        return f"(({x} * {x} - {x}) & 1) == 0"

    def generate_opaque_predicate_always_false(self, x: str = "x") -> str:
        """
        Generates a number-theoretic opaque predicate invariant that is ALWAYS FALSE for any integer x.
        """
        return f"(7 * ({x} * {x}) + 1) % 7 == 0"
