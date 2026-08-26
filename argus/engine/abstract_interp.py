# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Abstract Interpretation & Loop Invariant Summarization Engine.
Evaluates code over the Interval Lattice [Lower, Upper] to deduce loop invariants,
value bounds, and closed-form induction summaries for million-scale loops in O(1) time.
"""
from typing import Dict, Tuple, Optional, Any, List

class Interval:
    def __init__(self, lower: int, upper: int):
        self.lower = lower
        self.upper = upper

    def is_constant(self) -> bool:
        return self.lower == self.upper

    def join(self, other: 'Interval') -> 'Interval':
        """Union / Join (⊔) in Interval Lattice"""
        return Interval(min(self.lower, other.lower), max(self.upper, other.upper))

    def meet(self, other: 'Interval') -> 'Interval':
        """Intersection / Meet (⊓) in Interval Lattice"""
        return Interval(max(self.lower, other.lower), min(self.upper, other.upper))

    def add(self, other: 'Interval') -> 'Interval':
        return Interval(self.lower + other.lower, self.upper + other.upper)

    def sub(self, other: 'Interval') -> 'Interval':
        return Interval(self.lower - other.upper, self.upper - other.lower)

    def __repr__(self):
        return f"[{self.lower}, {self.upper}]"

class LoopSummarizer:
    def __init__(self):
        pass

    def summarize_linear_induction_loop(self, init_val: int, step_val: int, iterations: int) -> Dict[str, Any]:
        """
        Deduces closed-form arithmetic summary for inductive loop variable without unrolling:
        x_final = init_val + step_val * iterations
        """
        final_val = (init_val + step_val * iterations) & 0xFFFFFFFF
        interval = Interval(min(init_val, final_val), max(init_val, final_val))

        return {
            "initial_value": hex(init_val),
            "step": step_val,
            "total_iterations": iterations,
            "final_value": hex(final_val),
            "invariant_interval": str(interval),
            "is_closed_form": True
        }
