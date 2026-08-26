from __future__ import annotations

"""Linear MBA / opaque-predicate simplification using Z3 proofs."""

from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

import z3


@dataclass
class SimplifyResult:
    original: str
    simplified: str
    proved: bool


class MBASimplifier:
    """Prove equivalence of bitvector expressions to a simpler candidate."""

    def __init__(self, bits: int = 32):
        self.bits = bits

    def prove_equiv(self, f: z3.BoolRef | z3.BitVecRef, g: z3.BitVecRef) -> bool:
        x = None  # unused; f,g already closed
        s = z3.Solver()
        s.add(f != g)
        return s.check() == z3.unsat

    def simplify_binary_expr(
        self,
        expr_fn: Callable[[z3.BitVecRef, z3.BitVecRef], z3.BitVecRef],
        candidates: Optional[List[Tuple[str, Callable]]] = None,
    ) -> SimplifyResult:
        x = z3.BitVec("x", self.bits)
        y = z3.BitVec("y", self.bits)
        target = z3.simplify(expr_fn(x, y))
        if candidates is None:
            candidates = [
                ("x+y", lambda a, b: a + b),
                ("x-y", lambda a, b: a - b),
                ("x^y", lambda a, b: a ^ b),
                ("x&y", lambda a, b: a & b),
                ("x|y", lambda a, b: a | b),
                ("x", lambda a, b: a),
                ("y", lambda a, b: b),
                ("0", lambda a, b: z3.BitVecVal(0, self.bits)),
                ("-1", lambda a, b: z3.BitVecVal((1 << self.bits) - 1, self.bits)),
            ]
        for name, cand in candidates:
            c = cand(x, y)
            s = z3.Solver()
            s.set("timeout", 1000)
            s.add(target != c)
            if s.check() == z3.unsat:
                return SimplifyResult(str(target), name, True)
        return SimplifyResult(str(target), str(target), False)

    def is_opaque_true(self, pred: Callable[[z3.BitVecRef], z3.BoolRef]) -> bool:
        x = z3.BitVec("x", self.bits)
        s = z3.Solver()
        s.add(z3.Not(pred(x)))
        return s.check() == z3.unsat

    def is_opaque_false(self, pred: Callable[[z3.BitVecRef], z3.BoolRef]) -> bool:
        x = z3.BitVec("x", self.bits)
        s = z3.Solver()
        s.add(pred(x))
        return s.check() == z3.unsat


# Classic linear MBA identities (for demos/tests)
def mba_x_plus_y(x: z3.BitVecRef, y: z3.BitVecRef) -> z3.BitVecRef:
    # (x ^ y) + 2*(x & y) == x + y
    return (x ^ y) + (x & y) + (x & y)


def mba_x_xor_y(x: z3.BitVecRef, y: z3.BitVecRef) -> z3.BitVecRef:
    # (x | y) - (x & y) == x ^ y
    return (x | y) - (x & y)
