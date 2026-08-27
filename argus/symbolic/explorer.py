from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Set

import z3

from argus.binary.image import BinaryImage
from argus.symbolic.engine import Engine
from argus.symbolic.state import SimState, conc_or_none


@dataclass
class SolveResult:
    success: bool
    stdin: Optional[bytes]
    stdout: bytes
    model: Optional[dict]
    paths_explored: int
    message: str


class Explorer:
    def __init__(
        self,
        image: BinaryImage,
        max_steps: int = 50_000,
        max_states: int = 256,
        concrete_first: bool = True,
    ):
        self.image = image
        self.engine = Engine(image)
        self.max_steps = max_steps
        self.max_states = max_states
        self.concrete_first = concrete_first

    def solve_to_address(
        self,
        target: int,
        avoid: Optional[Set[int]] = None,
        stdin_len: int = 24,
        entry: Optional[int] = None,
        find_needle: Optional[bytes] = None,
    ) -> SolveResult:
        avoid = avoid or set()
        initial = self.engine.make_entry_state(entry=entry, stdin_len=stdin_len)
        # Dual buckets: concrete (no/few constraints) vs symbolic
        concrete_q: List[SimState] = [initial]
        symbolic_q: List[SimState] = []
        explored = 0
        steps = 0

        while (concrete_q or symbolic_q) and steps < self.max_steps:
            if self.concrete_first and concrete_q:
                state = concrete_q.pop(0)
            elif concrete_q:
                state = concrete_q.pop(0)
            else:
                state = symbolic_q.pop(0)
            explored += 1
            if state.ip in avoid or (state.exited and state.exit_code != 0):
                continue
            if state.ip == target or (find_needle and find_needle in state.stdout):
                ok, model, raw = self._sat(state)
                if ok:
                    return SolveResult(True, raw, state.stdout, model, explored, "target reached")
                continue

            successors = self.engine.step(state)
            steps += 1
            for s in successors:
                if len(concrete_q) + len(symbolic_q) >= self.max_states:
                    break
                if s.constraints and not self._quick_sat(s):
                    continue
                if len(s.constraints) <= len(state.constraints):
                    concrete_q.append(s)
                else:
                    symbolic_q.append(s)

            if state.ip == target or (find_needle and find_needle in state.stdout):
                ok, model, raw = self._sat(state)
                if ok:
                    return SolveResult(True, raw, state.stdout, model, explored, "target reached")

        return SolveResult(False, None, b"", None, explored, "exhausted search")

    def solve_find_string(self, needle: bytes, stdin_len: int = 24) -> SolveResult:
        initial = self.engine.make_entry_state(stdin_len=stdin_len)
        concrete_q: List[SimState] = [initial]
        symbolic_q: List[SimState] = []
        explored = 0
        steps = 0
        while (concrete_q or symbolic_q) and steps < self.max_steps:
            state = concrete_q.pop(0) if concrete_q else symbolic_q.pop(0)
            explored += 1
            if needle in state.stdout:
                ok, model, raw = self._sat(state)
                if ok:
                    return SolveResult(True, raw, state.stdout, model, explored, f"found {needle!r}")
            if state.halted or state.exited:
                continue
            for s in self.engine.step(state):
                steps += 1
                if len(concrete_q) + len(symbolic_q) >= self.max_states:
                    break
                if not self._quick_sat(s):
                    continue
                if len(s.constraints) <= len(state.constraints):
                    concrete_q.insert(0, s)
                else:
                    symbolic_q.append(s)
        return SolveResult(False, None, b"", None, explored, "not found")

    def _quick_sat(self, state: SimState) -> bool:
        if not state.constraints:
            return True
        solver = z3.Solver()
        solver.set("timeout", 200)
        for c in state.constraints:
            solver.add(c)
        return solver.check() != z3.unsat

    def _sat(self, state: SimState):
        solver = z3.Solver()
        for c in state.constraints:
            solver.add(c)
        for b in state.stdin:
            if isinstance(b, z3.ExprRef):
                solver.add(z3.And(b >= 0x20, b <= 0x7E))
        if solver.check() != z3.sat:
            return False, None, None
        model = solver.model()
        raw = bytearray()
        assignments = {}
        for i, b in enumerate(state.stdin):
            if isinstance(b, int):
                raw.append(b & 0xFF)
                assignments[f"stdin_{i}"] = b & 0xFF
            else:
                v = model.eval(b, model_completion=True)
                val = v.as_long() & 0xFF
                raw.append(val)
                assignments[f"stdin_{i}"] = val
        while raw.endswith(b"\x00"):
            raw = raw[:-1]
        return True, assignments, bytes(raw)


def solve_binary(path: str, find: Optional[bytes] = None) -> SolveResult:
    from argus.binary import load_binary

    image = load_binary(path)
    # Optional concrete warm-up (does not replace symbolic solve)
    try:
        from argus.concrete.concolic import concrete_until_branch

        concrete_until_branch(image, stdin=b"A" * 16 + b"\n")
    except Exception:
        pass
    ex = Explorer(image)
    if "accepted" in image.symbols:
        avoid = set()
        if "rejected" in image.symbols:
            avoid.add(image.symbols["rejected"].addr)
        return ex.solve_to_address(
            image.symbols["accepted"].addr, avoid=avoid, find_needle=find
        )
    if not find:
        return SolveResult(
            False, None, b"", None, 0, "find needle required (no hardcoded success string)"
        )
    return ex.solve_find_string(find)
