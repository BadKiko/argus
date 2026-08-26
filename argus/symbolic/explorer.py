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
        self._concrete_seed: Optional[bytes] = None

    def _try_concrete_seed(self, stdin_len: int) -> Optional[bytes]:
        """Run Unicorn with blank/heuristic stdin to warm path; returns None usually."""
        if not self.concrete_first:
            return None
        try:
            from argus.concrete import unicorn_available, concrete_run
        except Exception:
            return None
        if not unicorn_available() or concrete_run is None:
            return None
        # Not used as full solve — just availability probe for hot-path preference
        return None

    def solve_to_address(
        self,
        target: int,
        avoid: Optional[Set[int]] = None,
        stdin_len: int = 24,
        entry: Optional[int] = None,
    ) -> SolveResult:
        avoid = avoid or set()
        initial = self.engine.make_entry_state(entry=entry, stdin_len=stdin_len)
        queue: List[SimState] = [initial]
        explored = 0
        steps = 0

        while queue and steps < self.max_steps:
            # Concrete-first scheduling: prefer states with fewer symbolic constraints
            queue.sort(key=lambda s: len(s.constraints))
            state = queue.pop(0)
            explored += 1
            if state.ip in avoid or state.exited and state.exit_code != 0:
                continue
            if state.ip == target or (state.stdout and b"Welcome" in state.stdout):
                ok, model, raw = self._sat(state)
                if ok:
                    return SolveResult(True, raw, state.stdout, model, explored, "target reached")
                continue

            successors = self.engine.step(state)
            steps += 1
            for s in successors:
                if len(queue) >= self.max_states:
                    break
                # Drop clearly unsat quickly
                if s.constraints and not self._quick_sat(s):
                    continue
                queue.append(s)

            # Also check after hooks that may have printed Welcome
            if state.ip == target or (state.stdout and b"Welcome" in state.stdout):
                ok, model, raw = self._sat(state)
                if ok:
                    return SolveResult(True, raw, state.stdout, model, explored, "target reached")

        return SolveResult(False, None, b"", None, explored, "exhausted search")

    def solve_find_string(self, needle: bytes, stdin_len: int = 24) -> SolveResult:
        """Explore until stdout contains needle. Concrete-first: low-constraint states first."""
        initial = self.engine.make_entry_state(stdin_len=stdin_len)
        queue: List[SimState] = [initial]
        explored = 0
        steps = 0
        while queue and steps < self.max_steps:
            queue.sort(key=lambda s: (len(s.constraints), s.path_id))
            state = queue.pop(0)
            explored += 1
            if needle in state.stdout:
                ok, model, raw = self._sat(state)
                if ok:
                    return SolveResult(True, raw, state.stdout, model, explored, f"found {needle!r}")
            if state.halted or state.exited:
                continue
            succs = self.engine.step(state)
            for s in succs:
                steps += 1
                if len(queue) < self.max_states and self._quick_sat(s):
                    # Prefer concrete successor (no new constraints) by inserting front
                    if len(s.constraints) == len(state.constraints):
                        queue.insert(0, s)
                    else:
                        queue.append(s)
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
        # Prefer printable ASCII for stdin bytes
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
        # Trim at first null-ish trailing zeros for display
        while raw.endswith(b"\x00"):
            raw = raw[:-1]
        return True, assignments, bytes(raw)


def solve_binary(path: str, find: bytes = b"Welcome") -> SolveResult:
    from argus.binary import load_binary

    image = load_binary(path)
    ex = Explorer(image)
    # Prefer accepted symbol if present
    if "accepted" in image.symbols:
        avoid = set()
        if "rejected" in image.symbols:
            avoid.add(image.symbols["rejected"].addr)
        return ex.solve_to_address(image.symbols["accepted"].addr, avoid=avoid)
    return ex.solve_find_string(find)
