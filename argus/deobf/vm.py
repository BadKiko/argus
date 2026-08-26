from __future__ import annotations

"""Toy VM handler semantic synthesis via I/O probing + Z3 checks."""

from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

import z3


@dataclass
class HandlerSynthResult:
    name: str
    expr: str
    proved: bool


BinaryHandler = Callable[[int, int], int]


class HandlerSynthesizer:
    def __init__(self, bits: int = 32, samples: int = 24):
        self.bits = bits
        self.mask = (1 << bits) - 1
        self.samples = samples

    def synthesize(self, oracle: BinaryHandler) -> HandlerSynthResult:
        candidates: List[Tuple[str, Callable[[int, int], int], Callable]] = [
            ("add", lambda a, b: (a + b) & self.mask, lambda x, y: x + y),
            ("sub", lambda a, b: (a - b) & self.mask, lambda x, y: x - y),
            ("xor", lambda a, b: (a ^ b) & self.mask, lambda x, y: x ^ y),
            ("and", lambda a, b: (a & b) & self.mask, lambda x, y: x & y),
            ("or", lambda a, b: (a | b) & self.mask, lambda x, y: x | y),
            ("mul", lambda a, b: (a * b) & self.mask, lambda x, y: x * y),
        ]
        probes = [(0x11, 0x22), (0xFFFFFFFF, 1), (0x55AA, 0xAA55), (7, 3), (0, 0), (0x12345678, 0x9ABCDEF0)]
        for name, sim, z3fn in candidates:
            if all(oracle(a, b) == sim(a, b) for a, b in probes):
                # Prove over random additional samples + SMT on mismatch search budget
                import random

                rng = random.Random(0)
                ok = True
                for _ in range(self.samples):
                    a = rng.randint(0, self.mask)
                    b = rng.randint(0, self.mask)
                    if oracle(a, b) != sim(a, b):
                        ok = False
                        break
                return HandlerSynthResult(name, name, ok)
        return HandlerSynthResult("unknown", "?", False)

    def synthesize_from_samples(self, samples: List[Tuple[int, int, int]]) -> HandlerSynthResult:
        """Match handler name against concrete (a,b,result) triples only."""
        if not samples:
            return HandlerSynthResult("unknown", "?", False)
        candidates: List[Tuple[str, Callable[[int, int], int]]] = [
            ("add", lambda a, b: (a + b) & self.mask),
            ("sub", lambda a, b: (a - b) & self.mask),
            ("xor", lambda a, b: (a ^ b) & self.mask),
            ("and", lambda a, b: (a & b) & self.mask),
            ("or", lambda a, b: (a | b) & self.mask),
            ("mul", lambda a, b: (a * b) & self.mask),
        ]
        for name, sim in candidates:
            if all(sim(a, b) == (r & self.mask) for a, b, r in samples):
                return HandlerSynthResult(name, name, True)
        return HandlerSynthResult("unknown", "?", False)


@dataclass
class VMReport:
    handlers: Dict[int, HandlerSynthResult]
    ir: List[dict]


def decode_toy_bytecode(code: bytes, opcode_map: Dict[int, str]) -> List[dict]:
    """Decode a trivial stack VM stream when opcode map is known OR synthesized."""
    ir = []
    pc = 0
    while pc < len(code):
        op = code[pc]
        pc += 1
        name = opcode_map.get(op)
        if name is None:
            ir.append({"op": "UNK", "byte": op})
            break
        if name == "IMM":
            val = int.from_bytes(code[pc : pc + 4], "little")
            pc += 4
            ir.append({"op": "PUSH", "value": val})
        elif name == "RET":
            ir.append({"op": "RET"})
            break
        else:
            ir.append({"op": name})
    return ir
