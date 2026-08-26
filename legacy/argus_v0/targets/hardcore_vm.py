# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Hardcore Multi-Round Feistel Virtual Machine Target.
Implements a 16-round nonlinear Feistel cipher structure inside an obfuscated dispatcher:
- Round function F(R, K) = ROL32((R ^ K) * 0x45D9F3B + 0x1337BEEF, 5)
- Dynamic state mutations and loop counters
- High entropy output designed to resist purely static symbolic algebraic reduction
"""
from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional, Any
import random

@dataclass
class FeistelVMInstr:
    opcode: str
    arg1: Optional[Any] = None
    arg2: Optional[Any] = None
    is_junk: bool = False

class HardcoreFeistelVM:
    def __init__(self, rounds: int = 16, seed: int = 1337):
        self.rounds = rounds
        self.rng = random.Random(seed)
        self.round_keys = [self.rng.randint(0x10000000, 0xFFFFFFFF) | 1 for _ in range(rounds)]

    def round_function(self, r_val: int, k_val: int) -> int:
        """F(R, K) = ROL32(((R ^ K) * 0x45D9F3B + 0x1337BEEF) & 0xFFFFFFFF, 5)"""
        mixed = ((r_val ^ k_val) * 0x45D9F3B + 0x1337BEEF) & 0xFFFFFFFF
        return ((mixed << 5) | (mixed >> 27)) & 0xFFFFFFFF

    def execute_concrete(self, left: int, right: int) -> Tuple[int, int, List[str]]:
        """
        Executes the Feistel network in concrete domain, logging the execution trace.
        """
        l = left & 0xFFFFFFFF
        r = right & 0xFFFFFFFF
        trace: List[str] = []

        for rnd in range(self.rounds):
            k = self.round_keys[rnd]
            f_out = self.round_function(r, k)
            new_r = (l ^ f_out) & 0xFFFFFFFF
            new_l = r
            trace.append(f"[ROUND {rnd:02d}] L=0x{l:08X}, R=0x{r:08X} -> F(R,K)=0x{f_out:08X} -> NewL=0x{new_l:08X}, NewR=0x{new_r:08X}")
            l, r = new_l, new_r

        return l, r, trace
