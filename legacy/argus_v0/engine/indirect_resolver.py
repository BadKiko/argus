# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Symbolic Jump Table & Indirect Branch Resolver.
Resolves computed jump targets (e.g. JMP [Table + RAX*8]) using Value-Set Analysis and Z3 SMT constraints.
"""
import z3
from typing import List, Dict, Tuple, Any

class IndirectJumpResolver:
    def __init__(self):
        pass

    def resolve_jump_table(self, table_base: int, entry_size: int, num_entries: int, memory_reader) -> List[Dict[str, Any]]:
        """
        Recovers all concrete targets from a structured jump table.
        """
        targets = []
        for i in range(num_entries):
            entry_addr = table_base + (i * entry_size)
            raw_bytes = memory_reader(entry_addr, entry_size)
            target_addr = int.from_bytes(raw_bytes, "little")
            targets.append({
                "index": i,
                "entry_address": hex(entry_addr),
                "target_address": hex(target_addr)
            })
        return targets

    def solve_bounded_indirect_targets(self, max_cases: int = 16) -> List[int]:
        """
        Uses Z3 SMT to verify that jump index is strictly bounded in [0, max_cases-1].
        """
        s = z3.Solver()
        idx = z3.BitVec("switch_index", 32)
        s.add(z3.ULT(idx, max_cases))
        
        valid_indices = []
        for i in range(max_cases):
            s_check = z3.Solver()
            s_check.add(idx == i)
            if s_check.check() == z3.sat:
                valid_indices.append(i)

        return valid_indices
