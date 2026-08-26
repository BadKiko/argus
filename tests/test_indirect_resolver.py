# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
import pytest
from argus.engine.indirect_resolver import IndirectJumpResolver
from argus.targets.indirect_jump_target import IndirectJumpTarget

def test_indirect_jump_table_resolution():
    target = IndirectJumpTarget()
    resolver = IndirectJumpResolver()

    def mem_reader(addr: int, size: int) -> bytes:
        offset = addr - target.table_base
        return bytes(target.table_bytes[offset:offset+size])

    recovered = resolver.resolve_jump_table(
        table_base=target.table_base,
        entry_size=8,
        num_entries=4,
        memory_reader=mem_reader
    )

    assert len(recovered) == 4
    for i, t in enumerate(recovered):
        assert int(t["target_address"], 16) == target.targets[i]

    # Verify SMT bounded index cases
    cases = resolver.solve_bounded_indirect_targets(max_cases=4)
    assert cases == [0, 1, 2, 3]
