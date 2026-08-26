# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
import pytest
from argus.engine.integrity_slicer import InterlockingIntegritySlicer
from argus.targets.interlocking_target import InterlockingTarget

def test_interlocking_integrity_invariant_solving():
    target = InterlockingTarget()
    slicer = InterlockingIntegritySlicer()

    res = slicer.solve_hash_invariant(
        code_bytes=target.code_bytes,
        target_expected_hash=target.expected_hash,
        state_variable_input=0x12345678
    )

    assert res["is_valid"] is True
    # Verify state matches concrete execution
    expected_state = target.execute_state_step(0x12345678, target.code_bytes)
    assert int(res["entangled_state_out"], 16) == expected_state
