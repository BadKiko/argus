# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
import pytest
from argus.engine.ssa_optimizer import SSAOptimizer

def test_ssa_optimizer_gvn_and_dce():
    optimizer = SSAOptimizer()

    # Redundant code:
    # v0 = CONST(10)
    # v1 = CONST(20)
    # v2 = ADD(v0, v1) -> Folded to CONST(30)
    # v3 = ADD(v0, v1) -> GVN Match with v2
    # v4 = CONST(999)  -> Dead code
    # v5 = XOR(v2, v3) -> Return sink
    raw_ir = [
        {"dest": "v0", "op": "CONST", "args": ["10"]},
        {"dest": "v1", "op": "CONST", "args": ["20"]},
        {"dest": "v2", "op": "ADD", "args": ["v0", "v1"]},
        {"dest": "v3", "op": "ADD", "args": ["v0", "v1"]},
        {"dest": "v4", "op": "CONST", "args": ["999"]},
        {"dest": "v5", "op": "XOR", "args": ["v2", "v3"]}
    ]

    optimized = optimizer.optimize_ir_block(raw_ir)

    # v4 (dead code) must be eliminated
    dests = [instr["dest"] for instr in optimized]
    assert "v4" not in dests
    assert len(optimized) < len(raw_ir)
