# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
import pytest
from argus.engine.exception_cfg import ExceptionCFGBuilder, ExceptionType
from argus.targets.seh_dispatch_target import SEHDispatchTarget

def test_exception_cfg_veh_edge_recovery():
    target = SEHDispatchTarget()
    builder = ExceptionCFGBuilder()
    
    # 1. Register active VEH handler
    builder.register_veh_handler(
        handler_rva=target.veh_handler_rva,
        exception_code=ExceptionType.DIVIDE_BY_ZERO,
        target_rva=target.target_hidden_rva
    )

    # 2. Resolve faulting instruction
    res = builder.resolve_faulting_instruction(target.fault_rva, target.faulting_opcode)

    assert res is not None
    assert res["is_stitched"] is True
    assert res["exception_type"] == ExceptionType.DIVIDE_BY_ZERO
    assert res["implicit_target_rva"] == hex(target.target_hidden_rva)
