# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
import pytest
import z3
from argus.targets.hardcore_vm import HardcoreFeistelVM
from argus.engine.concolic import ConcolicPathEngine

def test_hardcore_feistel_concrete_execution():
    vm = HardcoreFeistelVM(rounds=16, seed=42)
    l_out, r_out, trace = vm.execute_concrete(0xDEADBEEF, 0xCAFEBABE)
    
    assert len(trace) == 16
    assert isinstance(l_out, int)
    assert isinstance(r_out, int)

def test_concolic_symbolic_unrolling():
    vm = HardcoreFeistelVM(rounds=4, seed=42)
    engine = ConcolicPathEngine(bit_size=32)
    
    res = engine.execute_concolic_unroll(vm, num_unroll_rounds=4)
    assert res["unrolled_rounds"] == 4
    assert res["symbolic_left_ast"] is not None
    assert res["symbolic_right_ast"] is not None
