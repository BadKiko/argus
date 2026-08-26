# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
import pytest
from argus.targets.nested_vm import NestedDoubleVM, InnerOpcode

def test_nested_double_vm_execution():
    vm = NestedDoubleVM()
    
    # Inner program: R2 = (R0 + R1) ^ R0
    # LOAD R0 (0x01 0x00), LOAD R1 (0x01 0x01), ADD (0x02), LOAD R0 (0x01 0x00), XOR (0x03), STORE R2 (0x04 0x02), HALT (0xFF)
    inner_program = [
        InnerOpcode.INNER_LOAD, 0,
        InnerOpcode.INNER_LOAD, 1,
        InnerOpcode.INNER_ADD,
        InnerOpcode.INNER_LOAD, 0,
        InnerOpcode.INNER_XOR,
        InnerOpcode.INNER_STORE, 2,
        InnerOpcode.INNER_HALT
    ]
    
    initial_regs = {"R0": 0x10, "R1": 0x20}
    # Expected: (0x10 + 0x20) ^ 0x10 = 0x30 ^ 0x10 = 0x20
    regs, trace = vm.run_nested_program(inner_program, initial_regs)
    
    assert regs["R2"] == 0x20
    assert any("[OUTER_VM]" in line for line in trace)
    assert any("[INNER_VM]" in line for line in trace)
