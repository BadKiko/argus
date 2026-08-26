# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
import pytest
from argus.engine.emulator import CPUSandbox
from argus.targets.packed_oep_target import PackedOEPTarget

def test_cpu_sandbox_oep_detection():
    target = PackedOEPTarget()
    sandbox = CPUSandbox(initial_pc=target.stub_base)

    # Map stub and OEP section
    sandbox.map_memory(target.stub_base, 4096, target.stub_bytes)
    sandbox.map_memory(target.oep_base, 4096, target.oep_bytes)

    # Run emulation
    res = sandbox.emulate_step(max_steps=50, target_oep_section=(0x140005000, 0x140006000))

    assert res["oep_detected"] is True
    assert res["oep_address"] == hex(target.oep_base)
