# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
import pytest
import z3
from argus.engine.shadow_state import ShadowEnvironment

def test_shadow_state_peb_and_rdtsc_determinism():
    env = ShadowEnvironment(is_64bit=True)

    # Verify Clean PEB (BeingDebugged = 0)
    assert env.peb_data[0x02] == 0x00

    # Verify Monotonic RDTSC (Anti-Timing Protection)
    eax1, edx1 = env.emulate_rdtsc(100)
    eax2, edx2 = env.emulate_rdtsc(100)
    val1 = (edx1 << 32) | eax1
    val2 = (edx2 << 32) | eax2
    assert val2 > val1
    assert (val2 - val1) == 100

    # Verify CPUID non-hypervisor
    cpuid_res = env.emulate_cpuid(1)
    # Check bit 31 of ECX is 0 (no hypervisor flag)
    assert (cpuid_res["ecx"] & (1 << 31)) == 0

    # Verify Z3 SMT constraint
    solver = z3.Solver()
    constraint = env.get_symbolic_peb_constraint(solver)
    solver.add(constraint)
    assert solver.check() == z3.sat
