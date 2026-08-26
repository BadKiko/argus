# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Deterministic Shadow State & Anti-Analysis Neutralization Engine.
Provides high-fidelity deterministic models for Windows PEB, TEB, KUSER_SHARED_DATA,
and hardware instructions (CPUID, RDTSC) for isolated symbolic analysis without triggering hardware breakpoints (DRx).
"""
import struct
import z3
from typing import Dict, Any, Optional, Tuple

class ShadowEnvironment:
    def __init__(self, is_64bit: bool = True):
        self.is_64bit = is_64bit
        self.rdtsc_tick_counter = 1000000
        self.cpuid_vendor = b"GenuineIntel"
        self.peb_address = 0x7FFFFFD0000 if is_64bit else 0x7FFDF000
        self.teb_address = 0x7FFFFFE0000 if is_64bit else 0x7FFDE000
        
        # Synthetic Clean PEB Structure (Zero anti-debug artifacts)
        self.peb_data = bytearray(0x1000)
        self._init_clean_peb()

    def _init_clean_peb(self):
        """Initializes a genuine, non-debugged PEB state."""
        # BeingDebugged = 0 (offset 0x02)
        self.peb_data[0x02] = 0x00
        # NtGlobalFlag = 0 (offset 0xBC for x64, 0x68 for x86)
        flag_offset = 0xBC if self.is_64bit else 0x68
        struct.pack_into("<I", self.peb_data, flag_offset, 0x00000000)

    def emulate_rdtsc(self, instruction_cost: int = 15) -> Tuple[int, int]:
        """
        Returns deterministic (EAX, EDX) timestamps that monotonically advance,
        neutralizing anti-analysis timing checks (RDTSC delta traps).
        """
        self.rdtsc_tick_counter += instruction_cost
        eax = self.rdtsc_tick_counter & 0xFFFFFFFF
        edx = (self.rdtsc_tick_counter >> 32) & 0xFFFFFFFF
        return eax, edx

    def emulate_cpuid(self, leaf: int) -> Dict[str, int]:
        """Returns standard CPUID register values (EAX, EBX, ECX, EDX) without hypervisor flags."""
        if leaf == 0:
            # Vendor String "GenuineIntel": EBX=Genu, EDX=ineI, ECX=ntel
            return {"eax": 0x16, "ebx": 0x756E6547, "ecx": 0x6C65746E, "edx": 0x49656E69}
        elif leaf == 1:
            # Standard feature flags with Hypervisor Present bit (ECX bit 31) = 0
            return {"eax": 0x000806EA, "ebx": 0x00100800, "ecx": 0x7FFAFBFF & ~(1 << 31), "edx": 0xBFEBFBFF}
        return {"eax": 0, "ebx": 0, "ecx": 0, "edx": 0}

    def get_symbolic_peb_constraint(self, solver: z3.Solver) -> z3.BoolRef:
        """Returns formal Z3 constraints enforcing clean PEB values during symbolic execution."""
        being_debugged = z3.BitVec("PEB_BeingDebugged", 8)
        nt_global_flag = z3.BitVec("PEB_NtGlobalFlag", 32)
        return z3.And(being_debugged == 0, nt_global_flag == 0)
