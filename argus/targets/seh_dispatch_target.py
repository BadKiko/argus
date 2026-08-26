# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
SEH/VEH Exception-Driven Control Flow Target.
Executes an IDIV by zero to intentionally trigger VEH and route control to a hidden branch.
"""
class SEHDispatchTarget:
    def __init__(self):
        self.fault_rva = 0x140001020
        self.veh_handler_rva = 0x140002000
        self.target_hidden_rva = 0x140003000
        # idiv ecx (0xf7 0xf9) with ecx=0
        self.faulting_opcode = b"\x31\xc9\xf7\xf9" # xor ecx, ecx; idiv ecx
