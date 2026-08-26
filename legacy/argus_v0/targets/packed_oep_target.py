# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Packed OEP Simulation Target.
Simulates an unpacker stub jumping to a decrypted code section.
"""
class PackedOEPTarget:
    def __init__(self):
        self.stub_base = 0x140001000
        self.oep_base = 0x140005000 # In decrypted section
        
        # Stub: JMP to OEP (0xE9 + rel32)
        rel_offset = self.oep_base - (self.stub_base + 5)
        self.stub_bytes = b"\xe9" + rel_offset.to_bytes(4, "little", signed=True)
        # OEP code: PUSH RBP; RET
        self.oep_bytes = b"\x55\xc3"
