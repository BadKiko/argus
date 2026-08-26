# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Overlapping Instruction (JMP $+1) Target.
"""
class OverlappingCodeTarget:
    def __init__(self):
        self.base_addr = 0x140001000
        # Byte sequence:
        # 140001000: EB 01       JMP 0x140001003 (+1 byte jump)
        # 140001002: E8          (Junk byte)
        # 140001003: B8 37 13 00 00 MOV EAX, 0x1337
        # 140001008: C3          RET
        self.code_bytes = b"\xeb\x01\xe8\xb8\x37\x13\x00\x00\xc3"
