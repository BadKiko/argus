# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
import pytest
from argus.frontend.assembler import X86Assembler

def test_x86_assembler_encodings():
    assembler = X86Assembler(bit_size=64)
    
    assert assembler.nop(3) == b"\x90\x90\x90"
    assert assembler.ret(0) == b"\xC3"
    assert assembler.xor_eax_eax() == b"\x31\xC0"
    assert assembler.mov_eax_imm32(1) == b"\xB8\x01\x00\x00\x00"
    
    # Test simple assembler text parser
    assert assembler.assemble_simple("nop") == b"\x90"
    assert assembler.assemble_simple("ret") == b"\xC3"
    assert assembler.assemble_simple("xor eax, eax") == b"\x31\xC0"
    assert assembler.assemble_simple("mov eax, 0x1337") == b"\xB8\x37\x13\x00\x00"
