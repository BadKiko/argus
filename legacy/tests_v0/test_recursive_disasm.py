# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
import pytest
from argus.frontend.recursive_disasm import RecursiveDescentDisassembler
from argus.targets.overlapping_code_target import OverlappingCodeTarget

def test_recursive_descent_overlapping_resolution():
    target = OverlappingCodeTarget()
    disasm = RecursiveDescentDisassembler(is_64bit=True)

    instructions = disasm.disassemble_flow(target.code_bytes, target.base_addr)

    # Must find JMP, MOV EAX, 0x1337, and RET without being tripped by 0xE8 junk byte
    mnemonics = [i["mnemonic"] for i in instructions]
    assert "jmp" in mnemonics
    assert "mov" in mnemonics
    assert "ret" in mnemonics
