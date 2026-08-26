# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
x86/x64 Machine Code Assembler & Instruction Encoder.
Encodes canonical assembly instructions into raw machine bytecode for binary patching.
"""
import struct
from typing import Optional

class X86Assembler:
    def __init__(self, bit_size: int = 64):
        self.bit_size = bit_size

    def nop(self, count: int = 1) -> bytes:
        """Returns count NOP (0x90) bytes."""
        return b"\x90" * count

    def ret(self, pop_bytes: int = 0) -> bytes:
        """Returns RET (0xC3) or RET imm16 (0xC2 imm16)."""
        if pop_bytes == 0:
            return b"\xC3"
        return b"\xC2" + struct.pack("<H", pop_bytes)

    def xor_eax_eax(self) -> bytes:
        """Returns XOR EAX, EAX (0x31 0xC0)."""
        return b"\x31\xC0"

    def mov_eax_imm32(self, val: int) -> bytes:
        """Returns MOV EAX, imm32 (0xB8 imm32)."""
        return b"\xB8" + struct.pack("<I", val & 0xFFFFFFFF)

    def mov_rax_imm64(self, val: int) -> bytes:
        """Returns MOV RAX, imm64 (0x48 0xB8 imm64)."""
        return b"\x48\xB8" + struct.pack("<Q", val & 0xFFFFFFFFFFFFFFFF)

    def jmp_rel32(self, offset: int) -> bytes:
        """Returns JMP rel32 (0xE9 rel32)."""
        return b"\xE9" + struct.pack("<i", offset)

    def jz_rel8(self, offset: int) -> bytes:
        """Returns JZ rel8 (0x74 rel8)."""
        return b"\x74" + struct.pack("<b", offset)

    def jnz_rel8(self, offset: int) -> bytes:
        """Returns JNZ rel8 (0x75 rel8)."""
        return b"\x75" + struct.pack("<b", offset)

    def assemble_simple(self, asm_line: str) -> bytes:
        """
        Assembles a single high-level mnemonic string into raw machine bytes.
        """
        cleaned = asm_line.strip().lower()
        if cleaned == "nop":
            return self.nop(1)
        elif cleaned == "ret":
            return self.ret(0)
        elif cleaned in ["xor eax, eax", "xor rax, rax"]:
            return self.xor_eax_eax()
        elif cleaned.startswith("mov eax,"):
            imm_str = cleaned.split(",")[1].strip()
            val = int(imm_str, 0)
            return self.mov_eax_imm32(val)
        elif cleaned.startswith("mov rax,"):
            imm_str = cleaned.split(",")[1].strip()
            val = int(imm_str, 0)
            return self.mov_rax_imm64(val)
        else:
            raise ValueError(f"Unsupported mnemonic for basic assembler: {asm_line}")
