# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Lightweight CPU Emulation Sandbox & Original Entry Point (OEP) Detector.
Emulates unpacking stubs and detects transitions to the decrypted application payload.
"""
from typing import Dict, List, Tuple, Optional, Any
import numpy as np

class CPUSandbox:
    def __init__(self, initial_pc: int = 0x140001000):
        self.pc = initial_pc
        self.registers = {
            "rax": 0, "rbx": 0, "rcx": 0, "rdx": 0,
            "rsi": 0, "rdi": 0, "rbp": 0x7FFFFFF0, "rsp": 0x7FFFFFF0,
            "r8": 0, "r9": 0, "r10": 0, "r11": 0,
            "r12": 0, "r13": 0, "r14": 0, "r15": 0,
            "rip": initial_pc
        }
        self.memory: Dict[int, bytearray] = {} # Page base -> 4KB page
        self.executed_instructions: List[int] = []

    def map_memory(self, base_addr: int, size: int, data: bytes = None):
        """Maps virtual memory pages into sandbox."""
        aligned_base = base_addr & ~0xFFF
        total_pages = (size + 0xFFF) // 4096
        for i in range(total_pages):
            page_addr = aligned_base + (i * 4096)
            if page_addr not in self.memory:
                self.memory[page_addr] = bytearray(4096)

        if data:
            self.write_memory(base_addr, data)

    def write_memory(self, addr: int, data: bytes):
        for i, b in enumerate(data):
            page_addr = (addr + i) & ~0xFFF
            offset = (addr + i) & 0xFFF
            if page_addr in self.memory:
                self.memory[page_addr][offset] = b

    def read_memory(self, addr: int, length: int) -> bytes:
        res = bytearray()
        for i in range(length):
            page_addr = (addr + i) & ~0xFFF
            offset = (addr + i) & 0xFFF
            if page_addr in self.memory:
                res.append(self.memory[page_addr][offset])
            else:
                res.append(0)
        return bytes(res)

    def emulate_step(self, max_steps: int = 1000, target_oep_section: Tuple[int, int] = None) -> Dict[str, Any]:
        """
        Emulates execution and tracks OEP transitions.
        """
        steps = 0
        oep_detected = False
        oep_address = None

        while steps < max_steps:
            steps += 1
            self.executed_instructions.append(self.pc)
            
            # Check OEP condition (transition into decrypted code section)
            if target_oep_section:
                sec_start, sec_end = target_oep_section
                if sec_start <= self.pc < sec_end:
                    oep_detected = True
                    oep_address = self.pc
                    break

            # Read 16 bytes at current PC
            code_chunk = self.read_memory(self.pc, 16)
            if not code_chunk or code_chunk[0] == 0x00: # Padding or unmapped
                break

            # Handle simple unpacker instructions
            # JMP rel32 (0xE9 xx xx xx xx)
            if code_chunk[0] == 0xE9:
                rel = int.from_bytes(code_chunk[1:5], "little", signed=True)
                self.pc = (self.pc + 5 + rel) & 0xFFFFFFFFFFFFFFFF
            # JMP rel8 (0xEB xx)
            elif code_chunk[0] == 0xEB:
                rel = int.from_bytes(code_chunk[1:2], "little", signed=True)
                self.pc = (self.pc + 2 + rel) & 0xFFFFFFFFFFFFFFFF
            # RET (0xC3)
            elif code_chunk[0] == 0xC3:
                break
            else:
                self.pc += 1

        return {
            "total_steps": steps,
            "oep_detected": oep_detected,
            "oep_address": hex(oep_address) if oep_address else None,
            "final_pc": hex(self.pc)
        }
