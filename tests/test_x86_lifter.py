# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
import pytest
import z3
from argus.frontend.x86_lifter import X86Lifter
from argus.engine.smt import SMTEngine

def test_x86_lifter_arithmetic_and_bitwise():
    # x86_64 shellcode for:
    # mov rax, rdi   (48 89 f8)
    # add rax, rsi   (48 01 f0)
    # xor rax, 0x42  (48 83 f0 42)
    shellcode = b"\x48\x89\xf8\x48\x01\xf0\x48\x83\xf0\x42"
    
    lifter = X86Lifter(bit_size=64)
    env, disasm = lifter.lift_code_bytes(shellcode, initial_regs=["rdi", "rsi"])
    
    assert "rax" in env
    recovered_rax = env["rax"]
    
    # Ground Truth Z3 formula: (rdi + rsi) ^ 0x42
    rdi = z3.BitVec("rdi", 64)
    rsi = z3.BitVec("rsi", 64)
    expected_rax = (rdi + rsi) ^ z3.BitVecVal(0x42, 64)
    
    smt = SMTEngine(bit_size=64)
    is_equivalent, counterexample = smt.prove_equivalence(recovered_rax, expected_rax)
    
    assert is_equivalent, f"Lifter mismatch! Counterexample: {counterexample}"
    assert len(disasm) == 3
