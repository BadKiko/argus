# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
import pytest
import z3
from argus.engine.path_explorer import SymbolicPathExplorer

def test_symbolic_path_explorer_password_recovery():
    explorer = SymbolicPathExplorer(bit_size=32)
    
    # Create a 4-byte symbolic password buffer: [p0, p1, p2, p3]
    passwd = explorer.create_symbolic_byte_buffer("pwd", 4)
    
    # Simulate a multi-stage obfuscated authentication check:
    # Stage 1: (p0 ^ 0x5A) == 0x1B   => p0 = 0x5A ^ 0x1B = 0x41 ('A')
    # Stage 2: (p1 + 0x10) == 0x52   => p1 = 0x52 - 0x10 = 0x42 ('B')
    # Stage 3: (p2 ^ p0)   == 0x02   => p2 = 'A' ^ 0x02 = 0x43 ('C')
    # Stage 4: (p3 - 0x05) == 0x3F   => p3 = 0x3F + 0x05 = 0x44 ('D')
    
    explorer.add_path_constraint((passwd[0] ^ z3.BitVecVal(0x5A, 8)) == z3.BitVecVal(0x1B, 8))
    explorer.add_path_constraint((passwd[1] + z3.BitVecVal(0x10, 8)) == z3.BitVecVal(0x52, 8))
    explorer.add_path_constraint((passwd[2] ^ passwd[0]) == z3.BitVecVal(0x02, 8))
    explorer.add_path_constraint((passwd[3] - z3.BitVecVal(0x05, 8)) == z3.BitVecVal(0x3F, 8))
    
    is_sat, assignments, recovered_bytes = explorer.solve_for_target_sink()
    
    assert is_sat is True
    assert recovered_bytes is not None
    assert recovered_bytes.decode('ascii') == "ABCD"
