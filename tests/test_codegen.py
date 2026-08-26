# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
import pytest
import z3
from argus.engine.codegen import CCodeGenerator

def test_c_code_generation():
    x = z3.BitVec("x", 32)
    y = z3.BitVec("y", 32)
    
    # Formula: (x ^ y) + 0x1337
    expr = (x ^ y) + z3.BitVecVal(0x1337, 32)
    
    codegen = CCodeGenerator(function_name="calc_token")
    c_code = codegen.generate_c_function(expr, input_params=["x", "y"])
    
    assert "uint32_t calc_token(uint32_t x, uint32_t y)" in c_code
    assert "0x1337U" in c_code
    assert "^" in c_code
    assert "+" in c_code
