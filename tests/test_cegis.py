# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
import pytest
import z3
from argus.engine.cegis import CEGISSynthesizer
from argus.targets.nonlinear_mba import NonlinearMBAGenerator

def test_cegis_nonlinear_product_recovery():
    # Target oracle: f(x, y) = ((x & y)*(x | y) + (x & ~y)*(~x & y)) mod 2^32 == x * y
    gen = NonlinearMBAGenerator(seed=123)
    obf_str, _ = gen.generate_nonlinear_product_mba("x", "y")
    
    # Concrete Python executable oracle
    oracle = lambda x, y: eval(obf_str, {"__builtins__": None}, {"x": x, "y": y})

    synthesizer = CEGISSynthesizer(bit_size=32)
    expr_str, z3_ast = synthesizer.synthesize_affine_or_binary_candidate(oracle, ("x", "y"))

    assert expr_str == "(x * y)"
    assert z3_ast is not None

def test_cegis_affine_mba_recovery():
    gen = NonlinearMBAGenerator(seed=456)
    obf_str, truth_str = gen.generate_affine_masked_mba("x", "y")
    
    oracle = lambda x, y: eval(obf_str, {"__builtins__": None}, {"x": x, "y": y})

    synthesizer = CEGISSynthesizer(bit_size=32)
    expr_str, z3_ast = synthesizer.synthesize_affine_or_binary_candidate(oracle, ("x", "y"))

    assert expr_str is not None
    assert "(x ^ y)" in expr_str
