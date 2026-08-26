import pytest
import z3
from argus.targets.mba_generator import MBAGenerator
from argus.engine.simplifier import MBASimplifier
from argus.engine.smt import SMTEngine

def test_linear_mba_add_simplification():
    gen = MBAGenerator(seed=100)
    simplifier = MBASimplifier(bit_size=32)
    
    for _ in range(5):
        obf, truth = gen.generate_linear_mba_add("x", "y")
        z3_expr = simplifier.parse_python_mba_to_z3(obf, ("x", "y"))
        simplified, is_valid = simplifier.simplify_and_verify(z3_expr)
        
        assert is_valid, f"Verification failed for {obf}"

def test_linear_mba_xor_simplification():
    gen = MBAGenerator(seed=200)
    simplifier = MBASimplifier(bit_size=32)
    
    for _ in range(5):
        obf, truth = gen.generate_linear_mba_xor("x", "y")
        z3_expr = simplifier.parse_python_mba_to_z3(obf, ("x", "y"))
        simplified, is_valid = simplifier.simplify_and_verify(z3_expr)
        
        assert is_valid, f"Verification failed for {obf}"

def test_opaque_predicates():
    gen = MBAGenerator()
    smt = SMTEngine(bit_size=32)
    x = smt.create_bitvec("x")
    
    # x * (x - 1) & 1 == 0
    pred_true_expr = (x * x - x) & 1 == 0
    assert smt.check_opaque_predicate(pred_true_expr) == "ALWAYS_TRUE"
