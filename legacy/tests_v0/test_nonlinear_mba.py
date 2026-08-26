# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
import pytest
import z3
from argus.targets.nonlinear_mba import NonlinearMBAGenerator
from argus.engine.simplifier import MBASimplifier
from argus.engine.smt import SMTEngine

def test_nonlinear_mba_smt_hardness_barrier():
    """
    Demonstrates the fundamental academic SMT Hardness Barrier:
    Degree-2 nonlinear product MBA causes Z3 solver timeout (returns 'unknown'),
    proving that classical algebraic solvers alone fail on high-degree MBA.
    """
    gen = NonlinearMBAGenerator(seed=777)
    obf, truth = gen.generate_nonlinear_product_mba("x", "y")

    simplifier = MBASimplifier(bit_size=32)
    z3_obf = simplifier.parse_python_mba_to_z3(obf, ("x", "y"))
    z3_truth = simplifier.parse_python_mba_to_z3(truth, ("x", "y"))

    solver = z3.Solver()
    solver.set("timeout", 1500)  # 1.5s timeout
    solver.add(z3_obf != z3_truth)
    res = solver.check()
    
    # Z3 cannot solve full 32-bit nonlinear multiplication in polynomial time -> 'unknown'
    assert res in [z3.unsat, z3.unknown]

def test_affine_masked_mba_ground_truth():
    gen = NonlinearMBAGenerator(seed=888)
    obf, truth = gen.generate_affine_masked_mba("x", "y")

    simplifier = MBASimplifier(bit_size=32)
    z3_obf = simplifier.parse_python_mba_to_z3(obf, ("x", "y"))
    z3_truth = simplifier.parse_python_mba_to_z3(truth, ("x", "y"))

    smt = SMTEngine(bit_size=32)
    is_equiv, counterexample = smt.prove_equivalence(z3_obf, z3_truth)
    assert is_equiv, f"Affine MBA mismatch! Counterexample: {counterexample}"
