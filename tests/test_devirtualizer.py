# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
import pytest
import z3
from argus.targets.complex_license_vm import ComplexLicenseValidatorVM
from argus.engine.devirtualizer import AutomatedDevirtualizer
from argus.engine.smt import SMTEngine

def test_automated_devirtualization_ground_truth():
    vm = ComplexLicenseValidatorVM(seed=999)
    program = vm.generate_complex_validation_suite()
    
    devirt = AutomatedDevirtualizer(bit_size=32)
    recovered_ast, stats = devirt.devirtualize_program(
        bytecode=program,
        input_vars=["HWID_IN", "LICENSE_KEY"],
        target_var="AUTH_TOKEN"
    )
    
    # Construct Ground Truth formal Z3 specification
    hwid = z3.BitVec("HWID_IN", 32)
    lic = z3.BitVec("LICENSE_KEY", 32)
    
    hwid_part1 = hwid ^ z3.BitVecVal(0x5A5A5A5A, 32)
    and_masked = hwid & z3.BitVecVal(0x0F0F0F0F, 32)
    hwid_part2 = (and_masked << 2) | z3.LShR(and_masked, 30)
    hwid_hash = hwid_part1 + hwid_part2
    
    ground_truth_token = ((lic ^ hwid_hash) + z3.BitVecVal(0x1337BEEF, 32)) ^ z3.BitVecVal(0xCAFEBABE, 32)
    ground_truth_simplified = z3.simplify(ground_truth_token)

    # Prove 100% equivalence using SMT Theorem Prover
    smt = SMTEngine(bit_size=32)
    is_equivalent, counterexample = smt.prove_equivalence(recovered_ast, ground_truth_simplified)
    
    assert is_equivalent, f"Devirtualization mismatch! Counterexample: {counterexample}"
    assert stats["pruned_junk_instructions"] > 0
    assert stats["states_traversed"] == 4
