# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
import pytest
from argus.core.ir import Instruction, Operand, Opcode
from argus.ai.junk_classifier import MLJunkClassifier

def test_ml_junk_sifter_million_scale_simulation():
    # Create synthetic massive trace with 80% junk
    r_target = Operand("r_target")
    r_live1 = Operand("r_live1")
    r_live2 = Operand("r_live2")
    r_dead = Operand("r_dead")
    
    trace = [
        # Real dependency
        Instruction(Opcode.MOV, dest=r_live1, src1=Operand("const_10", is_constant=True, value=10)),
        # Junk operations
        Instruction(Opcode.MOV, dest=r_dead, src1=Operand("const_99", is_constant=True, value=99), is_junk=True),
        Instruction(Opcode.ADD, dest=r_dead, src1=r_dead, src2=Operand("const_1", is_constant=True, value=1), is_junk=True),
        Instruction(Opcode.PUSH, dest=None, src1=r_dead, is_junk=True),
        # Real dependency
        Instruction(Opcode.MOV, dest=r_live2, src1=Operand("const_20", is_constant=True, value=20)),
        # Real target computation
        Instruction(Opcode.ADD, dest=r_target, src1=r_live1, src2=r_live2),
    ]

    sifter = MLJunkClassifier(confidence_threshold=0.75)
    clean_trace, stats = sifter.sift_trace(trace, target_sink_var="r_target")

    assert stats["total_input_instructions"] == 6
    assert stats["sifted_junk_instructions"] == 3
    assert stats["retained_critical_instructions"] == 3
    assert clean_trace[-1].dest.name == "r_target"
