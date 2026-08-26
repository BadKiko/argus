import pytest
from argus.targets.vm_toy import ToyVM
from argus.core.ir import Instruction, Operand, Opcode
from argus.engine.slicer import BackwardSlicer

def test_backward_slicing():
    # Создаем трассу с мусорными инструкциями
    r0 = Operand("r0")
    r1 = Operand("r1")
    r_junk = Operand("r_junk")
    res = Operand("res")
    
    trace = [
        Instruction(Opcode.MOV, dest=r0, src1=Operand("const1", is_constant=True, value=10)),
        Instruction(Opcode.MOV, dest=r_junk, src1=Operand("const99", is_constant=True, value=99), is_junk=True),
        Instruction(Opcode.MOV, dest=r1, src1=Operand("const2", is_constant=True, value=20)),
        Instruction(Opcode.ADD, dest=r_junk, src1=r_junk, src2=Operand("const5", is_constant=True, value=5), is_junk=True),
        Instruction(Opcode.ADD, dest=res, src1=r0, src2=r1),
    ]
    
    slicer = BackwardSlicer()
    sliced = slicer.slice_trace(trace, target_var="res")
    
    # Слайсер должен оставить только инструкции, влияющие на res (3 из 5)
    assert len(sliced) == 3
    assert all(not instr.is_junk for instr in sliced)
    assert sliced[-1].dest.name == "res"
