"""
Backward Program Slicer.
По заданной цели (Sink / Result) строит граф зависимостей и вырезает весь нерелевантный код.
"""
from typing import List, Set
from ..core.ir import Instruction, Opcode

class BackwardSlicer:
    def __init__(self):
        pass

    def slice_trace(self, trace: List[Instruction], target_var: str) -> List[Instruction]:
        """
        Выполняет обратный слайсинг (Backward Slicing) трассы инструкций.
        Оставляет только те инструкции, которые непосредственно влияют на target_var.
        """
        needed_vars: Set[str] = {target_var}
        sliced_instructions: List[Instruction] = []

        # Идем с конца трассы в начало
        for instr in reversed(trace):
            if instr.dest and instr.dest.name in needed_vars:
                sliced_instructions.append(instr)
                
                # Добавляем аргументы этой инструкции в список необходимых переменных
                if instr.src1 and not instr.src1.is_constant:
                    needed_vars.add(instr.src1.name)
                if instr.src2 and not instr.src2.is_constant:
                    needed_vars.add(instr.src2.name)
            elif instr.is_junk:
                # Мертвый код игнорируется
                continue

        # Возвращаем инструкции в правильном хронологическом порядке
        sliced_instructions.reverse()
        return sliced_instructions
