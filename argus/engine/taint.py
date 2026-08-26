"""
Dynamic Taint Analysis (DTA) Engine.
Отслеживает распространение меток от исходных данных к результату,
позволяя отсекать мусорные ветви и побочные вычисления.
"""
from typing import Set, Dict, List, Any
from ..core.ir import Instruction, Operand, Opcode

class TaintEngine:
    def __init__(self):
        # Множество запятнанных (tainted) переменных и регистров
        self.tainted_sources: Set[str] = set()
        self.tainted_history: List[Instruction] = []

    def set_source_tainted(self, var_name: str) -> None:
        self.tainted_sources.add(var_name)

    def is_tainted(self, var_name: str) -> bool:
        return var_name in self.tainted_sources

    def process_instruction(self, instr: Instruction) -> bool:
        """
        Обрабатывает инструкцию IR.
        Если операнды-источники (src1, src2) помечены -> помечает dest и возвращает True.
        Если инструкция не зависит от tainted данных -> возвращает False (кандидат в мусор).
        """
        src1_tainted = instr.src1.name in self.tainted_sources if instr.src1 and not instr.src1.is_constant else False
        src2_tainted = instr.src2.name in self.tainted_sources if instr.src2 and not instr.src2.is_constant else False

        is_active_flow = src1_tainted or src2_tainted

        if is_active_flow and instr.dest:
            self.tainted_sources.add(instr.dest.name)
            instr.dest.is_tainted = True
            self.tainted_history.append(instr)
            return True
        elif instr.dest and instr.dest.name in self.tainted_sources and not is_active_flow:
            # Перезапись значения незапятнанным источником снимает метку (Untaint)
            self.tainted_sources.remove(instr.dest.name)

        return False
