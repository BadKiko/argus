"""
Полиморфная стековая микро-виртуальная машина (Toy VM).
Служит реалистичной мишенью для тестирования Taint-анализа и De-virtualization.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Any, Optional
import random

class VMOpcode:
    PUSH_CONST = 0x10
    PUSH_VAR   = 0x11
    POP_VAR    = 0x12
    ADD        = 0x20
    SUB        = 0x21
    XOR        = 0x22
    AND        = 0x23
    OR         = 0x24
    JUNK_MATH  = 0x90
    JUNK_STACK = 0x91
    EXIT       = 0xFF

@dataclass
class VMInstruction:
    opcode: int
    arg: Optional[Any] = None
    is_junk: bool = False

class ToyVM:
    def __init__(self, junk_ratio: float = 0.5, seed: int = 1337):
        self.junk_ratio = junk_ratio
        self.seed = seed
        self.random = random.Random(seed)

    def compile_expression_to_bytecode(self, op: str, var_a: str, var_b: str, dest_var: str) -> List[VMInstruction]:
        """
        Компилирует выражение (dest = var_a <op> var_b) в поток байткода
        с добавлением мусорных инструкций и стековых манипуляций.
        """
        op_map = {
            '+': VMOpcode.ADD,
            '-': VMOpcode.SUB,
            '^': VMOpcode.XOR,
            '&': VMOpcode.AND,
            '|': VMOpcode.OR,
        }
        target_op = op_map.get(op, VMOpcode.ADD)
        
        program: List[VMInstruction] = []
        
        # 1. Загрузка операнда A
        if self.random.random() < self.junk_ratio:
            program.append(VMInstruction(VMOpcode.JUNK_STACK, arg=self.random.randint(1, 100), is_junk=True))
            program.append(VMInstruction(VMOpcode.JUNK_MATH, arg=0x42, is_junk=True))
            
        program.append(VMInstruction(VMOpcode.PUSH_VAR, arg=var_a))
        
        # 2. Загрузка операнда B
        if self.random.random() < self.junk_ratio:
            program.append(VMInstruction(VMOpcode.JUNK_STACK, arg=self.random.randint(1, 100), is_junk=True))
            
        program.append(VMInstruction(VMOpcode.PUSH_VAR, arg=var_b))
        
        # 3. Выполнение операции
        program.append(VMInstruction(target_op))
        
        # 4. Мусор после вычисления
        if self.random.random() < self.junk_ratio:
            program.append(VMInstruction(VMOpcode.JUNK_MATH, arg=0xDEAD, is_junk=True))
            
        # 5. Сохранение результата
        program.append(VMInstruction(VMOpcode.POP_VAR, arg=dest_var))
        program.append(VMInstruction(VMOpcode.EXIT))
        
        return program

    def execute(self, bytecode: List[VMInstruction], initial_state: Dict[str, int]) -> Tuple[Dict[str, int], List[str]]:
        """
        Исполняет байт-код и возвращает (финальное_состояние_переменных, трасса_исполнения).
        """
        stack: List[int] = []
        state = dict(initial_state)
        trace_log: List[str] = []
        
        for idx, instr in enumerate(bytecode):
            op = instr.opcode
            tag = "[JUNK]" if instr.is_junk else "[REAL]"
            
            if op == VMOpcode.PUSH_CONST:
                stack.append(instr.arg & 0xFFFFFFFF)
                trace_log.append(f"{idx:03d} {tag} PUSH_CONST 0x{instr.arg:X}")
            elif op == VMOpcode.PUSH_VAR:
                val = state.get(instr.arg, 0) & 0xFFFFFFFF
                stack.append(val)
                trace_log.append(f"{idx:03d} {tag} PUSH_VAR {instr.arg} (val=0x{val:X})")
            elif op == VMOpcode.POP_VAR:
                if stack:
                    val = stack.pop()
                    state[instr.arg] = val
                    trace_log.append(f"{idx:03d} {tag} POP_VAR {instr.arg} = 0x{val:X}")
            elif op == VMOpcode.ADD:
                if len(stack) >= 2:
                    b, a = stack.pop(), stack.pop()
                    res = (a + b) & 0xFFFFFFFF
                    stack.append(res)
                    trace_log.append(f"{idx:03d} {tag} ADD (0x{a:X} + 0x{b:X} = 0x{res:X})")
            elif op == VMOpcode.XOR:
                if len(stack) >= 2:
                    b, a = stack.pop(), stack.pop()
                    res = (a ^ b) & 0xFFFFFFFF
                    stack.append(res)
                    trace_log.append(f"{idx:03d} {tag} XOR (0x{a:X} ^ 0x{b:X} = 0x{res:X})")
            elif op == VMOpcode.JUNK_MATH or op == VMOpcode.JUNK_STACK:
                # Фиктивные манипуляции
                dummy = (self.random.randint(1, 1000) ^ 0x55) & 0xFFFFFFFF
                trace_log.append(f"{idx:03d} {tag} JUNK_OP (dummy=0x{dummy:X})")
            elif op == VMOpcode.EXIT:
                trace_log.append(f"{idx:03d} [SYS] EXIT")
                break
                
        return state, trace_log
