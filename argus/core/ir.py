# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, List, Dict, Set, Any

class Opcode(Enum):
    # Arithmetic & Bitwise
    ADD = auto()
    SUB = auto()
    MUL = auto()
    XOR = auto()
    AND = auto()
    OR = auto()
    NOT = auto()
    SHL = auto()
    SHR = auto()
    ROL = auto()
    
    # Memory & Register Management
    MOV = auto()
    LOAD = auto()
    STORE = auto()
    PUSH = auto()
    POP = auto()
    
    # Control Flow
    JMP = auto()
    JZ = auto()
    JNZ = auto()
    RET = auto()
    UPDATE_STATE = auto()
    
    # Analysis & Protection Primitives
    NOP = auto()
    OPAQUE = auto()
    JUNK = auto()

@dataclass
class Operand:
    name: str
    size_bits: int = 32
    is_constant: bool = False
    value: Optional[int] = None
    is_tainted: bool = False

    def __repr__(self) -> str:
        if self.is_constant:
            return f"0x{self.value:X}" if self.value is not None else "0"
        tag = "[T]" if self.is_tainted else ""
        return f"{self.name}{tag}"

@dataclass
class Instruction:
    opcode: Opcode
    dest: Optional[Operand] = None
    src1: Optional[Operand] = None
    src2: Optional[Operand] = None
    address: int = 0
    state_id: int = 0
    is_junk: bool = False
    
    def __repr__(self) -> str:
        ops = []
        if self.dest: ops.append(str(self.dest))
        if self.src1: ops.append(str(self.src1))
        if self.src2: ops.append(str(self.src2))
        ops_str = ", ".join(ops)
        prefix = f"[JUNK 0x{self.address:04X}]" if self.is_junk else f"[0x{self.address:04X}]"
        return f"{prefix} {self.opcode.name:<8} {ops_str}"

@dataclass
class BasicBlock:
    id: int
    instructions: List[Instruction] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)

@dataclass
class Function:
    name: str
    entry_block: int = 0
    blocks: Dict[int, BasicBlock] = field(default_factory=dict)
