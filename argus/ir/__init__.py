"""Minimal SSA-like IR placeholders for future lifters."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional


class Op(Enum):
    ADD = auto()
    SUB = auto()
    XOR = auto()
    AND = auto()
    OR = auto()
    MOV = auto()
    LOAD = auto()
    STORE = auto()
    JMP = auto()
    RET = auto()


@dataclass
class Imm:
    value: int
    bits: int = 64


@dataclass
class Reg:
    name: str


@dataclass
class Stmt:
    op: Op
    dst: Optional[str] = None
    a: Optional[object] = None
    b: Optional[object] = None
    addr: int = 0
