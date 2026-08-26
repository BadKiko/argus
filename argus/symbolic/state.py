from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

import z3


BV = z3.BitVecRef
Value = Union[int, BV]


def is_symbolic(v: Value) -> bool:
    return isinstance(v, z3.ExprRef)


def as_bv(v: Value, bits: int = 64) -> BV:
    if isinstance(v, z3.ExprRef):
        return v
    return z3.BitVecVal(int(v) & ((1 << bits) - 1), bits)


def conc_or_none(v: Value) -> Optional[int]:
    if isinstance(v, int):
        return v
    if z3.is_bv_value(v):
        return v.as_long()
    simp = z3.simplify(v)
    if z3.is_bv_value(simp):
        return simp.as_long()
    return None


@dataclass
class SymMemory:
    concrete: Dict[int, int] = field(default_factory=dict)
    symbolic: Dict[int, BV] = field(default_factory=dict)
    bits: int = 64

    def store_bytes(self, addr: Value, data: bytes) -> None:
        base = conc_or_none(addr)
        if base is None:
            raise NotImplementedError("symbolic store address not supported")
        for i, b in enumerate(data):
            a = base + i
            self.concrete[a] = b
            self.symbolic.pop(a, None)

    def store_byte(self, addr: Value, val: Value) -> None:
        base = conc_or_none(addr)
        if base is None:
            raise NotImplementedError("symbolic store address not supported")
        c = conc_or_none(val)
        if c is not None:
            self.concrete[base] = c & 0xFF
            self.symbolic.pop(base, None)
        else:
            self.symbolic[base] = z3.Extract(7, 0, as_bv(val, self.bits))
            self.concrete.pop(base, None)

    def load_byte(self, addr: Value) -> Value:
        base = conc_or_none(addr)
        if base is None:
            raise NotImplementedError("symbolic load address not supported")
        if base in self.symbolic:
            return self.symbolic[base]
        return self.concrete.get(base, 0)

    def load_bytes(self, addr: Value, n: int) -> List[Value]:
        base = conc_or_none(addr)
        if base is None:
            raise NotImplementedError("symbolic load address not supported")
        return [self.load_byte(base + i) for i in range(n)]

    def load_int(self, addr: Value, size: int, signed: bool = False) -> Value:
        bytes_ = self.load_bytes(addr, size)
        # little-endian combine
        if all(isinstance(b, int) for b in bytes_):
            v = 0
            for i, b in enumerate(bytes_):
                v |= (int(b) & 0xFF) << (8 * i)
            if signed and v >= (1 << (8 * size - 1)):
                v -= 1 << (8 * size)
            return v
        acc = as_bv(0, 8 * size)
        for i, b in enumerate(bytes_):
            piece = as_bv(b, 8) if not isinstance(b, z3.ExprRef) or b.size() == 8 else z3.Extract(7, 0, b)
            if piece.size() != 8:
                piece = z3.Extract(7, 0, as_bv(piece, 64))
            acc = acc | (z3.ZeroExt(8 * size - 8, piece) << (8 * i))
        return acc

    def store_int(self, addr: Value, value: Value, size: int) -> None:
        base = conc_or_none(addr)
        if base is None:
            raise NotImplementedError("symbolic store address not supported")
        c = conc_or_none(value)
        if c is not None:
            for i in range(size):
                self.store_byte(base + i, (c >> (8 * i)) & 0xFF)
            return
        bv = as_bv(value, max(size * 8, 64))
        for i in range(size):
            self.store_byte(base + i, z3.Extract(8 * i + 7, 8 * i, bv))

    def clone(self) -> "SymMemory":
        return SymMemory(
            concrete=dict(self.concrete),
            symbolic=dict(self.symbolic),
            bits=self.bits,
        )


@dataclass
class SimState:
    ip: int
    regs: Dict[str, Value]
    mem: SymMemory
    constraints: List[Any] = field(default_factory=list)
    stdin: List[Value] = field(default_factory=list)
    stdin_pos: int = 0
    stdout: bytes = b""
    halted: bool = False
    exited: bool = False
    exit_code: int = 0
    path_id: int = 0

    def clone(self) -> "SimState":
        return SimState(
            ip=self.ip,
            regs=dict(self.regs),
            mem=self.mem.clone(),
            constraints=list(self.constraints),
            stdin=list(self.stdin),
            stdin_pos=self.stdin_pos,
            stdout=self.stdout,
            halted=self.halted,
            exited=self.exited,
            exit_code=self.exit_code,
            path_id=self.path_id,
        )

    def get_reg(self, name: str) -> Value:
        name = _norm_reg(name)
        if name not in self.regs:
            self.regs[name] = 0
        return self.regs[name]

    def set_reg(self, name: str, val: Value) -> None:
        self.regs[_norm_reg(name)] = val


def _norm_reg(name: str) -> str:
    name = name.lower().lstrip("%")
    alias = {
        "eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
        "esi": "rsi", "edi": "rdi", "ebp": "rbp", "esp": "rsp",
        "eip": "rip",
        "r8d": "r8", "r9d": "r9", "r10d": "r10", "r11d": "r11",
        "r12d": "r12", "r13d": "r13", "r14d": "r14", "r15d": "r15",
        "al": "rax", "bl": "rbx", "cl": "rcx", "dl": "rdx",
        "sil": "rsi", "dil": "rdi", "bpl": "rbp", "spl": "rsp",
        "ax": "rax", "bx": "rbx", "cx": "rcx", "dx": "rdx",
    }
    return alias.get(name, name)


REG64 = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
