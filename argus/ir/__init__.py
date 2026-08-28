"""Minimal Argus IR — format-agnostic analysis/transform model."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional


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


@dataclass
class String:
    va: int
    text: str
    encoding: str = "utf-8"


@dataclass
class XRef:
    from_va: int
    to_va: int
    kind: str = "data"


@dataclass
class Function:
    name: str
    entry: int
    size: int = 0
    stmts: List[Stmt] = field(default_factory=list)


@dataclass
class Module:
    path: str
    format: str
    arch: str
    functions: List[Function] = field(default_factory=list)
    strings: List[String] = field(default_factory=list)
    xrefs: List[XRef] = field(default_factory=list)


@dataclass
class PatchStep:
    kind: str
    addr: int
    module: Optional[str] = None
    value: Optional[int] = None
    taken: Optional[bool] = None
    why: str = ""

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"kind": self.kind, "addr": hex(self.addr) if self.addr else self.addr}
        if self.module:
            out["module"] = self.module
        if self.value is not None:
            out["value"] = self.value
        if self.taken is not None:
            out["taken"] = self.taken
        if self.why:
            out["why"] = self.why
        return out


@dataclass
class Verification:
    kind: str
    ok: bool
    detail: str = ""
    level: str = "UNKNOWN"


@dataclass
class Artifact:
    """Top-level binary artifact (executable or library)."""

    path: str
    format: str
    arch: str
    modules: List[Module] = field(default_factory=list)
    patch_plan: List[PatchStep] = field(default_factory=list)
    verification: Optional[Verification] = None
