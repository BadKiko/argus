from __future__ import annotations

"""Proof-carrying analysis: ML may propose; math must approve."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set

from argus.disasm.cfg import CFG


class CertKind(str, Enum):
    NOP_ONLY = "nop_only"
    UNREACHABLE = "unreachable_from_entry"
    NO_SIDE_EFFECTS_AND_NOT_ON_SINK_PATH = "no_side_effects_off_sink_path"
    REJECTED_HAS_EFFECTS = "rejected_has_effects"
    REJECTED_ON_SINK_PATH = "rejected_on_sink_path"
    REJECTED_NO_PROOF = "rejected_no_proof"


@dataclass
class BlockCertificate:
    addr: int
    allowed_prune: bool
    kind: CertKind
    detail: str = ""


@dataclass
class PruneCertificate:
    proposed: List[int]
    approved: List[int]
    rejected: List[int]
    block_certs: List[BlockCertificate] = field(default_factory=list)
    thesis: str = "propose-with-ML, drop-only-with-proof"

    def to_dict(self) -> dict:
        return {
            "thesis": self.thesis,
            "proposed": [hex(a) for a in self.proposed],
            "approved": [hex(a) for a in self.approved],
            "rejected": [hex(a) for a in self.rejected],
            "blocks": [
                {
                    "addr": hex(c.addr),
                    "allowed_prune": c.allowed_prune,
                    "kind": c.kind.value,
                    "detail": c.detail,
                }
                for c in self.block_certs
            ],
        }


_SIDE_EFFECT = {
    "call", "callq", "syscall", "sysenter",
    "out", "outs", "outsb", "outsd", "outsw",
    "in", "ins", "insb", "insd", "insw",
    "stos", "stosb", "stosd", "stosq", "stosw",
    "movs", "movsb", "movsd", "movsq", "movsw",
    "push", "pop", "pushf", "popf",
    "ret", "retn", "retf",
}


def _is_nop_block(cfg: CFG, addr: int) -> bool:
    blk = cfg.blocks.get(addr)
    if not blk or not blk.instructions:
        return False
    return all(ins.mnemonic in ("nop", "endbr64") for ins in blk.instructions)


def _has_side_effects(cfg: CFG, addr: int) -> bool:
    blk = cfg.blocks.get(addr)
    if not blk:
        return True
    for ins in blk.instructions:
        if ins.mnemonic in _SIDE_EFFECT or ins.is_call or ins.is_ret:
            return True
        # memory write: mnemonic mov/xchg with [...] as first operand
        if "[" in ins.op_str.split(",")[0] and ins.mnemonic.startswith(("mov", "xchg", "add", "sub", "xor", "and", "or")):
            return True
    return False


def reachable_from(cfg: CFG, entry: int) -> Set[int]:
    if entry not in cfg.graph and entry not in cfg.blocks:
        return set()
    seen: Set[int] = set()
    stack = [entry]
    while stack:
        n = stack.pop()
        if n in seen:
            continue
        seen.add(n)
        if n in cfg.graph:
            stack.extend(cfg.graph.successors(n))
    return seen


def can_reach_sink(cfg: CFG, start: int, sinks: Set[int]) -> bool:
    if start in sinks:
        return True
    seen: Set[int] = set()
    stack = [start]
    while stack:
        n = stack.pop()
        if n in seen:
            continue
        seen.add(n)
        if n in sinks:
            return True
        if n in cfg.graph:
            stack.extend(cfg.graph.successors(n))
    return False


def find_sinks(cfg: CFG) -> Set[int]:
    sinks: Set[int] = set()
    for addr, blk in cfg.blocks.items():
        if any(ins.is_ret for ins in blk.instructions):
            sinks.add(addr)
        if any(ins.is_call for ins in blk.instructions):
            sinks.add(addr)
    return sinks


def certify_block(cfg: CFG, addr: int, reachable: Set[int], sinks: Set[int]) -> BlockCertificate:
    if addr not in cfg.blocks:
        return BlockCertificate(addr, True, CertKind.UNREACHABLE, "missing block")
    if addr not in reachable:
        return BlockCertificate(addr, True, CertKind.UNREACHABLE, "not reachable from entry")
    if _is_nop_block(cfg, addr):
        return BlockCertificate(addr, True, CertKind.NOP_ONLY, "nop-only block")
    if _has_side_effects(cfg, addr):
        return BlockCertificate(addr, False, CertKind.REJECTED_HAS_EFFECTS, "call/store/ret present")
    if can_reach_sink(cfg, addr, sinks):
        return BlockCertificate(addr, False, CertKind.REJECTED_ON_SINK_PATH, "reaches sink without proof of deadness")
    return BlockCertificate(
        addr,
        True,
        CertKind.NO_SIDE_EFFECTS_AND_NOT_ON_SINK_PATH,
        "no side effects and cannot reach sink",
    )


def certify_prune_proposals(cfg: CFG, proposed: List[int]) -> PruneCertificate:
    reachable = reachable_from(cfg, cfg.entry)
    sinks = find_sinks(cfg)
    approved: List[int] = []
    rejected: List[int] = []
    certs: List[BlockCertificate] = []
    for addr in proposed:
        cert = certify_block(cfg, addr, reachable, sinks)
        certs.append(cert)
        if cert.allowed_prune:
            approved.append(addr)
        else:
            rejected.append(addr)
    return PruneCertificate(
        proposed=list(proposed),
        approved=approved,
        rejected=rejected,
        block_certs=certs,
    )
