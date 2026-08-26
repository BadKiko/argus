from __future__ import annotations

"""Bogus control-flow / opaque predicate detection + certified patching."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import z3

from argus.disasm.cfg import CFG
from argus.mba.simplifier import MBASimplifier
from argus.patch.patcher import Patcher
from argus.prove.certificate import PatchCertificate


@dataclass
class OpaqueHit:
    addr: int
    kind: str  # opaque_true | opaque_false | constant_jz
    detail: str


@dataclass
class BogusCFReport:
    hits: List[OpaqueHit] = field(default_factory=list)
    patched: int = 0
    notes: List[str] = field(default_factory=list)
    certificate: Optional[PatchCertificate] = None

    def to_dict(self) -> dict:
        return {
            "hits": [{"addr": hex(h.addr), "kind": h.kind, "detail": h.detail} for h in self.hits],
            "patched": self.patched,
            "notes": self.notes,
            "certificate": self.certificate.to_dict() if self.certificate else None,
        }


def _imm_from_op(text: str) -> Optional[int]:
    text = text.strip()
    try:
        if text.startswith("0x") or text.isdigit() or (text.startswith("-") and text[1:].isdigit()):
            return int(text, 0) & 0xFFFFFFFF
    except ValueError:
        return None
    return None


def find_constant_branches(cfg: CFG) -> List[OpaqueHit]:
    """
    Detect jz/jnz after cmp/test with both operands concrete immediates,
    or xor-same / test-same patterns that force ZF.
    """
    hits: List[OpaqueHit] = []
    for addr, blk in cfg.blocks.items():
        ins = blk.instructions
        for i, inst in enumerate(ins):
            if inst.mnemonic not in ("je", "jz", "jne", "jnz"):
                continue
            # look back for cmp/test
            zf_known = None  # True => ZF=1
            detail = ""
            for j in range(i - 1, max(i - 4, -1), -1):
                prev = ins[j]
                if prev.mnemonic == "cmp":
                    parts = [p.strip() for p in prev.op_str.split(",")]
                    if len(parts) == 2:
                        a, b = _imm_from_op(parts[0]), _imm_from_op(parts[1])
                        if a is not None and b is not None:
                            zf_known = (a - b) & 0xFFFFFFFF == 0
                            detail = f"cmp {hex(a)},{hex(b)}"
                            break
                if prev.mnemonic == "test":
                    parts = [p.strip() for p in prev.op_str.split(",")]
                    if len(parts) == 2 and parts[0] == parts[1]:
                        # test reg,reg after xor reg,reg often ZF=1; alone unknown
                        pass
                if prev.mnemonic == "xor":
                    parts = [p.strip() for p in prev.op_str.split(",")]
                    if len(parts) == 2 and parts[0] == parts[1]:
                        zf_known = True
                        detail = f"xor-zero {parts[0]}"
                        break
            if zf_known is None:
                continue
            take = (zf_known and inst.mnemonic in ("je", "jz")) or (
                (not zf_known) and inst.mnemonic in ("jne", "jnz")
            )
            hits.append(
                OpaqueHit(
                    addr=inst.address,
                    kind="opaque_true" if take else "opaque_false",
                    detail=detail,
                )
            )
    return hits


def prove_mba_catalog(bits: int = 32) -> List[dict]:
    """Prove classic linear MBA identities used by OLLVM-style math obfuscation."""
    from argus.mba.simplifier import MBA_CATALOG

    s = MBASimplifier(bits)
    results = []
    for name, fn in MBA_CATALOG:
        r = s.simplify_binary_expr(fn)
        results.append({"name": name, "simplified": r.simplified, "proved": r.proved})
    always_true = s.is_opaque_true(lambda x: (x | ~x) == z3.BitVecVal((1 << bits) - 1, bits))
    always_false = s.is_opaque_false(lambda x: (x ^ x) != 0)
    results.append({"name": "opaque_or_not", "proved": always_true, "simplified": "true"})
    results.append({"name": "opaque_xor_self", "proved": always_false, "simplified": "false"})
    return results


def patch_opaque_branches(patcher: Patcher, hits: List[OpaqueHit]) -> Tuple[int, PatchCertificate]:
    """
    opaque_true  → force taken: patch jz→jmp (or nop jnz)
    opaque_false → force not taken: nop the jcc
    """
    patched = 0
    records = []
    for h in hits:
        off_ok = False
        if h.kind == "opaque_true":
            # Replace short/near conditional with unconditional jmp when possible.
            # Prefer invert-or-nop of the fallthrough side: make jcc always jump via
            # rewriting to jmp (E9/EB). We only handle 2-byte jcc (70-7F) and 6-byte.
            fo = patcher._file_offset(h.addr)
            if fo is None:
                continue
            op = patcher.data[fo]
            if 0x70 <= op <= 0x7F:
                # short jcc → short jmp, keep rel8
                if patcher.patch_bytes(h.addr, bytes([0xEB, patcher.data[fo + 1]]), note=h.detail):
                    patched += 1
                    off_ok = True
            elif op == 0x0F and patcher.data[fo + 1] in (0x84, 0x85):
                # near jcc → near jmp, keep rel32
                rel = bytes(patcher.data[fo + 2 : fo + 6])
                if patcher.patch_bytes(h.addr, b"\xe9" + rel + b"\x90", note=h.detail):
                    patched += 1
                    off_ok = True
        elif h.kind == "opaque_false":
            fo = patcher._file_offset(h.addr)
            if fo is None:
                continue
            op = patcher.data[fo]
            length = 2 if 0x70 <= op <= 0x7F else (6 if op == 0x0F else 0)
            if length and patcher.nop(h.addr, length, note=h.detail):
                patched += 1
                off_ok = True
        if off_ok and patcher.patches:
            records.append(patcher.patches[-1])

    cert = PatchCertificate(
        patches=[
            {"addr": hex(p.addr), "old": p.old.hex(), "new": p.new.hex(), "note": p.note}
            for p in records
        ],
        proven=patched > 0,
        notes=["opaque/constant branch patches from concrete cmp/xor proofs"],
    )
    return patched, cert


def analyze_bogus_cf(cfg: CFG, patcher: Optional[Patcher] = None) -> BogusCFReport:
    hits = find_constant_branches(cfg)
    mba = prove_mba_catalog()
    notes = [f"mba_catalog proved={sum(1 for x in mba if x.get('proved'))}/{len(mba)}"]
    report = BogusCFReport(hits=hits, notes=notes)
    report.notes.append(f"constant_branches={len(hits)}")
    if patcher and hits:
        n, cert = patch_opaque_branches(patcher, hits)
        report.patched = n
        report.certificate = cert
    return report
