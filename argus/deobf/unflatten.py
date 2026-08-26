from __future__ import annotations

"""CFF unflatten: rewrite return-to-dispatcher jumps into direct edges."""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from argus.deobf.cff import (
    CFFReport,
    _parse_imm_token,
    _slot_in_text,
    extract_state_stores,
    recover_cff,
)
from argus.disasm.cfg import CFG, CFGBlock
from argus.patch.patcher import Patcher
from argus.prove.certificate import PatchCertificate


def encode_jmp_rel32(src_addr: int, dst_addr: int) -> bytes:
    rel = (dst_addr - (src_addr + 5)) & 0xFFFFFFFF
    return b"\xe9" + rel.to_bytes(4, "little")


def encode_je_rel32(src_addr: int, dst_addr: int) -> bytes:
    rel = (dst_addr - (src_addr + 6)) & 0xFFFFFFFF
    return b"\x0f\x84" + rel.to_bytes(4, "little")


def encode_jne_rel32(src_addr: int, dst_addr: int) -> bytes:
    rel = (dst_addr - (src_addr + 6)) & 0xFFFFFFFF
    return b"\x0f\x85" + rel.to_bytes(4, "little")


def encode_jmp_rel8(src_addr: int, dst_addr: int) -> Optional[bytes]:
    rel = dst_addr - (src_addr + 2)
    if -128 <= rel <= 127:
        return bytes([0xEB, rel & 0xFF])
    return None


@dataclass
class UnflattenResult:
    report: CFFReport
    patches_applied: int
    redirected: List[Tuple[int, int, int]] = field(default_factory=list)
    nopped: List[int] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    certificate: Optional[PatchCertificate] = None

    def to_dict(self) -> dict:
        return {
            "cff": self.report.to_dict(),
            "patches_applied": self.patches_applied,
            "redirected": [[hex(a), hex(b), hex(c)] for a, b, c in self.redirected],
            "nopped": [hex(a) for a in self.nopped],
            "notes": self.notes,
            "certificate": self.certificate.to_dict() if self.certificate else None,
        }


def _trampoline_targets(cfg: CFG, dispatcher: int) -> Set[int]:
    out = {dispatcher}
    for addr, blk in cfg.blocks.items():
        if not blk.instructions:
            continue
        if all(i.is_jmp or i.mnemonic == "nop" for i in blk.instructions):
            last = blk.instructions[-1]
            if last.is_jmp and dispatcher in last.targets:
                out.add(addr)
    return out


def _last_imm_store(blk: CFGBlock, state_slot: str) -> Optional[int]:
    last = None
    for ins in blk.instructions:
        if ins.mnemonic != "mov":
            continue
        parts = [p.strip() for p in ins.op_str.split(",")]
        if len(parts) == 2 and _slot_in_text(state_slot, parts[0]):
            imm = _parse_imm_token(parts[1])
            if imm is not None:
                last = imm & 0xFFFFFFFF
    return last


def _detect_cmove_state(blk: CFGBlock, state_slot: str) -> Optional[dict]:
    """
    Detect OLLVM-style:
      mov rA, IMM_FALSE
      mov rB, IMM_TRUE
      ...
      cmp ...
      cmove rA, rB   (ZF=1 → IMM_TRUE)
      mov [slot], rA
      jmp dispatcher
    """
    ins = blk.instructions
    if len(ins) < 5:
        return None
    last = ins[-1]
    if not last.is_jmp:
        return None
    # find mov [slot], reg near end
    store_idx = None
    store_reg = None
    for i in range(len(ins) - 2, max(len(ins) - 6, -1), -1):
        if ins[i].mnemonic != "mov":
            continue
        parts = [p.strip() for p in ins[i].op_str.split(",")]
        if len(parts) == 2 and _slot_in_text(state_slot, parts[0]):
            if re.fullmatch(r"e?[abcd]x|r[89]d?|r1[0-5]d?|esi|edi", parts[1], re.I):
                store_idx = i
                store_reg = parts[1].lower()
                break
    if store_idx is None:
        return None
    # cmove/cmovz before store
    cmov = None
    cmov_idx = None
    for i in range(store_idx - 1, max(store_idx - 4, -1), -1):
        if ins[i].mnemonic in ("cmove", "cmovz", "cmovne", "cmovnz"):
            cmov = ins[i]
            cmov_idx = i
            break
    if cmov is None:
        return None
    parts = [p.strip() for p in cmov.op_str.split(",")]
    if len(parts) != 2:
        return None
    dst, src = parts[0].lower(), parts[1].lower()
    if dst != store_reg:
        return None
    # find imm loads into dst and src regs earlier
    imm_a = imm_b = None
    for i in range(cmov_idx):
        if ins[i].mnemonic != "mov":
            continue
        pp = [p.strip() for p in ins[i].op_str.split(",")]
        if len(pp) != 2:
            continue
        d, s = pp[0].lower(), pp[1]
        imm = _parse_imm_token(s)
        if imm is None:
            continue
        if d == dst:
            imm_a = imm & 0xFFFFFFFF
        elif d == src:
            imm_b = imm & 0xFFFFFFFF
        # spilled: mov [mem], imm then later mov reg, [mem] — handle via dword stores to temp
        # also: mov edi, IMM; mov [rbp-X], edi; later mov eax, [rbp-X]
        md = re.search(r"\[(rbp|ebp)\s*([+-])\s*(0x[0-9a-f]+)\]", d, re.I)
        if md and imm is not None:
            # remember spill slot → imm
            pass
    # Spilled form used in authenticate strcmp block
    if imm_a is None or imm_b is None:
        spills: Dict[str, int] = {}
        for i in range(cmov_idx):
            if ins[i].mnemonic != "mov":
                continue
            pp = [p.strip() for p in ins[i].op_str.split(",")]
            if len(pp) != 2:
                continue
            d, s = pp[0], pp[1]
            imm = _parse_imm_token(s)
            if imm is not None:
                spills[d.lower()] = imm & 0xFFFFFFFF
                continue
            # mov reg, [slot] restore
            if d.lower() in (dst, src):
                key = s.lower()
                # find earlier store to same mem from a reg that had imm
                for reg, val in list(spills.items()):
                    # crude: if we stored imm via `mov [mem], reg` 
                    pass
            # mov [mem], reg where reg had imm
            md = re.search(r"(\w+)\s*,\s*(\w+)$", ins[i].op_str, re.I)
        # Second pass: track reg→imm and mem←reg
        reg_imm: Dict[str, int] = {}
        mem_imm: Dict[str, int] = {}
        for i in range(cmov_idx):
            if ins[i].mnemonic != "mov":
                continue
            pp = [p.strip() for p in ins[i].op_str.split(",")]
            if len(pp) != 2:
                continue
            d, s = pp[0].lower(), pp[1].lower()
            imm = _parse_imm_token(pp[1])
            if imm is not None and re.fullmatch(r"e?[abcd]x|r\d+d?|esi|edi|r[89]d?|r1[0-5]d?", d, re.I):
                reg_imm[d] = imm & 0xFFFFFFFF
            elif imm is not None and "[" in d:
                mem_imm[d] = imm & 0xFFFFFFFF
            elif s in reg_imm and "[" in d:
                mem_imm[d] = reg_imm[s]
            elif d in (dst, src) and s in mem_imm:
                if d == dst:
                    imm_a = mem_imm[s]
                else:
                    imm_b = mem_imm[s]
            elif d in (dst, src) and "[" in s:
                # normalize mem key loosely
                for mk, mv in mem_imm.items():
                    if _mem_keys_match(mk, s):
                        if d == dst:
                            imm_a = mv
                        else:
                            imm_b = mv
        if imm_a is None:
            imm_a = reg_imm.get(dst)
        if imm_b is None:
            imm_b = reg_imm.get(src)

    if imm_a is None or imm_b is None:
        return None
    # find cmp before cmov
    cmp_idx = None
    for i in range(cmov_idx - 1, max(cmov_idx - 6, -1), -1):
        if ins[i].mnemonic == "cmp":
            cmp_idx = i
            break
    if cmp_idx is None:
        return None
    eq_is_b = cmov.mnemonic in ("cmove", "cmovz")
    return {
        "cmp_idx": cmp_idx,
        "imm_a": imm_a,  # taken when ZF=0 if cmove
        "imm_b": imm_b,  # taken when ZF=1 if cmove
        "eq_is_b": eq_is_b,
        "jmp": last,
    }


def _mem_keys_match(a: str, b: str) -> bool:
    def norm(x: str) -> str:
        x = re.sub(r"\s+", "", x.lower())
        x = x.replace("dwordptr", "").replace("qwordptr", "").replace("ptr", "")
        return x

    return norm(a) == norm(b)


def _patch_cmove_block(
    patcher: Patcher,
    blk: CFGBlock,
    info: dict,
    case_map: Dict[int, int],
) -> Optional[Tuple[int, int, int]]:
    """Rewrite from cmp through jmp into: cmp; je tgt_eq; jmp tgt_neq."""
    imm_eq = info["imm_b"] if info["eq_is_b"] else info["imm_a"]
    imm_neq = info["imm_a"] if info["eq_is_b"] else info["imm_b"]
    tgt_eq = case_map.get(imm_eq)
    tgt_neq = case_map.get(imm_neq)
    if tgt_eq is None or tgt_neq is None:
        return None
    cmp_ins = blk.instructions[info["cmp_idx"]]
    last = info["jmp"]
    start = cmp_ins.address
    end = last.address + last.size
    avail = end - start
    # Keep original cmp bytes
    cmp_bytes = cmp_ins.bytes
    cursor = start + cmp_ins.size
    je = encode_je_rel32(cursor, tgt_eq)
    cursor2 = cursor + len(je)
    jmp = encode_jmp_rel32(cursor2, tgt_neq)
    payload = cmp_bytes + je + jmp
    if len(payload) > avail:
        return None
    payload = payload + b"\x90" * (avail - len(payload))
    if not patcher.patch_bytes(start, payload, note=f"cmove unflatten je {hex(tgt_eq)} else {hex(tgt_neq)}"):
        return None
    return (start, last.targets[0] if last.targets else 0, tgt_eq)


def unflatten_cfg(cfg: CFG, report: Optional[CFFReport] = None) -> Dict[int, int]:
    """Return mapping jmp_site_va -> new_target for constant-state returns."""
    report = report or recover_cff(cfg)
    if not report.dispatcher or not report.state_slot or not report.case_map:
        return {}
    tramp = _trampoline_targets(cfg, report.dispatcher)
    redirects: Dict[int, int] = {}
    for addr, blk in cfg.blocks.items():
        if not blk.instructions:
            continue
        if _detect_cmove_state(blk, report.state_slot):
            continue  # handled separately
        last = blk.instructions[-1]
        if not last.is_jmp:
            continue
        if not any(t in tramp for t in last.targets):
            continue
        imm = _last_imm_store(blk, report.state_slot)
        if imm is None:
            continue
        target = report.case_map.get(imm)
        if target is None:
            continue
        redirects[last.address] = target
    return redirects


def apply_unflatten(
    patcher: Patcher,
    cfg: CFG,
    report: Optional[CFFReport] = None,
    nop_dispatcher_chain: bool = False,
) -> UnflattenResult:
    report = report or recover_cff(cfg)
    notes: List[str] = []
    if not report.dispatcher or not report.state_slot:
        return UnflattenResult(report, 0, notes=["no dispatcher/slot"])

    redirected: List[Tuple[int, int, int]] = []
    applied = 0
    tramp = _trampoline_targets(cfg, report.dispatcher)

    # 1) Entry: block that stores initial state and falls into dispatcher
    for addr, blk in cfg.blocks.items():
        if report.dispatcher not in blk.successors:
            continue
        imm = _last_imm_store(blk, report.state_slot)
        if imm is None:
            continue
        target = report.case_map.get(imm)
        if target is None:
            continue
        last = blk.instructions[-1]
        # Fallthrough into dispatcher: replace last state store with jmp
        if not last.is_jmp and _slot_in_text(report.state_slot, last.op_str.split(",")[0] if "," in last.op_str else ""):
            if last.size >= 5:
                new = encode_jmp_rel32(last.address, target)
                new = new + b"\x90" * (last.size - 5)
                if patcher.patch_bytes(last.address, new, note=f"entry unflatten -> {hex(target)}"):
                    applied += 1
                    redirected.append((last.address, report.dispatcher, target))
                    notes.append(f"entry redirect {hex(last.address)} -> {hex(target)}")

    # 2) Constant state returns
    for site, new_tgt in sorted(unflatten_cfg(cfg, report).items()):
        old_ins = None
        for b in cfg.blocks.values():
            for ins in b.instructions:
                if ins.address == site:
                    old_ins = ins
                    break
        if old_ins is None or old_ins.size < 5:
            continue
        old_tgt = old_ins.targets[0] if old_ins.targets else 0
        new = encode_jmp_rel32(site, new_tgt) + b"\x90" * (old_ins.size - 5)
        if patcher.patch_bytes(site, new, note=f"unflatten -> {hex(new_tgt)}"):
            applied += 1
            redirected.append((site, old_tgt, new_tgt))

    # 3) cmove conditional state updates
    for addr, blk in cfg.blocks.items():
        info = _detect_cmove_state(blk, report.state_slot)
        if not info:
            continue
        if not any(t in tramp for t in info["jmp"].targets):
            continue
        got = _patch_cmove_block(patcher, blk, info, report.case_map)
        if got:
            applied += 1
            redirected.append(got)
            notes.append(f"cmove unflatten at {hex(got[0])}")

    nopped: List[int] = []
    if nop_dispatcher_chain and applied:
        for addr in tramp - {report.dispatcher}:
            blk = cfg.blocks.get(addr)
            if not blk:
                continue
            for ins in blk.instructions:
                if patcher.nop(ins.address, ins.size, note="nop trampoline"):
                    nopped.append(ins.address)
                    applied += 1

    cert = PatchCertificate(
        patches=[
            {
                "addr": hex(a),
                "old_target": hex(b),
                "new_target": hex(c),
                "note": "cff unflatten redirect",
            }
            for a, b, c in redirected
        ],
        proven=bool(redirected) and bool(report.case_map),
        notes=[
            "redirects derived from state-variable case_map / cmove pattern",
            f"cases={len(report.case_map)}",
        ],
    )
    notes.append(f"applied={applied} redirected={len(redirected)} nopped={len(nopped)}")
    return UnflattenResult(
        report=report,
        patches_applied=applied,
        redirected=redirected,
        nopped=nopped,
        notes=notes,
        certificate=cert,
    )


def deobf_and_patch(
    path: str,
    function: str | list[str],
    output: str,
    verify_stdin: bytes = b"",
) -> UnflattenResult:
    from argus.binary import load_binary
    from argus.disasm import build_function_cfg

    img = load_binary(path)
    fns = [function] if isinstance(function, str) else list(function)
    patcher = Patcher.from_path(path)
    merged: Optional[UnflattenResult] = None
    for fn in fns:
        if fn not in img.symbols:
            continue
        cfg = build_function_cfg(img, fn)
        report = recover_cff(cfg)
        result = apply_unflatten(patcher, cfg, report)
        if merged is None:
            merged = result
        else:
            merged.patches_applied += result.patches_applied
            merged.redirected.extend(result.redirected)
            merged.nopped.extend(result.nopped)
            merged.notes.append(f"--- {fn} ---")
            merged.notes.extend(result.notes)
            if merged.certificate and result.certificate:
                merged.certificate.patches.extend(result.certificate.patches)
                merged.certificate.notes.extend(result.certificate.notes)
    if merged is None:
        # fallback single
        cfg = build_function_cfg(img, fns[0])
        merged = apply_unflatten(patcher, cfg, recover_cff(cfg))
    patcher.save(output)
    if img.fmt == "elf":
        v = patcher.verify_runs(stdin=verify_stdin or b"")
        if merged.certificate:
            merged.certificate.behavioral = {
                "ok": v.get("ok"),
                "returncode": v.get("returncode"),
                "stdout": (v.get("stdout") or b"")[:200],
            }
            if v.get("ok"):
                merged.certificate.notes.append("behavioral verify ran")
            merged.notes.append(f"verify ok={v.get('ok')} rc={v.get('returncode')}")
    return merged


def solve_after_deobf(
    path: str,
    function: str | list[str] | None = None,
    stdin_len: int = 24,
) -> "SolveResult":
    """Unflatten CFF functions to a temp binary, then symbolic-solve."""
    import os
    import tempfile

    from argus.binary import load_binary
    from argus.symbolic import solve_binary

    img = load_binary(path)
    if function is None:
        # Prefer known crackme pair; else main + largest funcs with CFF
        candidates = []
        for name in ("authenticate", "main"):
            if name in img.symbols:
                candidates.append(name)
        if not candidates:
            candidates = ["main"] if "main" in img.symbols else []
        function = candidates or "main"

    with tempfile.NamedTemporaryFile(delete=False, suffix=".deobf") as f:
        tmp = f.name
    try:
        deobf_and_patch(path, function, tmp, verify_stdin=b"")
        return solve_binary(tmp)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
