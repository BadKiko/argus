from __future__ import annotations

"""OLLVM-style CFF recovery via state-variable analysis (Intel Capstone syntax)."""

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from argus.disasm.cfg import CFG


@dataclass
class StateTransition:
    from_block: int
    state_value: int
    to_block: int


@dataclass
class CFFReport:
    dispatcher: Optional[int]
    state_slot: Optional[str]
    state_blocks: List[int]
    case_map: Dict[int, int] = field(default_factory=dict)
    recovered_edges: List[Tuple[int, int]] = field(default_factory=list)
    transitions: List[StateTransition] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "dispatcher": hex(self.dispatcher) if self.dispatcher else None,
            "state_slot": self.state_slot,
            "case_map": {hex(k): hex(v) for k, v in self.case_map.items()},
            "recovered_edges": [[hex(u), hex(v)] for u, v in self.recovered_edges],
            "transitions": [
                {"from": hex(t.from_block), "state": hex(t.state_value), "to": hex(t.to_block)}
                for t in self.transitions
            ],
            "notes": self.notes,
        }


# dword ptr [rbp - 0x2c] / PE x64 [rsp+0x28]
_MEM_SLOT = re.compile(
    r"(?:byte|word|dword|qword)\s+ptr\s+\[(rbp|ebp|rsp|r\d+b)\s*([+-])\s*(0x[0-9a-f]+|\d+)\]",
    re.I,
)


def _slot_key(m: re.Match) -> str:
    off = m.group(3)
    if not off.lower().startswith("0x"):
        off = hex(int(off))
    return f"[{m.group(1).lower()}{m.group(2)}{off.lower()}]"


def _slot_in_text(slot: str, text: str) -> bool:
    inner = slot.strip("[]")
    m = re.match(r"(rbp|ebp)([+-])(0x[0-9a-f]+)", inner, re.I)
    if not m:
        return slot in text
    return bool(re.search(rf"{m.group(1)}\s*\{m.group(2)}\s*{m.group(3)}", text, re.I))


def _parse_imm_token(tok: str) -> Optional[int]:
    tok = tok.strip()
    if re.fullmatch(r"0x[0-9a-f]+|\d+", tok, re.I):
        return int(tok, 0)
    return None


def find_dispatcher(cfg: CFG) -> Optional[int]:
    best, best_score = None, -1
    for addr in cfg.blocks:
        if addr not in cfg.graph:
            continue
        blk = cfg.blocks.get(addr)
        has_indirect = False
        if blk:
            for ins in blk.instructions:
                if ins.mnemonic == "jmp" and "[" in ins.op_str and "ptr" in ins.op_str:
                    has_indirect = True
                    break
        indeg = cfg.graph.in_degree(addr)
        outdeg = cfg.graph.out_degree(addr)
        back = 0
        for pred in cfg.graph.predecessors(addr):
            pblk = cfg.blocks.get(pred)
            if pblk and pblk.instructions:
                last = pblk.instructions[-1]
                if last.is_jmp and addr in last.targets:
                    back += 1
        score = back * 10 + indeg * outdeg + (15 if has_indirect else 0)
        if back >= 1 and outdeg >= 2 and score > best_score:
            best, best_score = addr, score
    if best is not None:
        return best
    for addr in cfg.blocks:
        if addr not in cfg.graph:
            continue
        indeg = cfg.graph.in_degree(addr)
        outdeg = cfg.graph.out_degree(addr)
        score = indeg * outdeg
        if indeg >= 2 and outdeg >= 2 and score > best_score:
            best, best_score = addr, score
    return best


def detect_state_slot(cfg: CFG, dispatcher: int) -> Optional[str]:
    writes: Counter = Counter()
    reads: Counter = Counter()
    for blk in cfg.blocks.values():
        for ins in blk.instructions:
            parts = [p.strip() for p in ins.op_str.split(",")]
            if ins.mnemonic == "mov" and len(parts) == 2:
                md = _MEM_SLOT.search(parts[0])
                if md and _parse_imm_token(parts[1]) is not None:
                    writes[_slot_key(md)] += 1
            for part in parts:
                mr = _MEM_SLOT.search(part)
                if mr and ins.mnemonic in ("mov", "cmp", "sub", "add"):
                    reads[_slot_key(mr)] += 1
    disp_blk = cfg.blocks.get(dispatcher)
    disp_text = " ".join(f"{i.op_str}" for i in (disp_blk.instructions if disp_blk else []))
    best, best_score = None, 0
    for slot, wc in writes.items():
        score = wc * 2 + reads.get(slot, 0)
        if _slot_in_text(slot, disp_text):
            score += 8
        if score > best_score:
            best, best_score = slot, score
    return best


def extract_state_stores(cfg: CFG, state_slot: str) -> List[Tuple[int, int]]:
    out: List[Tuple[int, int]] = []
    for addr, blk in cfg.blocks.items():
        for ins in blk.instructions:
            if ins.mnemonic != "mov":
                continue
            parts = [p.strip() for p in ins.op_str.split(",")]
            if len(parts) != 2:
                continue
            imm = _parse_imm_token(parts[1])
            if imm is not None and _slot_in_text(state_slot, parts[0]):
                out.append((addr, imm & 0xFFFFFFFF))
    return out


def extract_dispatcher_cases(cfg: CFG, dispatcher: int, state_slot: str) -> Dict[int, int]:
    """Recover state_imm -> handler from compare chain, including spilled aliases."""
    cases: Dict[int, int] = {}
    queue = [dispatcher]
    seen: Set[int] = set()
    aliases: Set[str] = {state_slot}
    state_regs: Set[str] = set()

    def is_state_mem(text: str) -> bool:
        return any(_slot_in_text(s, text) for s in aliases)

    while queue and len(seen) < 100:
        a = queue.pop(0)
        if a in seen or a not in cfg.blocks:
            continue
        seen.add(a)
        blk = cfg.blocks[a]
        for i, ins in enumerate(blk.instructions):
            parts = [p.strip() for p in ins.op_str.split(",")]
            if ins.mnemonic == "mov" and len(parts) == 2:
                dst, src = parts[0], parts[1]
                if is_state_mem(src):
                    state_regs.add(dst.lower())
                elif src.lower() in state_regs:
                    md = _MEM_SLOT.search(dst)
                    if md:
                        aliases.add(_slot_key(md))
                    elif re.fullmatch(r"e?[abcd]x|r\d+d?", dst, re.I):
                        state_regs.add(dst.lower())
            elif ins.mnemonic == "sub" and len(parts) == 2 and parts[0].lower() in state_regs:
                imm = _parse_imm_token(parts[1])
                for j in range(i + 1, min(i + 5, len(blk.instructions))):
                    nxt = blk.instructions[j]
                    if nxt.is_conditional and nxt.mnemonic in ("je", "jz") and nxt.targets and imm is not None:
                        cases[imm & 0xFFFFFFFF] = nxt.targets[0]
                        break
            elif ins.mnemonic == "cmp" and len(parts) == 2:
                # switch-style: cmp reg/mem, imm ; je handler
                left, right = parts[0], parts[1]
                imm = _parse_imm_token(right)
                if imm is None:
                    imm = _parse_imm_token(left)
                stateish = (left.lower() in state_regs) or is_state_mem(left) or is_state_mem(right)
                if imm is not None and stateish:
                    for j in range(i + 1, min(i + 4, len(blk.instructions))):
                        nxt = blk.instructions[j]
                        if nxt.is_conditional and nxt.mnemonic in ("je", "jz") and nxt.targets:
                            cases[imm & 0xFFFFFFFF] = nxt.targets[0]
                            break
            elif ins.mnemonic == "jmp" and "[" in ins.op_str:
                # jmp qword ptr [reg*8 + table] — record table base if immediate present
                m = re.search(r"0x[0-9a-f]+", ins.op_str, re.I)
                if m:
                    notes_table = int(m.group(0), 16)
                    # cannot resolve without memory; leave marker via alias note later
                    _ = notes_table
        for s in blk.successors:
            if s not in seen:
                queue.append(s)
    return cases


def recover_cff(cfg: CFG) -> CFFReport:
    notes: List[str] = []
    disp = find_dispatcher(cfg)
    if disp is None:
        return CFFReport(None, None, [], notes=["no dispatcher-like hub found"])

    notes.append(
        f"dispatcher 0x{disp:x} in={cfg.graph.in_degree(disp)} out={cfg.graph.out_degree(disp)}"
    )
    slot = detect_state_slot(cfg, disp)
    if not slot:
        notes.append("state slot not detected; falling back to hub edges")
        preds = list(cfg.graph.predecessors(disp))
        succs = list(cfg.graph.successors(disp))
        edges = sorted({(p, s) for p in preds for s in succs if s != disp})
        return CFFReport(disp, None, succs, {}, edges, [], notes)

    notes.append(f"state slot {slot}")
    cases = extract_dispatcher_cases(cfg, disp, slot)
    notes.append(f"dispatcher cases recovered: {len(cases)}")
    stores = extract_state_stores(cfg, slot)

    transitions: List[StateTransition] = []
    edges: Set[Tuple[int, int]] = set()
    for block, imm in stores:
        target = cases.get(imm)
        if target is not None and target != block:
            transitions.append(StateTransition(block, imm, target))
            edges.add((block, target))

    recovered = sorted(edges)
    notes.append(f"semantic edges from state analysis: {len(recovered)}")
    return CFFReport(
        dispatcher=disp,
        state_slot=slot,
        state_blocks=sorted(set(cases.values())),
        case_map=cases,
        recovered_edges=recovered,
        transitions=transitions,
        notes=notes,
    )


def cleaned_adjacency(cfg: CFG, report: CFFReport) -> Dict[int, List[int]]:
    adj: Dict[int, List[int]] = {a: list(cfg.blocks[a].successors) for a in cfg.blocks}
    if not report.dispatcher:
        return adj
    d = report.dispatcher
    for a, succs in list(adj.items()):
        adj[a] = [s for s in succs if s != d]
    for u, v in report.recovered_edges:
        adj.setdefault(u, [])
        if v not in adj[u]:
            adj[u].append(v)
    return adj
