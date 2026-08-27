from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple

import capstone as cs
import networkx as nx

from argus.binary.image import BinaryImage


@dataclass
class Instr:
    address: int
    size: int
    mnemonic: str
    op_str: str
    bytes: bytes
    is_branch: bool = False
    is_call: bool = False
    is_ret: bool = False
    is_jmp: bool = False
    is_conditional: bool = False
    targets: List[int] = field(default_factory=list)


@dataclass
class CFGBlock:
    addr: int
    instructions: List[Instr] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)

    @property
    def end_addr(self) -> int:
        if not self.instructions:
            return self.addr
        last = self.instructions[-1]
        return last.address + last.size

    @property
    def size(self) -> int:
        return sum(i.size for i in self.instructions)


@dataclass
class CFG:
    entry: int
    blocks: Dict[int, CFGBlock]
    graph: nx.DiGraph
    function_name: Optional[str] = None

    def block_addrs(self) -> List[int]:
        return sorted(self.blocks)

    def to_dot(self) -> str:
        lines = ["digraph CFG {", "  node [shape=box fontname=monospace];"]
        for addr, blk in sorted(self.blocks.items()):
            label_lines = [f"0x{addr:x}"]
            for ins in blk.instructions[:8]:
                label_lines.append(f"{ins.mnemonic} {ins.op_str}".strip())
            if len(blk.instructions) > 8:
                label_lines.append("...")
            label = "\\n".join(label_lines).replace('"', '\\"')
            lines.append(f'  n{addr:x} [label="{label}"];')
        for u, v in self.graph.edges():
            lines.append(f"  n{u:x} -> n{v:x};")
        lines.append("}")
        return "\n".join(lines)


_COND_JMP = {
    "je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe", "jg", "jge", "jl", "jle",
    "jo", "jno", "js", "jns", "jp", "jnp", "jcxz", "jecxz", "jrcxz",
}


_COND_JMP = {
    "je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe", "jg", "jge", "jl", "jle",
    "jo", "jno", "js", "jns", "jp", "jnp", "jcxz", "jecxz", "jrcxz",
}


def _resolve_jump_table_targets(
    image: BinaryImage,
    jmp_addr: int,
    insn_cache: Dict[int, Instr],
    md: cs.Cs,
    *,
    max_cases: int = 64,
) -> List[int]:
    """
    Recover PIC switch targets: lea base,[rip+disp]; movsxd/mov idx,[base+reg*4];
    add idx, base; jmp idx. Returns absolute code VAs.
    """
    # Walk back up to ~12 instructions looking for lea rip + scaled load + add
    back: List[Instr] = []
    # Prefer cached linear predecessors by scanning previous bytes
    probe = jmp_addr
    for _ in range(16):
        # find previous insn start heuristically (1..15 bytes back)
        found = None
        for delta in range(1, 16):
            a = probe - delta
            if a in insn_cache:
                found = insn_cache[a]
                break
            raw = image.read_bytes(a, 15)
            try:
                insns = list(md.disasm(raw, a))
            except cs.CsError:
                continue
            if not insns:
                continue
            if insns[0].address + insns[0].size == probe:
                mnemonic = insns[0].mnemonic.lower()
                found = Instr(
                    address=insns[0].address,
                    size=insns[0].size,
                    mnemonic=mnemonic,
                    op_str=insns[0].op_str,
                    bytes=bytes(insns[0].bytes),
                )
                insn_cache[a] = found
                break
        if not found:
            break
        back.append(found)
        probe = found.address
        if len(back) >= 12:
            break

    # Find lea with rip in recent insns
    table_base = None
    for ins in back:
        if ins.mnemonic != "lea":
            continue
        if "rip" not in (ins.op_str or "").lower() and "eip" not in (ins.op_str or "").lower():
            continue
        # parse [rip ± disp]
        import re

        m = re.search(r"\[(?:rip|eip)\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)\]", ins.op_str or "", re.I)
        if not m:
            continue
        sign, imm = m.group(1), m.group(2)
        disp = int(imm, 0)
        if sign == "-":
            disp = -disp
        table_base = ins.address + ins.size + disp
        break
    if table_base is None:
        return []

    # Read relative offsets (int32) until they look invalid
    targets: List[int] = []
    for i in range(max_cases):
        raw = image.read_bytes(table_base + i * 4, 4)
        if len(raw) < 4:
            break
        rel = int.from_bytes(raw, "little", signed=True)
        tgt = (table_base + rel) & ((1 << 64) - 1)
        sec = image.section_at(tgt)
        if not (sec and sec.executable):
            # stop at first non-code; allow a couple zeros
            if rel == 0 and i == 0:
                continue
            break
        if tgt not in targets:
            targets.append(tgt)
    return targets[:max_cases]


def _make_cs(arch: str) -> cs.Cs:
    if arch == "x86_64":
        md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    else:
        md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32)
    md.detail = True
    return md


def disassemble_at(image: BinaryImage, addr: int, max_insns: int = 1) -> List[Instr]:
    md = _make_cs(image.arch)
    raw = image.read_bytes(addr, 16 * max_insns)
    out: List[Instr] = []
    for i in md.disasm(raw, addr):
        mnemonic = i.mnemonic.lower()
        is_ret = mnemonic in ("ret", "retn", "retf")
        is_call = mnemonic == "call"
        is_jmp = mnemonic == "jmp"
        is_cond = mnemonic in _COND_JMP
        is_branch = is_ret or is_call or is_jmp or is_cond
        targets: List[int] = []
        if i.operands:
            for op in i.operands:
                if op.type == cs.x86.X86_OP_IMM:
                    targets.append(int(op.imm))
        out.append(
            Instr(
                address=i.address,
                size=i.size,
                mnemonic=mnemonic,
                op_str=i.op_str,
                bytes=bytes(i.bytes),
                is_branch=is_branch,
                is_call=is_call,
                is_ret=is_ret,
                is_jmp=is_jmp,
                is_conditional=is_cond,
                targets=targets,
            )
        )
        if len(out) >= max_insns:
            break
    return out


def build_cfg(
    image: BinaryImage,
    entry: Optional[int] = None,
    max_blocks: int = 4096,
    function_name: Optional[str] = None,
) -> CFG:
    """Recursive-descent CFG within executable memory."""
    if entry is None:
        if function_name and function_name in image.symbols:
            entry = image.symbols[function_name].addr
        else:
            entry = image.entry

    md = _make_cs(image.arch)
    leaders: Set[int] = {entry}
    work: List[int] = [entry]
    seen_trace: Set[int] = set()
    fallthrough: Dict[int, int] = {}
    edges: Set[Tuple[int, int]] = set()
    insn_cache: Dict[int, Instr] = {}

    def executable(addr: int) -> bool:
        sec = image.section_at(addr)
        return bool(sec and sec.executable)

    while work and len(leaders) < max_blocks * 4:
        addr = work.pop()
        if addr in seen_trace or not executable(addr):
            continue
        seen_trace.add(addr)
        raw = image.read_bytes(addr, 15)
        try:
            insns = list(md.disasm(raw, addr))
        except cs.CsError:
            continue
        if not insns:
            continue
        i = insns[0]
        mnemonic = i.mnemonic.lower()
        instr = Instr(
            address=i.address,
            size=i.size,
            mnemonic=mnemonic,
            op_str=i.op_str,
            bytes=bytes(i.bytes),
            is_ret=mnemonic in ("ret", "retn", "retf"),
            is_call=mnemonic == "call",
            is_jmp=mnemonic == "jmp",
            is_conditional=mnemonic in _COND_JMP,
        )
        instr.is_branch = instr.is_ret or instr.is_call or instr.is_jmp or instr.is_conditional
        if i.operands:
            for op in i.operands:
                if op.type == cs.x86.X86_OP_IMM:
                    instr.targets.append(int(op.imm))
        insn_cache[addr] = instr
        nxt = addr + i.size

        if instr.is_ret:
            continue
        if instr.is_jmp:
            for t in instr.targets:
                if executable(t):
                    leaders.add(t)
                    edges.add((addr, t))
                    work.append(t)
            # indirect jmp: try PIC jump-table recovery
            if not instr.targets:
                for t in _resolve_jump_table_targets(image, addr, insn_cache, md, max_cases=64):
                    if executable(t):
                        instr.targets.append(t)
                        leaders.add(t)
                        edges.add((addr, t))
                        work.append(t)
            continue
        if instr.is_conditional:
            for t in instr.targets:
                if executable(t):
                    leaders.add(t)
                    edges.add((addr, t))
                    work.append(t)
            if executable(nxt):
                leaders.add(nxt)
                edges.add((addr, nxt))
                fallthrough[addr] = nxt
                work.append(nxt)
            continue
        if instr.is_call:
            for t in instr.targets:
                # do not descend into callees for intra-function CFG by default
                pass
            if executable(nxt):
                fallthrough[addr] = nxt
                work.append(nxt)
            continue
        # ordinary instruction
        if executable(nxt):
            fallthrough[addr] = nxt
            work.append(nxt)

    # Split into blocks at leaders
    # Also mark fallthrough targets of branches as leaders (already done)
    # Any instruction that is target of edge becomes leader
    for _, dst in edges:
        leaders.add(dst)

    leaders = {a for a in leaders if a in insn_cache or executable(a)}
    # Ensure we have instructions for leaders by re-walking linear regions
    blocks: Dict[int, CFGBlock] = {}
    sorted_leaders = sorted(leaders)

    def collect_block(start: int) -> CFGBlock:
        blk = CFGBlock(addr=start)
        addr = start
        while True:
            if addr not in insn_cache:
                # disassemble fresh
                raw = image.read_bytes(addr, 15)
                insns = list(md.disasm(raw, addr))
                if not insns:
                    break
                i = insns[0]
                mnemonic = i.mnemonic.lower()
                instr = Instr(
                    address=i.address,
                    size=i.size,
                    mnemonic=mnemonic,
                    op_str=i.op_str,
                    bytes=bytes(i.bytes),
                    is_ret=mnemonic in ("ret", "retn", "retf"),
                    is_call=mnemonic == "call",
                    is_jmp=mnemonic == "jmp",
                    is_conditional=mnemonic in _COND_JMP,
                )
                instr.is_branch = instr.is_ret or instr.is_call or instr.is_jmp or instr.is_conditional
                if i.operands:
                    for op in i.operands:
                        if op.type == cs.x86.X86_OP_IMM:
                            instr.targets.append(int(op.imm))
                insn_cache[addr] = instr
            instr = insn_cache[addr]
            blk.instructions.append(instr)
            nxt = addr + instr.size
            if instr.is_ret or instr.is_jmp or instr.is_conditional:
                break
            if nxt in leaders:
                break
            addr = nxt
            if len(blk.instructions) > 512:
                break
        return blk

    for lead in sorted_leaders:
        if not executable(lead):
            continue
        blocks[lead] = collect_block(lead)

    g = nx.DiGraph()
    for addr in blocks:
        g.add_node(addr)

    # Connect blocks
    for addr, blk in blocks.items():
        if not blk.instructions:
            continue
        last = blk.instructions[-1]
        if last.is_ret:
            continue
        if last.is_jmp:
            targets = list(last.targets)
            if not targets:
                targets = _resolve_jump_table_targets(image, last.address, insn_cache, md, max_cases=64)
                last.targets.extend(targets)
            for t in targets:
                if t in blocks:
                    g.add_edge(addr, t)
                    blk.successors.append(t)
            continue
        if last.is_conditional:
            for t in last.targets:
                if t in blocks:
                    g.add_edge(addr, t)
                    blk.successors.append(t)
            fall = last.address + last.size
            if fall in blocks:
                g.add_edge(addr, fall)
                blk.successors.append(fall)
            continue
        # fallthrough to next block
        fall = last.address + last.size
        if fall in blocks:
            g.add_edge(addr, fall)
            blk.successors.append(fall)

    for u, v in g.edges():
        if v in blocks and u not in blocks[v].predecessors:
            blocks[v].predecessors.append(u)

    return CFG(entry=entry, blocks=blocks, graph=g, function_name=function_name)


def build_function_cfg(image: BinaryImage, name: str) -> CFG:
    if name not in image.symbols:
        raise KeyError(f"Symbol not found: {name}")
    return build_cfg(image, entry=image.symbols[name].addr, function_name=name)
