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
            # indirect jmp: stop
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
            for t in last.targets:
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
