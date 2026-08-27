from __future__ import annotations

"""Recover approximate function bounds without symbols (stripped ELFs)."""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from argus.binary.image import BinaryImage

# x86_64 / i386 common prologues
_PROLOGUES = (
    b"\x55\x48\x89\xe5",  # push rbp; mov rbp, rsp
    b"\x55\x89\xe5",  # push ebp; mov ebp, esp
    b"\xf3\x0f\x1e\xfa",  # endbr64
    b"\x41\x57\x41\x56",  # push r15; push r14 (common)
    b"\x53\x48\x83\xec",  # push rbx; sub rsp, imm
    b"\x55\x41\x57",  # push rbp; push r15
)


@dataclass
class FuncBound:
    start: int
    end: int  # exclusive best-effort
    source: str = "prologue"

    def contains(self, addr: int) -> bool:
        return self.start <= addr < self.end

    @property
    def name(self) -> str:
        return f"sub_{self.start:x}"


@dataclass
class FuncIndex:
    """Sorted function starts + bounds for a binary."""

    starts: List[int]
    bounds: Dict[int, FuncBound]  # start -> bound
    text_ranges: List[Tuple[int, int]]  # (addr, end) executable

    def covering(self, addr: int) -> Optional[FuncBound]:
        if not self.starts:
            return None
        # binary search last start <= addr
        lo, hi = 0, len(self.starts) - 1
        best = -1
        while lo <= hi:
            mid = (lo + hi) // 2
            if self.starts[mid] <= addr:
                best = mid
                lo = mid + 1
            else:
                hi = mid - 1
        if best < 0:
            return None
        start = self.starts[best]
        b = self.bounds.get(start)
        if b and b.contains(addr):
            return b
        # start matched but end unknown — allow until next start
        nxt = self.starts[best + 1] if best + 1 < len(self.starts) else start + 0x10000
        if start <= addr < nxt:
            return FuncBound(start, nxt, source=b.source if b else "gap")
        return None

    def nearby_label(self, addr: int) -> Optional[str]:
        b = self.covering(addr)
        return b.name if b else None


_CACHE: Dict[Tuple[str, int], FuncIndex] = {}


def _exec_sections(img: BinaryImage) -> List[Tuple[int, bytes]]:
    out = []
    for s in img.sections:
        if s.executable and s.data and len(s.data) >= 16:
            out.append((s.addr, s.data))
    return out


def _scan_prologues(data: bytes, base: int, starts: set) -> None:
    for pro in _PROLOGUES:
        i = 0
        while True:
            j = data.find(pro, i)
            if j < 0:
                break
            # align-ish: prefer 16-byte aligned or after call padding
            if j == 0 or data[j - 1] in (0x90, 0xCC, 0xC3) or (j % 16 == 0):
                starts.add(base + j)
            elif pro.startswith(b"\xf3\x0f\x1e\xfa"):  # endbr64 often unaligned mid-pad
                starts.add(base + j)
            i = j + 1


def _scan_call_targets(img: BinaryImage, data: bytes, base: int, starts: set, limit: int = 200_000) -> None:
    """Collect direct near-call targets as function entries (sampled for huge .text)."""
    import capstone as cs

    mode = cs.CS_MODE_64 if img.bits == 64 else cs.CS_MODE_32
    md = cs.Cs(cs.CS_ARCH_X86, mode)
    md.detail = True
    # sample stride on huge sections
    step = 1
    if len(data) > 4_000_000:
        step = 3
    n = 0
    offset = 0
    while offset < len(data) and n < limit:
        chunk = data[offset : offset + 64]
        if not chunk:
            break
        consumed = 0
        for insn in md.disasm(chunk, base + offset):
            consumed = insn.address + insn.size - (base + offset)
            if insn.mnemonic == "call" and insn.operands:
                op = insn.operands[0]
                if op.type == cs.CS_OP_IMM:
                    starts.add(int(op.imm) & ((1 << img.bits) - 1))
                    n += 1
            break  # one insn then stride
        offset += max(consumed, step)


def _eh_frame_starts(img: BinaryImage) -> List[int]:
    """Best-effort: parse CIE/FDE length headers for FDE initial_location (DWARF32)."""
    sec = None
    for s in img.sections:
        if s.name == ".eh_frame" and s.data and len(s.data) > 16:
            sec = s
            break
    if not sec or not sec.data:
        return []
    data = sec.data
    starts: List[int] = []
    i = 0
    # Cap parse work
    while i + 8 < len(data) and len(starts) < 50_000:
        if i + 4 > len(data):
            break
        length = int.from_bytes(data[i : i + 4], "little")
        if length == 0:
            i += 4
            continue
        if length == 0xFFFFFFFF:
            break  # DWARF64 — skip for MVP
        end = i + 4 + length
        if end > len(data) or length < 8:
            break
        cie_id = int.from_bytes(data[i + 4 : i + 8], "little")
        if cie_id != 0:
            # FDE: initial_location is PC-relative to this field (i+8)
            field_at = i + 8
            if field_at + 4 <= len(data):
                rel = int.from_bytes(data[field_at : field_at + 4], "little", signed=True)
                pc = (sec.addr + field_at + rel) & ((1 << 64) - 1)
                if any(a <= pc < a + len(d) for a, d in _exec_sections(img)):
                    starts.append(pc)
        i = end
    return starts


def build_func_index(img: BinaryImage, *, max_starts: int = 80_000) -> FuncIndex:
    key = (img.path or "", _text_fingerprint(img))
    cached = _CACHE.get(key)
    if cached is not None:
        return cached

    starts: set[int] = set()
    text_ranges: List[Tuple[int, int]] = []
    for base, data in _exec_sections(img):
        text_ranges.append((base, base + len(data)))
        _scan_prologues(data, base, starts)
        # Call-target scan is expensive on multi-MB .text — skip for huge sections
        if len(data) <= 2_000_000 and len(starts) < max_starts // 2:
            _scan_call_targets(img, data, base, starts)
    for pc in _eh_frame_starts(img):
        starts.add(pc)

    # Prefer symbol function starts when present
    for s in img.symbols.values():
        if s.is_function and not s.is_import and s.addr:
            starts.add(s.addr)

    ordered = sorted(a for a in starts if any(lo <= a < hi for lo, hi in text_ranges))
    if len(ordered) > max_starts:
        # keep denser low addresses + sample
        ordered = ordered[: max_starts]

    bounds: Dict[int, FuncBound] = {}
    for i, st in enumerate(ordered):
        nxt = ordered[i + 1] if i + 1 < len(ordered) else st + 0x2000
        # clamp to section end
        for lo, hi in text_ranges:
            if lo <= st < hi:
                nxt = min(nxt, hi)
                break
        end = max(st + 1, nxt)
        src = "symbol" if any(
            s.addr == st and s.is_function for s in img.symbols.values()
        ) else "heuristic"
        bounds[st] = FuncBound(st, end, source=src)

    idx = FuncIndex(starts=ordered, bounds=bounds, text_ranges=text_ranges)
    _CACHE[key] = idx
    return idx


def _text_fingerprint(img: BinaryImage) -> int:
    total = 0
    for s in img.sections:
        if s.executable and s.data:
            total ^= len(s.data) << 1
            total ^= s.addr
    return total


def function_covering(img: BinaryImage, addr: int) -> Optional[FuncBound]:
    return build_func_index(img).covering(addr)


def functions_covering(img: BinaryImage, addr: int) -> Tuple[Optional[int], Optional[int]]:
    """Return (start, end) exclusive end, or (None, None)."""
    b = function_covering(img, addr)
    if not b:
        return None, None
    return b.start, b.end
