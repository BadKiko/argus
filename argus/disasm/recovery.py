from __future__ import annotations

"""Recover approximate function bounds without symbols (stripped ELFs)."""

import os
from dataclasses import dataclass
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

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
        nxt = self.starts[best + 1] if best + 1 < len(self.starts) else start + 0x10000
        if start <= addr < nxt:
            return FuncBound(start, nxt, source=b.source if b else "gap")
        return None

    def nearby_label(self, addr: int) -> Optional[str]:
        b = self.covering(addr)
        return b.name if b else None

    def function_at(self, addr: int) -> Optional[FuncBound]:
        """Exact start match, else covering."""
        if addr in self.bounds:
            return self.bounds[addr]
        return self.covering(addr)

    def iter_functions(self, limit: int = 10_000) -> Iterator[FuncBound]:
        for i, st in enumerate(self.starts):
            if i >= limit:
                break
            b = self.bounds.get(st)
            if b:
                yield b


# (path, mtime_ns, size, text_fp) -> index
_CACHE: Dict[Tuple[str, int, int, int], FuncIndex] = {}


def _exec_sections(img: BinaryImage) -> List[Tuple[int, bytes]]:
    out = []
    for s in img.sections:
        if s.executable and s.data and len(s.data) >= 16:
            out.append((s.addr, s.data))
    return out


def _scan_prologues(data: bytes, base: int, starts: Dict[int, str]) -> None:
    for pro in _PROLOGUES:
        i = 0
        while True:
            j = data.find(pro, i)
            if j < 0:
                break
            if j == 0 or data[j - 1] in (0x90, 0xCC, 0xC3) or (j % 16 == 0):
                starts.setdefault(base + j, "prologue")
            elif pro.startswith(b"\xf3\x0f\x1e\xfa"):
                starts.setdefault(base + j, "endbr64")
            i = j + 1


def _scan_call_targets(
    img: BinaryImage, data: bytes, base: int, starts: Dict[int, str], limit: int = 200_000
) -> None:
    """Collect direct near-call targets as function entries (sampled for huge .text)."""
    import capstone as cs

    mode = cs.CS_MODE_64 if img.bits == 64 else cs.CS_MODE_32
    md = cs.Cs(cs.CS_ARCH_X86, mode)
    md.detail = True
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
                    tgt = int(op.imm) & ((1 << img.bits) - 1)
                    starts.setdefault(tgt, "call_target")
                    n += 1
            break
        offset += max(consumed, step)


def _eh_frame_starts(img: BinaryImage) -> Dict[int, str]:
    """Parse CIE/FDE for FDE initial_location (DWARF32)."""
    sec = None
    for s in img.sections:
        if s.name == ".eh_frame" and s.data and len(s.data) > 16:
            sec = s
            break
    if not sec or not sec.data:
        return {}
    data = sec.data
    out: Dict[int, str] = {}
    i = 0
    exec_secs = _exec_sections(img)
    while i + 8 < len(data) and len(out) < 50_000:
        length = int.from_bytes(data[i : i + 4], "little")
        if length == 0:
            i += 4
            continue
        if length == 0xFFFFFFFF:
            break
        end = i + 4 + length
        if end > len(data) or length < 8:
            break
        cie_id = int.from_bytes(data[i + 4 : i + 8], "little")
        if cie_id != 0:
            field_at = i + 8
            if field_at + 4 <= len(data):
                rel = int.from_bytes(data[field_at : field_at + 4], "little", signed=True)
                pc = (sec.addr + field_at + rel) & ((1 << 64) - 1)
                if any(a <= pc < a + len(d) for a, d in exec_secs):
                    out[pc] = "eh_frame"
        i = end
    return out


def _plt_got_seeds(img: BinaryImage) -> Dict[int, str]:
    """
    Seed function starts from PLT stubs and import PLT addrs without full .text call-scan.
    Useful on multi-MB stripped binaries.
    """
    out: Dict[int, str] = {}
    for addr, _name in img.imports.items():
        if addr:
            out[addr] = "plt"
    for s in img.sections:
        if s.name in (".plt", ".plt.sec", ".plt.got") and s.data:
            # PLT entries often 16-byte aligned
            stride = 16 if img.bits == 64 else 16
            for off in range(0, len(s.data) - 4, stride):
                out[s.addr + off] = "plt_sec"
    return out


def _refine_end(img: BinaryImage, start: int, hard_end: int) -> int:
    """Shrink end using ret + nop/int3 padding before hard_end (best-effort)."""
    if hard_end <= start + 1:
        return hard_end
    # Scan last 64 bytes before next start for ret sled
    window_start = max(start, hard_end - 64)
    raw = img.read_bytes(window_start, hard_end - window_start)
    # find last ret (c3) followed by nop/int3/zeros
    last_ret = -1
    for i, b in enumerate(raw):
        if b == 0xC3:
            rest = raw[i + 1 :]
            if not rest or all(x in (0x90, 0xCC, 0x00) for x in rest[:16]):
                last_ret = i
    if last_ret >= 0:
        return min(hard_end, window_start + last_ret + 1)
    return hard_end


def _cache_key(img: BinaryImage) -> Tuple[str, int, int, int]:
    path = img.path or ""
    mtime_ns = 0
    size = 0
    try:
        st = os.stat(path)
        mtime_ns = getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9))
        size = st.st_size
    except OSError:
        pass
    return (path, mtime_ns, size, _text_fingerprint(img))


def recover_functions(img: BinaryImage, *, max_starts: int = 80_000) -> FuncIndex:
    """Public API: build / cache FuncIndex for stripped or named binaries."""
    return build_func_index(img, max_starts=max_starts)


def build_func_index(img: BinaryImage, *, max_starts: int = 80_000) -> FuncIndex:
    key = _cache_key(img)
    cached = _CACHE.get(key)
    if cached is not None:
        return cached

    starts: Dict[int, str] = {}
    text_ranges: List[Tuple[int, int]] = []
    for base, data in _exec_sections(img):
        text_ranges.append((base, base + len(data)))

    # Seed known symbols first (includes Windows .pdata runtime functions & ELF symbols)
    sym_by_addr = {}
    for s in img.symbols.values():
        if s.is_function and not s.is_import and s.addr:
            starts[s.addr] = "symbol"
            if s.size > 0:
                sym_by_addr[s.addr] = s

    for pc, src in _eh_frame_starts(img).items():
        starts.setdefault(pc, src)
    for pc, src in _plt_got_seeds(img).items():
        if any(lo <= pc < hi for lo, hi in text_ranges):
            starts.setdefault(pc, src)

    has_precise_functions = len(starts) >= 10
    for base, data in _exec_sections(img):
        if not has_precise_functions or len(data) <= 400_000:
            _scan_prologues(data, base, starts)
        if not has_precise_functions and len(data) <= 2_000_000 and len(starts) < max_starts // 2:
            _scan_call_targets(img, data, base, starts)

    # Always include program entry
    if img.entry and any(lo <= img.entry < hi for lo, hi in text_ranges):
        starts.setdefault(img.entry, "entry")

    ordered = sorted(a for a in starts if any(lo <= a < hi for lo, hi in text_ranges))
    if len(ordered) > max_starts:
        ordered = ordered[:max_starts]

    bounds: Dict[int, FuncBound] = {}
    for i, st in enumerate(ordered):
        if st in sym_by_addr and sym_by_addr[st].size > 0:
            end = st + sym_by_addr[st].size
            bounds[st] = FuncBound(st, end, source="pdata" if "sub_" in sym_by_addr[st].name else "symbol")
            continue
        nxt = ordered[i + 1] if i + 1 < len(ordered) else st + 0x2000
        for lo, hi in text_ranges:
            if lo <= st < hi:
                nxt = min(nxt, hi)
                break
        end = _refine_end(img, st, max(st + 1, nxt))
        src = starts.get(st, "heuristic")
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


def function_at(img: BinaryImage, addr: int) -> Optional[FuncBound]:
    return recover_functions(img).function_at(addr)


def function_covering(img: BinaryImage, addr: int) -> Optional[FuncBound]:
    return build_func_index(img).covering(addr)


def functions_covering(img: BinaryImage, addr: int) -> Tuple[Optional[int], Optional[int]]:
    """Return (start, end) exclusive end, or (None, None)."""
    b = function_covering(img, addr)
    if not b:
        return None, None
    return b.start, b.end


def iter_functions(img: BinaryImage, limit: int = 10_000) -> Iterable[FuncBound]:
    return recover_functions(img).iter_functions(limit=limit)
