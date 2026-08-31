"""Argus Global State Struct Invariant Detector.

Identifies core application state flags (e.g. is_licensed, is_admin, is_premium, trial_expired)
by clustering repeated heap/struct offset accesses: [reg + offset].
Pinpoints the exact writer sites (setcc / mov) to patch the flag globally across the entire binary.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import capstone as cs


@dataclass
class StateFlag:
    offset: int
    read_count: int
    readers: List[Dict[str, Any]] = field(default_factory=list)
    writers: List[Dict[str, Any]] = field(default_factory=list)
    recommended_patch: Optional[Dict[str, Any]] = None


def scan_state_struct_invariants(
    img: Any,
    *,
    min_reads: int = 4,
    max_scan_bytes: int = 2 * 1024 * 1024,
) -> List[Dict[str, Any]]:
    """Scan executable sections to locate global state flags in heap/object structures."""
    mode = cs.CS_MODE_64 if getattr(img, "bits", 64) == 64 else cs.CS_MODE_32
    md = cs.Cs(cs.CS_ARCH_X86, mode)

    read_counts = Counter()
    readers_by_off = defaultdict(list)
    writers_by_off = defaultdict(list)

    mem_rx = re.compile(r'\[([a-z0-9]+)\s*\+\s*(0x[0-9a-f]+|\d+)\]', re.IGNORECASE)

    for sec in getattr(img, "sections", []):
        if not getattr(sec, "executable", False) or not getattr(sec, "data", None):
            continue
        data = sec.data[:min(len(sec.data), max_scan_bytes)]
        sec_addr = getattr(sec, "addr", 0)

        for insn in md.disasm(data, sec_addr):
            m = mem_rx.search(insn.op_str)
            if not m:
                continue

            base_reg = m.group(1).lower()
            if base_reg in ("rsp", "rbp", "esp", "ebp", "rip", "eip"):
                continue

            off_str = m.group(2)
            try:
                off = int(off_str, 16) if off_str.startswith("0x") else int(off_str)
            except ValueError:
                continue

            if off > 0x1000:
                continue

            # Check for boolean comparison: cmp [reg + off], 1 / test [reg + off], 1
            if insn.mnemonic in ("cmp", "test"):
                if ", 1" in insn.op_str or ", 0" in insn.op_str:
                    read_counts[off] += 1
                    if len(readers_by_off[off]) < 8:
                        readers_by_off[off].append({
                            "addr": hex(insn.address),
                            "mnemonic": insn.mnemonic,
                            "op_str": insn.op_str,
                        })

            # Check for state writer: sete/setne/setg [reg + off] or mov byte ptr [reg + off], ...
            elif insn.mnemonic.startswith("set") or (insn.mnemonic == "mov" and ", 1" in insn.op_str):
                if len(writers_by_off[off]) < 8:
                    writers_by_off[off].append({
                        "addr": hex(insn.address),
                        "mnemonic": insn.mnemonic,
                        "op_str": insn.op_str,
                    })

    results: List[Dict[str, Any]] = []
    for off, count in read_counts.most_common(20):
        if count < min_reads:
            break
        writers = writers_by_off.get(off, [])
        rec_patch = None
        if writers:
            w0 = writers[0]
            w_addr = w0["addr"]
            if w0["mnemonic"].startswith("set"):
                rec_patch = {
                    "kind": "force_flag",
                    "addr": w_addr,
                    "target_offset": hex(off),
                    "why": f"Global AppState flag at +{hex(off)} (checked in {count} functions); force writer at {w_addr}",
                }

        results.append({
            "offset": hex(off),
            "offset_dec": off,
            "read_count": count,
            "sample_readers": readers_by_off[off],
            "writers": writers,
            "recommended_patch": rec_patch,
        })

    return results
