"""Goal atlas: two-phase map of strings → pointers/tables → jumps/regs → module hops.

Phase 1 — query=: catalog matching strings across the primary and linked ELF .so / PE .dll.
Phase 2 — string_addr=: chase data pointers and table bases, then map local jumps and registers.

No patch plan. Works on PE and ELF. Do not expand the query into generic tokens.
"""

from __future__ import annotations

import heapq
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from argus.binary import load_binary
from argus.disasm.recovery import function_covering
from argus.discover import (
    is_patch_artifact,
    list_dependency_names,
    resolve_link_base,
    sibling_modules,
    signal_score,
)
from argus.find import _scan_section_ci, find_string_xrefs_multi, query_string_needles, rewind_encoded_string, decode_encoded_preview
from argus.payload import looks_host_engine_string

_JCC = {
    "je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe", "jg", "jge", "jl", "jle",
    "js", "jns", "jo", "jno", "jp", "jpo", "jcxz", "jecxz", "jrcxz",
}

_MAX_FN_BYTES = 0x6000
_MAX_FNS_PER_MOD = 16
_MAX_JUMPS_PER_FN = 40
_MAX_CALLS_PER_FN = 32
_WINDOW_BACK = 0x500
_WINDOW_FWD = 0x900
_STRINGS_PER_MOD = 20
_STRINGS_GLOBAL = 40
_MAX_GRAPH_FNS = 22
_MAX_GRAPH_DEPTH = 2
_FANIN_SCAN = 36
_CALLERS_CAP = 64

_REG_TOKEN = re.compile(
    r"\b(r(?:ax|bx|cx|dx|si|di|bp|sp|8|9|10|11|12|13|14|15)|e(?:ax|bx|cx|dx|si|di|bp|sp)|"
    r"[abcd](?:l|h|x)|sil|dil|bpl|spl)\b",
    re.I,
)


def _mod_kind(path: str, fmt: str) -> str:
    name = Path(path).name.lower()
    if name.endswith(".dll") or ".dll." in name:
        return "dll"
    if ".so" in name or name.endswith(".dylib"):
        return "so"
    if name.endswith(".exe") or fmt == "pe":
        return "exe" if name.endswith(".exe") else fmt
    if fmt == "elf":
        return "elf"
    return fmt or "bin"


def _query_needles(query: str) -> List[bytes]:
    """Exact query only — no token split, no shared validate-substring lists."""
    return [raw for _kind, raw in query_string_needles(query)]


def _collect_modules(primary: str, query: str, *, max_modules: int) -> Tuple[List[str], List[Dict[str, Any]]]:
    from argus.discover import is_binary_file, resolve_dependency

    prim = str(Path(primary).resolve())
    link_base = str(resolve_link_base(prim, None))
    needles = _query_needles(query)
    hops: List[Dict[str, Any]] = []
    paths: List[str] = [prim]
    seen: Set[str] = {prim}
    lb = Path(link_base)
    if lb.is_file():
        seen.add(str(lb.resolve()))

    base_path = lb if lb.is_file() else Path(prim)

    def _add(p: Path, via: str) -> None:
        if not p.is_file() or is_patch_artifact(p.name):
            return
        from argus.payload import is_payload_file

        if not is_binary_file(p) and not is_payload_file(p):
            return
        key = str(p.resolve())
        if key in seen:
            return
        seen.add(key)
        paths.append(key)
        hops.append({"from": Path(prim).name, "to": p.name, "path": key, "via": via})

    mag = b""
    try:
        mag = base_path.read_bytes()[:4]
    except OSError:
        mag = b""
    dep_via = "DT_NEEDED" if mag[:4] == b"\x7fELF" else "import"

    for dep in list_dependency_names(base_path):
        resolved = resolve_dependency(base_path, dep)
        if resolved is not None:
            _add(resolved, dep_via)

    for sib in sibling_modules(base_path, limit=24):
        via = None
        try:
            blob = sib.read_bytes()[:4_000_000]
        except OSError:
            continue
        if needles and any(n and n in blob for n in needles):
            via = "sibling_query"
        elif signal_score(sib) > 0:
            via = "sibling_related"
        if via:
            _add(sib, via)
        if len(paths) >= max_modules + 1:
            break
    try:
        from argus.payload import sibling_payloads

        for pay in sibling_payloads(base_path, limit=16):
            via = "payload"
            try:
                blob = pay.read_bytes()[:4_000_000]
            except OSError:
                continue
            if needles and any(n and n in blob for n in needles):
                via = "payload_query"
            _add(pay, via)
            if len(paths) >= max_modules + 1:
                break
    except Exception:
        pass

    paths = [prim] + [p for p in paths if p != prim]
    return paths[: max_modules + 1], hops


def _cs(img: Any):
    import capstone as cs

    mode = cs.CS_MODE_64 if getattr(img, "bits", 64) == 64 else cs.CS_MODE_32
    md = cs.Cs(cs.CS_ARCH_X86, mode)
    md.detail = True
    return md


def _rip_effective(insn: Any) -> Optional[int]:
    try:
        import capstone as cs
        from capstone.x86 import X86_REG_RIP

        for op in getattr(insn, "operands", []) or []:
            if op.type == cs.CS_OP_MEM and op.mem.base == X86_REG_RIP:
                return int(insn.address + insn.size + op.mem.disp)
    except Exception:
        return None
    return None


def _is_exec_va(img: Any, va: int) -> bool:
    sec = _section_at(img, va) if "_section_at" in globals() else None
    if sec is None:
        for s in getattr(img, "sections", []) or []:
            data = getattr(s, "data", None) or b""
            if data and s.addr <= va < s.addr + len(data):
                sec = s
                break
    return bool(sec and getattr(sec, "executable", False))


def _regs_in(text: str) -> List[str]:
    seen: List[str] = []
    for m in _REG_TOKEN.finditer(text or ""):
        r = m.group(0).lower()
        if r not in seen:
            seen.append(r)
    return seen


def _predicate_and_regs(insns: list, jcc_idx: int) -> Tuple[str, List[str], Optional[str]]:
    pred = ""
    regs: List[str] = []
    producer = None
    for b in range(max(0, jcc_idx - 6), jcc_idx):
        m = insns[b].mnemonic
        if m in ("test", "cmp", "sete", "setne", "setz", "setnz"):
            pred = f"{m} {insns[b].op_str}"
            regs = _regs_in(pred)
            try:
                for rid in getattr(insns[b], "regs_read", []) or []:
                    rname = insns[b].reg_name(rid)
                    if rname and rname not in regs:
                        regs.append(rname)
            except Exception:
                pass
    for b in range(max(0, jcc_idx - 10), jcc_idx):
        if insns[b].mnemonic == "call":
            producer = f"{hex(insns[b].address)} {insns[b].op_str}"
    return pred, regs, producer


def _scan_function(img: Any, start: int, end: int) -> Dict[str, Any]:
    md = _cs(img)
    size = min(max(end - start, 32), _MAX_FN_BYTES)
    data = img.read_bytes(start, size)
    if not data:
        return {"fn": hex(start), "jumps": [], "calls": [], "indirect": [], "imm_stores": []}
    insns = list(md.disasm(data, start))
    jumps: List[Dict[str, Any]] = []
    calls: List[Dict[str, Any]] = []
    indirect: List[Dict[str, Any]] = []
    imm_stores: List[Dict[str, Any]] = []
    rip_strings: List[Dict[str, Any]] = []
    fn_ptrs: List[int] = []
    imports = getattr(img, "imports", {}) or {}

    for i, insn in enumerate(insns):
        ea = _rip_effective(insn)
        if ea:
            text = _peek_cstring(img, ea)
            if text and len(text) >= 8:
                rip_strings.append({"addr": hex(insn.address), "target": hex(ea), "preview": text[:72]})
            elif _is_exec_va(img, ea):
                fn_ptrs.append(ea)
        m = insn.mnemonic
        if m in _JCC:
            target = None
            try:
                target = hex(int(insn.op_str, 16))
            except Exception:
                target = insn.op_str
            pred, regs, producer = _predicate_and_regs(insns, i)
            jumps.append(
                {
                    "addr": hex(insn.address),
                    "op": f"{m} {insn.op_str}",
                    "target": target,
                    "predicate": pred,
                    "regs": regs,
                    "producer_call": producer,
                }
            )
            if len(jumps) >= _MAX_JUMPS_PER_FN:
                pass
        if m == "call":
            rec = {"addr": hex(insn.address), "op": insn.op_str}
            try:
                tgt = int(insn.op_str, 16)
                rec["target"] = hex(tgt)
                rec["import"] = imports.get(tgt)
            except Exception:
                rec["target"] = None
                if "[" in (insn.op_str or ""):
                    rec["vtable"] = True
                    indirect.append(
                        {
                            "addr": hex(insn.address),
                            "op": f"call {insn.op_str}",
                            "kind": "indirect_call",
                        }
                    )
            calls.append(rec)
            if len(calls) >= _MAX_CALLS_PER_FN:
                continue
        if m == "jmp" and "[" in (insn.op_str or ""):
            indirect.append({"addr": hex(insn.address), "op": f"jmp {insn.op_str}", "kind": "jmp_table"})
        if m == "mov" and "," in (insn.op_str or "") and "[" in (insn.op_str or ""):
            right = insn.op_str.split(",", 1)[1].strip()
            try:
                imm = int(right, 0)
            except (TypeError, ValueError):
                imm = None
            if imm is not None and 0 < imm < 256:
                imm_stores.append({"addr": hex(insn.address), "imm": imm, "op": insn.op_str})

    name = None
    try:
        sym = (getattr(img, "symbols", {}) or {}).get(start)
        name = getattr(sym, "name", None)
    except Exception:
        name = None
    return {
        "fn": hex(start),
        "name": name or f"sub_{start:x}",
        "size": size,
        "caller_count": 0,
        "jumps": jumps,
        "calls": calls[:_MAX_CALLS_PER_FN],
        "indirect": indirect[:12],
        "imm_stores": imm_stores[:16],
        "rip_strings": rip_strings[:12],
        "fn_ptrs": [hex(v) for v in fn_ptrs[:12]],
    }


def _merge_windows(windows: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    if not windows:
        return []
    windows = sorted(windows)
    merged = [windows[0]]
    for lo, hi in windows[1:]:
        plo, phi = merged[-1]
        if lo <= phi + 0x40:
            merged[-1] = (plo, max(phi, hi))
        else:
            merged.append((lo, hi))
    return merged[:_MAX_FNS_PER_MOD]


def _section_at(img: Any, va: int):
    fn = getattr(img, "section_at", None)
    if callable(fn):
        return fn(va)
    for sec in getattr(img, "sections", []) or []:
        data = getattr(sec, "data", None) or b""
        if data and sec.addr <= va < sec.addr + len(data):
            return sec
    return None


def _va_in_image(img: Any, va: int) -> bool:
    return _section_at(img, va) is not None


def _string_va_ok(img: Any, va: int) -> bool:
    """Drop file-only sections (.comment/.shstrtab at VA 0) and tiny ELF notes."""
    sec = _section_at(img, va)
    if not sec or not getattr(sec, "data", None):
        return False
    if int(getattr(sec, "addr", 0) or 0) < 0x1000:
        return False
    name = (getattr(sec, "name", None) or "").lower()
    if name.startswith(".comment") or name.startswith(".note") or name in (".interp", ".shstrtab"):
        return False
    return True


def _ptr_size(img: Any) -> int:
    return 8 if getattr(img, "bits", 64) == 64 else 4


def _read_ptr(img: Any, va: int) -> Optional[int]:
    n = _ptr_size(img)
    b = img.read_bytes(va, n)
    if not b or len(b) < n:
        return None
    return int.from_bytes(b, "little")


def _peek_cstring(img: Any, va: int, *, maxlen: int = 80) -> Optional[str]:
    if not _string_va_ok(img, va):
        return None
    b = img.read_bytes(va, maxlen + 1) or b""
    if not b or not (32 <= b[0] < 127):
        return None
    raw = b.split(b"\0")[0]
    if len(raw) < 4:
        return None
    if sum(1 for c in raw if 32 <= c < 127 or c in (9, 10, 13)) < max(4, int(len(raw) * 0.85)):
        return None
    try:
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return None


def _pointer_sites(img: Any, va: int, *, limit: int = 24) -> List[int]:
    """Non-exec data locations holding a pointer to va (FPC/resource tables)."""
    bits = getattr(img, "bits", 64)
    needles = []
    if bits == 64:
        needles.append(va.to_bytes(8, "little"))
    if va < 0x100000000:
        needles.append(va.to_bytes(4, "little"))
    align = 8 if bits == 64 else 4
    sites: List[int] = []
    seen: Set[int] = set()
    for sec in getattr(img, "sections", []) or []:
        if getattr(sec, "executable", False) or not sec.data:
            continue
        data = sec.data
        for needle in needles:
            start = 0
            while len(sites) < limit:
                idx = data.find(needle, start)
                if idx < 0:
                    break
                if idx % align == 0:
                    loc = sec.addr + idx
                    if loc not in seen:
                        seen.add(loc)
                        sites.append(loc)
                start = idx + 1
    return sites


def _table_bases(img: Any, sites: List[int]) -> List[int]:
    """Row starts around a string pointer (id at -N, string at site)."""
    ps = _ptr_size(img)
    out: List[int] = []
    seen: Set[int] = set()
    for site in sites:
        for k in range(0, 5):
            base = site - k * ps
            if base <= 0 or base in seen:
                continue
            seen.add(base)
            out.append(base)
        aligned = site & ~0xF
        if aligned not in seen and aligned > 0:
            seen.add(aligned)
            out.append(aligned)
    return out[:40]


def _sibling_strings(img: Any, sites: List[int], *, limit: int = 16) -> List[Dict[str, Any]]:
    ps = _ptr_size(img)
    out: List[Dict[str, Any]] = []
    seen: Set[int] = set()
    for site in sites[:8]:
        for k in range(-6, 10):
            loc = site + k * ps
            pv = _read_ptr(img, loc)
            if not pv or pv in seen:
                continue
            text = _peek_cstring(img, pv)
            if not text:
                continue
            seen.add(pv)
            out.append({"addr": hex(pv), "preview": text[:80], "via": "pointer_table", "slot": hex(loc)})
            if len(out) >= limit:
                return out
    return out


def _rewind_cstring(data: bytes, off: int) -> Tuple[int, bytes]:
    return rewind_encoded_string(data, off, "utf8")


def _rewind_utf16le(data: bytes, off: int) -> Tuple[int, bytes]:
    return rewind_encoded_string(data, off, "utf16le")


def _count_data_refs(img: Any, va: int, *, cap: int = 8) -> int:
    bits = getattr(img, "bits", 64)
    needles = []
    if bits == 64:
        needles.append(va.to_bytes(8, "little"))
    if va < 0x100000000:
        needles.append(va.to_bytes(4, "little"))
    n = 0
    for sec in getattr(img, "sections", []) or []:
        if getattr(sec, "executable", False) or not sec.data:
            continue
        for needle in needles:
            start = 0
            data = sec.data
            while n < cap:
                idx = data.find(needle, start)
                if idx < 0:
                    break
                n += 1
                start = idx + 1
            if n >= cap:
                return n
    return n


def _rank_string(preview: str, query: str, data_refs: int, *, match_off: int = 0) -> int:
    pl = (preview or "").lower()
    ql = (query or "").lower()
    score = min(len(preview), 120)
    if ql and pl.startswith(ql):
        score += 80
    elif ql and ql in pl:
        score += 40
        score -= min(pl.find(ql), 40)
    else:
        score -= 50
    if " " in (query or ""):
        score += 30
    if data_refs:
        score += 50 + min(data_refs, 8) * 5
    if match_off > 48:
        score -= 70
    elif match_off > 16:
        score -= 20
    if preview.startswith("\t") or "\x0e" in preview or "TUiAction" in preview:
        score -= 15
    if looks_host_engine_string(preview):
        score -= 120
    return score


def _catalog_payload_blob(path: str, query: str) -> Dict[str, Any]:
    from argus.payload import scan_payload_strings, sniff_magic

    hits = scan_payload_strings(path, query, limit=_STRINGS_PER_MOD)
    magic = sniff_magic(path)
    kind = "archive" if magic in ("asar", "zip") else "text"
    for h in hits:
        h["data_refs"] = 0
        h["match_off"] = 0
    return {
        "path": path,
        "name": Path(path).name,
        "fmt": kind,
        "kind": kind,
        "arch": "",
        "string_hits": hits,
        "functions": [],
        "jump_count": 0,
        "ok": True,
        "_img": None,
    }


def _catalog_module(path: str, query: str) -> Dict[str, Any]:
    from argus.discover import is_binary_file

    if not is_binary_file(Path(path)):
        return _catalog_payload_blob(path, query)
    img = load_binary(path)
    q = (query or "").strip()
    hits: List[Dict[str, Any]] = []
    seen: Set[int] = set()
    if len(q) >= 3:
        encodings = query_string_needles(q)
        for sec in img.sections:
            if not sec.data or int(getattr(sec, "addr", 0) or 0) < 0x1000:
                continue
            data = sec.data
            for kind, needle in encodings:
                if len(hits) >= _STRINGS_PER_MOD:
                    break
                start = 0
                while len(hits) < _STRINGS_PER_MOD:
                    if kind == "utf8":
                        offs = _scan_section_ci(data[start:], needle)
                        if not offs:
                            break
                        idx = start + offs[0]
                    else:
                        idx = data.find(needle, start)
                        if idx < 0:
                            break
                    s, preview = rewind_encoded_string(data, idx, kind)
                    va = sec.addr + s
                    if va not in seen:
                        seen.add(va)
                        text = decode_encoded_preview(preview, kind)
                        if text:
                            refs = _count_data_refs(img, va)
                            penalty = 0 if kind == "utf8" else (5 if kind == "utf16le" else 8)
                            hits.append(
                                {
                                    "addr": hex(va),
                                    "preview": text[:96],
                                    "kind": kind,
                                    "data_refs": refs,
                                    "match_off": idx - s,
                                    "score": _rank_string(text, q, refs, match_off=idx - s) - penalty,
                                }
                            )
                    step = max(len(needle), 1)
                    start = idx + step
            if len(hits) >= _STRINGS_PER_MOD:
                break
    hits.sort(key=lambda h: int(h.get("score") or 0), reverse=True)
    return {
        "path": path,
        "name": Path(path).name,
        "fmt": getattr(img, "fmt", ""),
        "kind": _mod_kind(path, getattr(img, "fmt", "")),
        "arch": getattr(img, "arch", ""),
        "string_hits": hits[:_STRINGS_PER_MOD],
        "functions": [],
        "jump_count": 0,
        "ok": True,
        "_img": img,
    }


def _is_ret_insn(img: Any, va: int) -> bool:
    md = _cs(img)
    data = img.read_bytes(va, 8) or b""
    for insn in md.disasm(data, va):
        return insn.address == va and insn.mnemonic in ("ret", "retn", "retf")
    return False


def _last_ret_before(img: Any, xref: int, back: int) -> Optional[int]:
    data = img.read_bytes(xref - back, back) or b""
    pos = len(data)
    for _ in range(12):
        idx = data.rfind(b"\xc3", 0, pos)
        if idx < 0:
            return None
        va = xref - back + idx
        if _is_ret_insn(img, va):
            return va
        pos = idx
    return None


def _skip_pad(img: Any, va: int, *, cap: int = 24) -> int:
    b = img.read_bytes(va, cap) or b""
    n = 0
    while n < len(b) and b[n] in (0x00, 0x90, 0xCC):
        n += 1
    return va + n


def _next_ret_after(img: Any, xref: int, fwd: int) -> int:
    data = img.read_bytes(xref, fwd) or b""
    pos = 16
    md = _cs(img)
    while pos < len(data):
        idx = data.find(b"\xc3", pos)
        if idx < 0:
            break
        va = xref + idx
        chunk = data[idx : idx + 8]
        for insn in md.disasm(chunk, va):
            if insn.address == va and insn.mnemonic in ("ret", "retn", "retf"):
                return va + insn.size
            break
        pos = idx + 1
    return xref + fwd


def _xref_window(img: Any, xaddr: int) -> Tuple[int, int]:
    cov = function_covering(img, xaddr)
    # eh_frame on stripped/FPC binaries often yields a megabyte-wide "function".
    # Only trust a covering if it is a compact real proc.
    if cov and 32 <= (cov.end - cov.start) <= 0x800:
        return cov.start, cov.end
    lo_ret = _last_ret_before(img, xaddr, _WINDOW_BACK)
    lo = _skip_pad(img, lo_ret + 1) if lo_ret is not None else xaddr - _WINDOW_BACK
    hi = _next_ret_after(img, xaddr, _WINDOW_FWD)
    if hi <= lo + 32:
        hi = lo + min(_WINDOW_FWD, _MAX_FN_BYTES)
    return lo, hi


def _is_plt_or_import(img: Any, va: int) -> bool:
    imports = getattr(img, "imports", {}) or {}
    if va in imports:
        return True
    sec = _section_at(img, va)
    name = (getattr(sec, "name", None) or "").lower()
    if ".plt" in name or name in (".idata", "extern", ".extern"):
        return True
    return False


def list_rel32_callers(img: Any, func_va: int, *, limit: int = _CALLERS_CAP) -> List[int]:
    """Sites of E8/E9 rel32 to func_va across executable sections."""
    hits: List[int] = []
    seen: Set[int] = set()
    try:
        import numpy as np
    except ImportError:
        return hits
    for sec in getattr(img, "sections", []) or []:
        if not getattr(sec, "executable", False) or not sec.data:
            continue
        data = sec.data
        base = sec.addr
        C = func_va - base - 4
        for shift in range(4):
            chunk_len = (len(data) - shift) // 4 * 4
            if chunk_len <= 0:
                continue
            arr = np.frombuffer(data[shift : shift + chunk_len], dtype=np.int32)
            offsets = (np.arange(len(arr), dtype=np.int64) * 4 + shift)
            for h in np.flatnonzero(arr.astype(np.int64) + offsets == C):
                idx = int(offsets[h])
                if idx > 0 and data[idx - 1] in (0xE8, 0xE9):
                    addr = base + idx - 1
                    if addr not in seen:
                        seen.add(addr)
                        hits.append(addr)
                    if len(hits) >= limit:
                        return hits
    return hits


def _covered(ranges: List[Tuple[int, int]], addr: int) -> bool:
    return any(lo <= addr < hi for lo, hi in ranges)


def _walk_string(img: Any, string_va: int) -> Dict[str, Any]:
    from argus.find_slice import _find_cstring_vas

    preview = _peek_cstring(img, string_va) or ""
    sites = _pointer_sites(img, string_va)
    bases = _table_bases(img, sites)
    siblings = _sibling_strings(img, sites)
    sib_vas = []
    for s in siblings:
        try:
            sib_vas.append(int(s["addr"], 0))
        except (TypeError, ValueError, KeyError):
            continue
    xref_targets = list(dict.fromkeys([string_va] + bases + sib_vas))[:40]
    xref_map = find_string_xrefs_multi(img, xref_targets, max_per_target=6) if xref_targets else {}

    heap: List[Tuple[int, int, int, str, int]] = []
    seq = 0
    seen_xaddr: Set[int] = set()
    queued: Set[int] = set()
    seen_fn: Set[int] = set()
    ranges: List[Tuple[int, int]] = []
    functions: List[Dict[str, Any]] = []
    xref_rows: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    caller_map: Dict[int, List[int]] = {}
    seen_str: Set[int] = {string_va}
    caller_cache: Dict[int, List[int]] = {}

    def callers_of(va: int) -> List[int]:
        if va not in caller_cache:
            caller_cache[va] = list_rel32_callers(img, va, limit=_CALLERS_CAP)
        return caller_cache[va]

    def push(xaddr: int, via: str, depth: int, prio: int) -> None:
        nonlocal seq
        if xaddr <= 0 or depth > _MAX_GRAPH_DEPTH:
            return
        key = xaddr & ~1
        if key in queued or key in seen_xaddr:
            return
        queued.add(key)
        heapq.heappush(heap, (prio, seq, xaddr, via, depth))
        seq += 1

    def ingest_xrefs(xmap: Dict[int, List[Dict[str, Any]]], via: str, depth: int, prio: int) -> None:
        last = None
        for tva, xrs in xmap.items():
            for xr in xrs:
                try:
                    xaddr = int(xr["addr"], 0)
                except (TypeError, ValueError):
                    continue
                if last is not None and abs(xaddr - last) == 1:
                    continue
                last = xaddr
                xref_rows.append(
                    {
                        "addr": hex(xaddr),
                        "kind": xr.get("kind"),
                        "mnemonic": xr.get("mnemonic"),
                        "target": hex(tva),
                        "via": via if tva != string_va else "string",
                    }
                )
                push(xaddr, via if tva != string_va else "string", depth, prio)

    ingest_xrefs(xref_map, "pointer_table", 0, 0)

    while heap and len(functions) < _MAX_GRAPH_FNS:
        _prio, _seq, xaddr, via, depth = heapq.heappop(heap)
        key = xaddr & ~1
        if key in seen_xaddr:
            continue
        seen_xaddr.add(key)
        if _covered(ranges, xaddr) and via not in ("string", "pointer_table", "string_copy"):
            continue
        lo, hi = _xref_window(img, xaddr)
        if lo in seen_fn:
            continue
        seen_fn.add(lo)
        rec = _scan_function(img, lo, hi)
        rec["via"] = via
        rec["depth"] = depth
        rec["string_xrefs"] = [
            r["addr"] for r in xref_rows if lo <= int(r["addr"], 0) < hi
        ][:8]
        sites_here = callers_of(lo)
        rec["callers"] = [hex(c) for c in sites_here[:_CALLERS_CAP]]
        rec["caller_count"] = len(sites_here)
        caller_map[lo] = sites_here
        ranges.append((lo, hi))
        functions.append(rec)

        extra_vas: List[int] = []
        if depth == 0:
            for rs in rec.get("rip_strings") or []:
                text = rs.get("preview") or ""
                if len(text) < 16 or ("@" in text and " " not in text[:24]):
                    continue
                needle = text[:28].split("\n")[0].encode("utf-8", errors="replace")
                if len(needle) < 16:
                    continue
                for cva, _prev in _find_cstring_vas(img, needle, limit=4):
                    if cva in seen_str:
                        continue
                    seen_str.add(cva)
                    extra_vas.append(cva)
                    siblings.append(
                        {
                            "addr": hex(cva),
                            "preview": (_peek_cstring(img, cva) or text)[:80],
                            "via": "string_copy",
                        }
                    )
            if extra_vas:
                extra_map = find_string_xrefs_multi(img, extra_vas, max_per_target=4)
                ingest_xrefs(extra_map, "string_copy", 1, 0)

        tiny = (hi - lo) < 0xC0
        if (
            via in ("string_copy", "string", "callee", "next_proc")
            and (via != "next_proc" or tiny)
            and depth <= 1
            and (tiny or rec.get("jumps") or rec.get("rip_strings") or rec.get("callers"))
        ):
            nxt = _skip_pad(img, hi)
            if nxt not in seen_fn and _is_exec_va(img, nxt):
                push(nxt, "next_proc", depth, 1)

        # FPC: address-taken nested proc (only from seeds — xref scan is expensive)
        if depth == 0:
            lea_map = find_string_xrefs_multi(img, [lo], max_per_target=6)
            for xr in lea_map.get(lo) or []:
                try:
                    a = int(xr["addr"], 0)
                except (TypeError, ValueError):
                    continue
                edges.append({"from": hex(a), "to": hex(lo), "kind": "fn_ptr"})
                push(a, "fn_ptr", depth + 1, 3)

        for fp in rec.get("fn_ptrs") or []:
            try:
                t = int(fp, 0)
            except (TypeError, ValueError):
                continue
            if not _is_plt_or_import(img, t):
                edges.append({"from": rec["fn"], "to": hex(t), "kind": "fn_ptr"})
                push(t, "fn_ptr", depth + 1, 3)

        for c in rec.get("calls") or []:
            raw = c.get("target")
            if not raw:
                continue
            try:
                tgt = int(raw, 0)
            except (TypeError, ValueError):
                continue
            if _is_plt_or_import(img, tgt):
                edges.append({"from": c.get("addr"), "to": hex(tgt), "kind": "import"})
                continue
            fan = callers_of(tgt)
            n = len(fan)
            edges.append({"from": c.get("addr"), "to": hex(tgt), "kind": "call", "fanin": n})
            if n > _FANIN_SCAN:
                continue
            caller_map.setdefault(tgt, fan)
            if depth < _MAX_GRAPH_DEPTH:
                push(tgt, "callee", depth + 1, 4)

        if depth < _MAX_GRAPH_DEPTH:
            n_here = len(sites_here)
            cp = 1 if 2 <= n_here <= 16 else 2
            for cs in sites_here:
                if not _covered(ranges, cs):
                    push(cs, "caller", depth + 1, cp)

    jump_n = sum(len(fn.get("jumps") or []) for fn in functions)
    callers_out: List[Dict[str, Any]] = []
    for fn_va, csites in sorted(
        caller_map.items(), key=lambda kv: (-int(kv[0] in seen_fn), -len(kv[1]))
    ):
        if not csites:
            continue
        if len(csites) > _FANIN_SCAN and fn_va not in seen_fn:
            continue
        callers_out.append(
            {
                "fn": hex(fn_va),
                "count": len(csites),
                "sites": [hex(s) for s in csites[:_CALLERS_CAP]],
            }
        )
        if len(callers_out) >= 16:
            break

    string_hits = [
        {
            "addr": hex(string_va),
            "preview": preview[:96],
            "kind": "chosen",
            "data_refs": len(sites),
            "pointer_sites": [hex(s) for s in sites[:12]],
        }
    ]
    seen_hit = {hex(string_va)}
    for sib in siblings:
        a = sib.get("addr")
        if not a or a in seen_hit:
            continue
        seen_hit.add(a)
        string_hits.append(sib)

    return {
        "string_hits": string_hits[:24],
        "functions": functions,
        "jump_count": jump_n,
        "xrefs": xref_rows[:32],
        "pointer_sites": [hex(s) for s in sites[:12]],
        "table_bases": [hex(b) for b in bases[:16]],
        "callers": callers_out,
        "edges": edges[:40],
    }


def _parse_addr(raw: Union[str, int, None]) -> Optional[int]:
    if raw is None or raw == "":
        return None
    if isinstance(raw, int):
        return raw
    s = str(raw).strip()
    if ":" in s and not s.startswith("0x") and s[0] not in "0123456789":
        s = s.split(":", 1)[1]
    try:
        return int(s, 0)
    except (TypeError, ValueError):
        return None


def _flatten_jumps(modules: List[Dict[str, Any]], *, cap: int = 80) -> List[Dict[str, Any]]:
    per_mod: List[List[Dict[str, Any]]] = []
    for mod in modules:
        if not mod.get("ok"):
            continue
        mname = mod.get("name")
        bucket: List[Dict[str, Any]] = []
        for fn in mod.get("functions") or []:
            for j in fn.get("jumps") or []:
                jj = dict(j)
                jj["module"] = mname
                jj["fn"] = fn.get("fn")
                jj["fn_name"] = fn.get("name")
                bucket.append(jj)
        if bucket:
            per_mod.append(bucket)
    jumps: List[Dict[str, Any]] = []
    idx = 0
    while len(jumps) < cap and per_mod:
        progressed = False
        for bucket in per_mod:
            if idx < len(bucket):
                jumps.append(bucket[idx])
                progressed = True
                if len(jumps) >= cap:
                    break
        if not progressed:
            break
        idx += 1
    return jumps


def build_atlas(
    primary: str,
    query: str = "",
    *,
    string_addr: Union[str, int, None] = None,
    module: Optional[str] = None,
    max_modules: int = 8,
) -> Dict[str, Any]:
    """Phase 1: query → string catalog. Phase 2: string_addr → jump/register map."""
    q = (query or "").strip()
    sva = _parse_addr(string_addr)
    if sva is None and not q:
        return {
            "ok": False,
            "phase": "strings",
            "summary": "atlas: pass query= to search strings, then string_addr= to map jumps",
            "modules": [],
            "hops": [],
            "jumps": [],
            "strings": [],
        }

    paths, hops = _collect_modules(primary, q, max_modules=max_modules)
    if module:
        want = str(module)
        paths = [p for p in paths if Path(p).name == want or p == want] or paths

    if sva is None:
        return _phase_strings(primary, q, paths, hops)

    return _phase_walk(primary, q, sva, paths, hops)


def _phase_strings(primary: str, query: str, paths: List[str], hops: List[Dict[str, Any]]) -> Dict[str, Any]:
    modules: List[Dict[str, Any]] = []
    catalog: List[Dict[str, Any]] = []
    for p in paths:
        try:
            rec = _catalog_module(p, query)
        except Exception as exc:
            modules.append({"path": p, "name": Path(p).name, "ok": False, "error": str(exc)})
            continue
        rec.pop("_img", None)
        modules.append(rec)
        for h in rec.get("string_hits") or []:
            row = dict(h)
            row["module"] = rec.get("name")
            row["path"] = rec.get("path")
            catalog.append(row)
    catalog.sort(key=lambda h: int(h.get("score") or 0), reverse=True)
    catalog = catalog[:_STRINGS_GLOBAL]
    top = catalog[0] if catalog else None
    observations = [
        f"phase=strings modules={len(modules)} hits={len(catalog)} hops={len(hops)}",
    ]
    for m in modules:
        if not m.get("ok"):
            observations.append(f"fail {m.get('name')}: {m.get('error')}")
            continue
        n = len(m.get("string_hits") or [])
        if n:
            observations.append(f"{m.get('kind')}:{m.get('name')} strings={n}")
    for h in hops:
        observations.append(f"hop {h.get('via')}: {h.get('from')} -> {h.get('to')}")
    suggested = (top or {}).get("addr")
    summary = (
        f"atlas strings query={query[:60]!r}: {len(catalog)} hits in "
        f"{sum(1 for m in modules if m.get('string_hits'))} modules"
    )
    return {
        "ok": True,
        "phase": "strings",
        "summary": summary,
        "observations": observations[:24],
        "query": query[:200],
        "primary": primary,
        "strings": catalog,
        "suggested_string_addr": suggested,
        "modules": [_slim_module(m, strings_only=True) for m in modules],
        "hops": hops,
        "jumps": [],
        "next_hint": (
            "Pick one strings[].addr (prefer high score / data_refs) and call "
            "argus_atlas(string_addr=<addr>) for the jump map, then "
            "argus_diagnose_failure(error_text=<verbatim strings[].preview>). "
            "Map only — do not patch from this tool."
        ),
    }


def _phase_walk(
    primary: str,
    query: str,
    string_va: int,
    paths: List[str],
    hops: List[Dict[str, Any]],
) -> Dict[str, Any]:
    modules: List[Dict[str, Any]] = []
    owners: List[str] = []
    for p in paths:
        try:
            img = load_binary(p)
        except Exception as exc:
            modules.append({"path": p, "name": Path(p).name, "ok": False, "error": str(exc)})
            continue
        if not _va_in_image(img, string_va):
            continue
        owners.append(p)
        walked = _walk_string(img, string_va)
        modules.append(
            {
                "path": p,
                "name": Path(p).name,
                "fmt": getattr(img, "fmt", ""),
                "kind": _mod_kind(p, getattr(img, "fmt", "")),
                "arch": getattr(img, "arch", ""),
                "ok": True,
                **walked,
            }
        )

    if not owners:
        return {
            "ok": False,
            "phase": "map",
            "summary": f"atlas: string_addr={hex(string_va)} not mapped in scanned modules",
            "query": query[:200],
            "string_addr": hex(string_va),
            "primary": primary,
            "modules": [],
            "hops": hops,
            "jumps": [],
            "strings": [],
            "next_hint": "Re-run with query= to list valid string addresses, or pass module= filename.",
        }

    jumps = _flatten_jumps(modules, cap=100)
    all_callers: List[Dict[str, Any]] = []
    for m in modules:
        all_callers.extend(m.get("callers") or [])
    observations = [
        f"phase=map string_addr={hex(string_va)} owners={len(owners)} jumps={len(jumps)} hops={len(hops)}",
    ]
    for m in modules:
        if not m.get("ok"):
            observations.append(f"fail {m.get('name')}: {m.get('error')}")
            continue
        observations.append(
            f"{m.get('kind')}:{m.get('name')} ptrs={len(m.get('pointer_sites') or [])} "
            f"xrefs={len(m.get('xrefs') or [])} fns={len(m.get('functions') or [])} "
            f"jumps={m.get('jump_count')} caller_sets={len(m.get('callers') or [])}"
        )
        for xr in (m.get("xrefs") or [])[:5]:
            observations.append(f"xref {xr.get('via')} {xr.get('addr')} -> {xr.get('target')}")
        for cl in (m.get("callers") or [])[:4]:
            observations.append(f"callers {cl.get('fn')} n={cl.get('count')} e.g. {(cl.get('sites') or [])[:6]}")
        for rec in (m.get("functions") or [])[:8]:
            observations.append(
                f"fn {rec.get('fn')} via={rec.get('via')} depth={rec.get('depth')} "
                f"jumps={len(rec.get('jumps') or [])} callers={rec.get('caller_count')}"
            )
        interesting = []
        for rec in m.get("functions") or []:
            for st in rec.get("imm_stores") or []:
                imm = int(st.get("imm") or 0)
                if 2 <= imm <= 64 and imm != 11:
                    interesting.append(st)
        for st in interesting[:8]:
            observations.append(f"imm {st.get('addr')} {st.get('op')}")
    for h in hops:
        observations.append(f"hop {h.get('via')}: {h.get('from')} -> {h.get('to')}")

    names = [m.get("name") for m in modules if m.get("ok")]
    summary = (
        f"atlas map string_addr={hex(string_va)}: {len(jumps)} jumps in "
        f"{', '.join(names[:6]) or 'none'}"
    )
    strings = []
    for m in modules:
        for h in m.get("string_hits") or []:
            row = dict(h)
            row.setdefault("module", m.get("name"))
            strings.append(row)
    return {
        "ok": True,
        "phase": "map",
        "summary": summary,
        "observations": observations[:36],
        "query": query[:200],
        "string_addr": hex(string_va),
        "primary": primary,
        "strings": strings[:24],
        "callers": all_callers[:16],
        "modules": [_slim_module(m) for m in modules],
        "hops": hops,
        "jumps": jumps,
        "next_hint": (
            "Map only — do not apply patches from this tool. "
            "Next: argus_diagnose_failure(error_text=<verbatim string preview or query>) "
            "then argus_apply_plan from corrective_patch / suggested_batches[0]. "
            "Do not argus_patch these jumps."
        ),
    }


def _slim_module(m: Dict[str, Any], *, strings_only: bool = False) -> Dict[str, Any]:
    if not m.get("ok"):
        return m
    if strings_only:
        return {
            "path": m.get("path"),
            "name": m.get("name"),
            "fmt": m.get("fmt"),
            "kind": m.get("kind"),
            "arch": m.get("arch"),
            "string_hits": (m.get("string_hits") or [])[:12],
            "ok": True,
        }
    fns = []
    for fn in (m.get("functions") or [])[:_MAX_FNS_PER_MOD]:
        fns.append(
            {
                "fn": fn.get("fn"),
                "name": fn.get("name"),
                "via": fn.get("via"),
                "depth": fn.get("depth"),
                "size": fn.get("size"),
                "caller_count": fn.get("caller_count"),
                "callers": (fn.get("callers") or [])[:12],
                "string_xrefs": fn.get("string_xrefs"),
                "jumps": (fn.get("jumps") or [])[:12],
                "indirect": (fn.get("indirect") or [])[:8],
                "imm_stores": (fn.get("imm_stores") or [])[:8],
                "calls_sample": (fn.get("calls") or [])[:8],
                "rip_strings": (fn.get("rip_strings") or [])[:6],
            }
        )
    return {
        "path": m.get("path"),
        "name": m.get("name"),
        "fmt": m.get("fmt"),
        "kind": m.get("kind"),
        "arch": m.get("arch"),
        "string_hits": (m.get("string_hits") or [])[:16],
        "pointer_sites": m.get("pointer_sites") or [],
        "xrefs": (m.get("xrefs") or [])[:16],
        "callers": (m.get("callers") or [])[:12],
        "edges": (m.get("edges") or [])[:24],
        "functions": fns,
        "jump_count": m.get("jump_count"),
        "ok": True,
    }
