from __future__ import annotations

"""Keyword / string / symbol find + xrefs for agent grounding."""

import os
import re
from typing import Any, Dict, List, Optional, Tuple

from argus.binary import load_binary

# Universal keywords (query-driven; empty default to keep engine generic)
DEFAULT_KEYWORDS: List[str] = []

# Soft gate-name filter — structural patterns only (generic predicate checks)
_GATE_NAME_RE = re.compile(
    r"(?:^|[^A-Za-z])(Is|Check|Verify|Validate|Has|Can|Should|Auth)"
    r"(?=[A-Z0-9_])[A-Za-z0-9_]*"
)
# Unmangled C-style API: IsValid, CheckAccess, VerifySignature, etc.
_GATE_SHORT_RE = re.compile(
    r"^(Is|Check|Verify|Validate|Has|Can|Should|Auth)[A-Za-z0-9_]*$"
)
# Mangled C++ method leaf
_GATE_MANGLED_BOOL_RE = re.compile(
    r"_ZN\d+\w+\d+(is|check|verify|validate|has|can|should|auth)[A-Za-z0-9_]*Ev$",
    re.IGNORECASE,
)
_GATE_NOISE_RE = re.compile(
    r"(?i)(\.cold$|_ZTV|_ZTI|_ZTS|qt_meta|nlohmann|basic_json|TypeAndForceComplete|"
    r"unordered_map|Invoker|thread11_State|zmq::|pipe_t|"
    r"mbedtls|nghttp|blowfish|pubkey|openssl|gnutls|libsodium|sqlite)"
)
_GATE_UI_RE = re.compile(r"(?i)(Callback|Widget|Dialog|Button|clicked|editingFinished)")


def _gate_score(name: str, is_function: bool) -> int:
    """Higher = better license/auth gate candidate for ret_imm."""
    if not name or _GATE_NOISE_RE.search(name):
        return -1
    if _GATE_UI_RE.search(name):
        return -1
    score = 0
    if is_function:
        score += 20
    if _GATE_SHORT_RE.match(name):
        score += 100
        if re.search(r"(?i)(Genuine|Valid|Licen)", name):
            score += 30
    elif _GATE_NAME_RE.search(name) and not name.startswith("_Z"):
        score += 60
    elif _GATE_MANGLED_BOOL_RE.search(name):
        score += 80
    elif _GATE_NAME_RE.search(name):
        score += 25
    else:
        return -1
    # Get* rarely unlocks — demote (keep Is/Check/Verify/Validate / isActivated)
    if re.match(r"(?i)^Get", name):
        score -= 55
    # Prefer short names; heavily demote huge mangled templates
    score -= min(len(name) // 8, 40)
    if name.startswith("_Z") and len(name) > 80:
        score -= 50
    return score


def _suggested_ret_value(name: str) -> int:
    """Heuristic only: Is/Check/Verify/Validate → 0 (OK); *isActivated*/Has* bool → 1."""
    if _GATE_MANGLED_BOOL_RE.search(name):
        return 1
    if re.match(r"(?i)^Has", name):
        return 1
    if re.match(r"(?i)^(Is|Check|Verify|Validate)", name):
        return 0
    return 0


def _query_intent(query: Optional[str]) -> str:
    """Return 'ui' | 'gate_transform' | 'mixed' for next_hint tone (no vendor logic)."""
    q = (query or "").lower()
    gate_kw = (
        "unlock",
        "bypass",
        "ret_imm",
        "stub",
        "убери провер",
        "отключ",
        "всегда актив",
        "skip check",
        "force success",
        "license check",
        "проверк",
    )
    ui_kw = (
        "title",
        "заголов",
        "текст",
        "string",
        "replace",
        "days left",
        "дней",
        "бесконеч",
        "надпис",
        "label",
        "heading",
        "писало",
        "напиши",
        "infinity",
        "∞",
    )
    wants_gate = any(k in q for k in gate_kw)
    wants_ui = any(k in q for k in ui_kw)
    if wants_gate and wants_ui:
        return "mixed"
    if wants_gate:
        return "gate_transform"
    if wants_ui:
        return "ui"
    if q and not any(k in q for k in ("license", "licence", "trial", "activat", "unlock")):
        return "ui"
    return "gate_transform" if any(k in q for k in ("license", "licence", "trial", "activat")) else "mixed"


def _collect_gate_symbols(img, query: Optional[str] = None, limit: int = 16) -> List[Dict[str, Any]]:
    """Rank structural license/auth gate symbols (no vendor name list)."""
    del query  # reserved for future query-token boosts
    scored: List[Tuple[int, Dict[str, Any]]] = []
    for s in img.symbols.values():
        if not s.name or s.is_import or not s.addr:
            continue
        sc = _gate_score(s.name, bool(s.is_function))
        if sc < 50:
            continue
        item = {
            "name": s.name,
            "addr": hex(s.addr),
            "score": sc,
            "ret_value": _suggested_ret_value(s.name),
        }
        scored.append((sc, item))
    scored.sort(key=lambda x: (-x[0], len(x[1]["name"])))
    out: List[Dict[str, Any]] = []
    seen = set()
    for _, item in scored:
        if item["name"] in seen:
            continue
        seen.add(item["name"])
        out.append(item)
        if len(out) >= limit:
            break
    return out


def _nearby_fn(img, addr: int) -> Optional[str]:
    """Prefer recovered function label; fall back to nearest named symbol."""
    try:
        from argus.disasm.recovery import function_covering

        b = function_covering(img, addr)
        if b:
            # If a real symbol starts here, use its name
            for s in img.symbols.values():
                if s.is_function and not s.is_import and s.addr == b.start and s.name:
                    return s.name
            return b.name
    except Exception:
        pass
    best = None
    best_addr = -1
    for s in img.symbols.values():
        if not s.is_function or s.is_import or not s.addr:
            continue
        if s.addr <= addr and s.addr >= best_addr:
            best_addr = s.addr
            best = s.name
    return best


def _scan_section_ci(data: bytes, needle: bytes) -> List[int]:
    if not needle or not data:
        return []
    low = data.lower()
    n = needle.lower()
    out: List[int] = []
    start = 0
    while True:
        idx = low.find(n, start)
        if idx < 0:
            break
        out.append(idx)
        start = idx + 1
    return out


def _junk_preview(preview: str) -> bool:
    p = preview.lower()
    if "std::" in p or "gnu_cxx" in p or "qstring" in p and "license" not in p:
        return True
    if ".cold" in p or "serializer" in p or "qcbor" in p:
        return True
    if preview.count("_") > 6 and "license" not in p:
        return True
    return False


def _score_hit(preview: str, needle: str, kind: str) -> int:
    score = len(needle) * 10
    pl = preview.lower()
    nl = needle.lower()
    if pl.startswith(nl) or pl == nl:
        score += 50
    if " " in needle:
        score += 40  # multi-word phrase
    if kind == "string":
        score += 20
    if _junk_preview(preview):
        score -= 100
    return score


def _exec_scan_bytes(img) -> int:
    total = sum(len(s.data) for s in img.sections if s.executable and s.data)
    default_cap = min(max(total, 8_000_000), 80_000_000)
    raw = os.environ.get("ARGUS_XREF_SCAN_MAX", "").strip()
    if raw:
        try:
            return min(int(raw), default_cap)
        except ValueError:
            pass
    return default_cap


def find_rodata_vicinity_xrefs(
    img,
    target: int,
    *,
    radius: int = 768,
    max_hits: int = 8,
) -> List[Dict[str, Any]]:
    """
    Stripped/Delphi binaries often reference the middle of a rodata blob, not the
    string start VA. Scan executable sections for 32/64-bit pointers into [target±radius].
    """
    if img.arch not in ("x86_64", "x86") or not target:
        return []
    lo, hi = target - radius, target + radius
    out: List[Dict[str, Any]] = []
    seen: set[int] = set()

    try:
        import numpy as np
        has_numpy = True
    except ImportError:
        has_numpy = False

    for sec in img.sections:
        if not sec.executable or not sec.data:
            continue
        data = sec.data
        if has_numpy:
            align_shifts = 8 if img.bits == 64 else 4
            dtype = np.uint64 if img.bits == 64 else np.uint32
            for shift in range(align_shifts):
                chunk_len = (len(data) - shift) // align_shifts * align_shifts
                if chunk_len <= 0:
                    continue
                arr = np.frombuffer(data[shift : shift + chunk_len], dtype=dtype)
                matches = np.flatnonzero((arr >= lo) & (arr <= hi))
                for m in matches:
                    idx = int(m) * align_shifts + shift
                    site = sec.addr + idx
                    if site in seen:
                        continue
                    seen.add(site)
                    val = int(arr[m])
                    out.append(
                        {
                            "addr": hex(site),
                            "mnemonic": "rodata_vicinity",
                            "op_str": hex(val),
                            "nearby_fn": _nearby_fn(img, site),
                            "kind": "vicinity",
                            "target_ref": hex(val),
                        }
                    )
                    if len(out) >= max_hits:
                        return out
        else:
            import struct
            for i in range(0, len(data) - 3):
                for fmt in ("<I", "<Q") if img.bits == 64 else ("<I",):
                    if fmt == "<Q" and i + 8 > len(data):
                        continue
                    if fmt == "<I" and i + 4 > len(data):
                        continue
                    try:
                        v = struct.unpack_from(fmt, data, i)[0]
                    except struct.error:
                        continue
                    if not (lo <= v <= hi):
                        continue
                    site = sec.addr + i
                    if site in seen:
                        continue
                    seen.add(site)
                    out.append(
                        {
                            "addr": hex(site),
                            "mnemonic": "rodata_vicinity",
                            "op_str": hex(v),
                            "nearby_fn": _nearby_fn(img, site),
                            "kind": "vicinity",
                            "target_ref": hex(v),
                        }
                    )
                    if len(out) >= max_hits:
                        return out
    return out


def find_string_xrefs_multi(
    img,
    targets: List[int],
    *,
    max_per_target: int = 8,
    chunk_size: int = 2_000_000,
    max_scan_bytes: int = 8_000_000,
) -> Dict[int, List[Dict[str, Any]]]:
    """Chunked Capstone pass + absolute imm/embedded-VA scan for string xrefs."""
    import capstone as cs
    from capstone.x86 import X86_REG_RIP

    want = {t: [] for t in targets if t}
    if not want or img.arch not in ("x86_64", "x86"):
        return want

    if max_scan_bytes == 8_000_000:
        max_scan_bytes = _exec_scan_bytes(img)
    for sec in img.sections:
        if not sec.executable or not sec.data:
            continue
        data = sec.data
        for t in list(want.keys()):
            if len(want[t]) >= max_per_target:
                continue
            # 64-bit and 32-bit encodings
            needles = [t.to_bytes(8, "little")]
            if t < 0x100000000:
                needles.append(t.to_bytes(4, "little"))
            for needle in needles:
                start = 0
                while len(want[t]) < max_per_target:
                    idx = data.find(needle, start)
                    if idx < 0:
                        break
                    # avoid matching inside unrelated data: prefer insn-aligned-ish
                    addr = sec.addr + idx
                    hit_addr = addr
                    want[t].append(
                        {
                            "addr": hex(hit_addr),
                            "mnemonic": "imm_embed",
                            "op_str": hex(t),
                            "nearby_fn": _nearby_fn(img, hit_addr),
                            "kind": "absolute",
                        }
                    )
                    start = idx + 1

    remaining = {t for t, bucket in want.items() if len(bucket) < max_per_target}
    if not remaining:
        return want

    mode = cs.CS_MODE_64 if img.bits == 64 else cs.CS_MODE_32
    md_fast = cs.Cs(cs.CS_ARCH_X86, mode)
    md_fast.detail = False
    md_detail = cs.Cs(cs.CS_ARCH_X86, mode)
    md_detail.detail = True

    # Vectorized NumPy fast path for x86_64 RIP-relative displacements (runs in milliseconds)
    if img.arch == "x86_64":
        try:
            import numpy as np
            has_np = True
        except ImportError:
            has_np = False

        if has_np:
            for sec in img.sections:
                if not remaining:
                    break
                if not sec.executable or not sec.data:
                    continue
                data = sec.data
                base = sec.addr

                for t in list(remaining):
                    if len(want[t]) >= max_per_target:
                        remaining.discard(t)
                        continue
                    found_sites: List[int] = []
                    for trailing in (0, 1, 2, 4):
                        if len(want[t]) >= max_per_target:
                            break
                        for shift in range(4):
                            chunk_len = (len(data) - shift) // 4 * 4
                            if chunk_len <= 0:
                                continue
                            arr = np.frombuffer(data[shift : shift + chunk_len], dtype=np.int32)
                            offsets = (np.arange(len(arr), dtype=np.int64) * 4 + shift).astype(np.int64)
                            C = t - base - 4 - trailing
                            hits = np.flatnonzero((arr.astype(np.int64) + offsets) == C)
                            for h in hits:
                                found_sites.append(int(offsets[h]))

                    for disp_off in found_sites:
                        if len(want[t]) >= max_per_target:
                            remaining.discard(t)
                            break
                        for back in (1, 2, 3, 4):
                            insn_off = disp_off - back
                            if insn_off < 0:
                                continue
                            insn_va = base + insn_off
                            win = data[insn_off : min(len(data), insn_off + 15)]
                            for insn in md_detail.disasm(win, insn_va):
                                for op in insn.operands:
                                    if op.type == cs.CS_OP_MEM and op.mem.base == X86_REG_RIP:
                                        ea = insn.address + insn.size + op.mem.disp
                                        if ea == t:
                                            hit_addr = hex(insn.address)
                                            if not any(b.get("addr") == hit_addr for b in want[t]):
                                                want[t].append(
                                                    {
                                                        "addr": hit_addr,
                                                        "mnemonic": insn.mnemonic,
                                                        "op_str": insn.op_str,
                                                        "nearby_fn": _nearby_fn(img, insn.address),
                                                        "kind": "rip",
                                                    }
                                                )
                                                if len(want[t]) >= max_per_target:
                                                    remaining.discard(t)
                                            break
                                break
                            if t not in remaining:
                                break

    remaining = {t for t, bucket in want.items() if len(bucket) < max_per_target}
    if not remaining or (has_np and img.arch == "x86_64"):
        # Vicinity fallback
        for t in list(want.keys()):
            if len(want[t]) >= max_per_target:
                continue
            for xr in find_rodata_vicinity_xrefs(img, t, max_hits=max_per_target - len(want[t])):
                if any(b.get("addr") == xr.get("addr") for b in want[t]):
                    continue
                want[t].append(xr)
        return want

    scanned = 0
    for sec in img.sections:
        if not remaining or scanned >= max_scan_bytes:
            break
        if not sec.executable or not sec.data:
            continue
        data = sec.data
        offset = 0
        while offset < len(data) and remaining and scanned < max_scan_bytes:
            take = min(chunk_size, max_scan_bytes - scanned, len(data) - offset)
            chunk = data[offset : offset + take + 16]
            base = sec.addr + offset
            try:
                for insn in md_fast.disasm(chunk[:take], base):
                    if not remaining:
                        break
                    op_str = insn.op_str or ""
                    has_rip = "rip" in op_str.lower()
                    has_imm = "0x" in op_str or any(c.isdigit() for c in op_str)
                    if not has_rip and not has_imm:
                        continue

                    # Detailed inspection only for candidate instructions
                    det_insns = list(md_detail.disasm(insn.bytes, insn.address))
                    if not det_insns:
                        continue
                    d_insn = det_insns[0]
                    hit_t = None
                    for op in d_insn.operands:
                        ea = None
                        if op.type == cs.CS_OP_MEM and op.mem.base == X86_REG_RIP:
                            ea = d_insn.address + d_insn.size + op.mem.disp
                        elif op.type == cs.CS_OP_IMM and op.imm in remaining:
                            ea = int(op.imm)
                        if ea in remaining:
                            hit_t = ea
                            break
                    if hit_t is None:
                        continue
                    bucket = want[hit_t]
                    # dedupe near same site
                    if any(b.get("addr") == hex(d_insn.address) for b in bucket):
                        continue
                    if len(bucket) >= max_per_target:
                        remaining.discard(hit_t)
                        continue
                    bucket.append(
                        {
                            "addr": hex(d_insn.address),
                            "mnemonic": d_insn.mnemonic,
                            "op_str": d_insn.op_str,
                            "nearby_fn": _nearby_fn(img, d_insn.address),
                            "kind": "rip" if has_rip else "imm",
                        }
                    )
                    if len(bucket) >= max_per_target:
                        remaining.discard(hit_t)
            except Exception:
                pass
            offset += take
            scanned += take

    # Vicinity fallback: Delphi/commercial blobs reference mid-rodata, not string start
    for t in list(want.keys()):
        if len(want[t]) >= max_per_target:
            continue
        for xr in find_rodata_vicinity_xrefs(img, t, max_hits=max_per_target - len(want[t])):
            if any(b.get("addr") == xr.get("addr") for b in want[t]):
                continue
            want[t].append(xr)
    return want


def find_string_xrefs(img, target: int, *, max_hits: int = 24) -> List[Dict[str, Any]]:
    return find_string_xrefs_multi(img, [target], max_per_target=max_hits).get(target, [])


def _is_safe_boolean_validator(img: Any, ct_val: int) -> bool:
    """Verify that ct_val is a function returning boolean in eax/al,
    NOT a jump table, dispatch thunk, or void setup function."""
    try:
        from argus.disasm.recovery import function_covering
        import capstone as cs

        vbound = function_covering(img, ct_val)
        if not vbound:
            return False
        # Must be called at or near the function entry point
        if abs(ct_val - vbound.start) > 16:
            return False
        size = min(vbound.end - ct_val, 4096)
        if size < 6:
            return False
        raw = img.read_bytes(ct_val, size)
        md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64 if img.bits == 64 else cs.CS_MODE_32)
        insns = list(md.disasm(raw, ct_val))
        if not insns or insns[0].mnemonic == "jmp":
            return False
        # Must have a ret reachable from ct_val
        has_ret = any(i.mnemonic == "ret" for i in insns)
        if not has_ret:
            return False
        # Check if the function sets eax/al (boolean or status return)
        sets_ret_reg = any(
            (i.mnemonic.startswith("mov") and ("eax" in i.op_str or "al" in i.op_str))
            or (i.mnemonic == "xor" and ("eax" in i.op_str or "al" in i.op_str))
            or (i.mnemonic.startswith("set"))
            for i in insns
        )
        return sets_ret_reg
    except Exception:
        return False


def suggest_patches_near(img, xref_addr: int, window: int = 96) -> List[Dict[str, Any]]:
    """Heuristic patch sites: jcc/call near a string xref; score UI-only vs predicate."""
    import capstone as cs

    mode = cs.CS_MODE_64 if img.bits == 64 else cs.CS_MODE_32
    md = cs.Cs(cs.CS_ARCH_X86, mode)
    md.detail = True

    # Clamp to recovered function bounds so we don't bleed across int3-separated stubs
    lo = xref_addr - window
    hi = xref_addr + window
    try:
        from argus.disasm.recovery import function_covering

        bound = function_covering(img, xref_addr)
        if bound and bound.end - bound.start < 0x8000:
            lo = max(lo, bound.start)
            hi = min(hi, bound.end)
    except Exception:
        pass
    # Also don't cross int3 padding near xref
    probe = img.read_bytes(max(0, xref_addr - window), window)
    for i in range(len(probe) - 1, -1, -1):
        if probe[i] == 0xCC:
            # keep going through CC sled; stop at first non-CC after sled when walking back from xref
            pass
    # walk left from xref for CC run
    left = img.read_bytes(xref_addr - min(window, 256), min(window, 256))
    cut = 0
    for i in range(len(left) - 1, -1, -1):
        if left[i] == 0xCC:
            cut = i + 1
            # continue through sled
            while i > 0 and left[i - 1] == 0xCC:
                i -= 1
                cut = i
            break
        if len(left) - i > 64:
            break
    if cut:
        lo = max(lo, xref_addr - min(window, 256) + cut)

    start = max(0, lo)
    length = max(16, hi - start)
    data = img.read_bytes(start, length + 32)
    if not data:
        return []

    insns = list(md.disasm(data, start))
    # Drop instructions before last int3 before xref (same-block only)
    filtered = []
    for insn in insns:
        if insn.address > xref_addr + window:
            break
        if insn.mnemonic in ("int3",) and insn.address < xref_addr:
            filtered = []
            continue
        filtered.append(insn)
    insns = filtered
    cands: List[Dict[str, Any]] = []
    for n, insn in enumerate(insns):
        m = insn.mnemonic
        near = abs(insn.address - xref_addr) <= window
        if not near:
            continue
        if m.startswith("j") and m not in ("jmp", "jecxz", "jrcxz"):
            # Filter out destructor cleanup branches jumping straight to ret/epilogue
            try:
                target_addr = int(insn.op_str, 16)
                is_cleanup = False
                for t_idx in range(n + 1, min(len(insns), n + 8)):
                    if insns[t_idx].address == target_addr:
                        if insns[t_idx].mnemonic in ("ret", "nop", "add", "pop"):
                            skipped = [insns[x].mnemonic for x in range(n + 1, t_idx)]
                            if any("call" in sm for sm in skipped) and len(skipped) <= 3:
                                is_cleanup = True
                        break
                if is_cleanup:
                    continue
            except (ValueError, TypeError):
                pass

            ui_only = True
            ret_guess = 1
            reason = f"conditional near string xref@{hex(xref_addr)}"
            score = 40
            saw_pred = False
            saw_call = False
            cmp_imm: Optional[int] = None
            for b in range(max(0, n - 8), n):
                bm = insns[b].mnemonic
                bo = insns[b].op_str or ""
                if bm in ("cmp", "test", "and", "or", "xor", "sub", "add"):
                    saw_pred = True
                    reason = f"jcc after {bm} near xref@{hex(xref_addr)}"
                    if bm == "cmp":
                        # parse trailing immediate: "eax, 1" / "rax, 0"
                        try:
                            if "," in bo:
                                rhs = bo.split(",")[-1].strip()
                                if rhs.startswith("0x"):
                                    cmp_imm = int(rhs, 16)
                                elif rhs.lstrip("-").isdigit():
                                    cmp_imm = int(rhs)
                        except ValueError:
                            pass
                if bm == "call":
                    saw_call = True
                    reason = f"jcc after call near xref@{hex(xref_addr)}"
            # Polarity: after cmp eax,1 / test al — jne usually means FAIL path
            if m in ("je", "jz"):
                if cmp_imm == 1:
                    taken = True  # je success when == 1
                else:
                    taken = False  # je fail after test/cmp0
            elif m in ("jne", "jnz"):
                if cmp_imm == 1:
                    taken = False  # jne fail when != 1
                else:
                    taken = True
            else:
                taken = True
            if saw_pred or saw_call:
                ui_only = False
                score = 40 + (45 if saw_call else 0) + (35 if saw_pred else 0)
                dist = abs(insn.address - xref_addr)
                score += max(0, 20 - dist // 8)
                if saw_call and cmp_imm == 1:
                    score += 40  # call→cmp eax,1→jcc = real validator gate
            if ui_only:
                score = 15
                reason = f"ui_label_only: jcc near string xref@{hex(xref_addr)} without cmp/call"
            cands.append(
                {
                    "kind": "force_branch",
                    "addr": hex(insn.address),
                    "mnemonic": f"{m} {insn.op_str}",
                    "taken": taken,
                    "reason": reason + (f" (taken={taken})" if not ui_only else ""),
                    "nearby_fn": _nearby_fn(img, insn.address),
                    "score": score,
                    "ui_label_only": ui_only,
                    "ret_guess": ret_guess,
                }
            )
        if m == "call" and abs(insn.address - xref_addr) < 64:
            score = 25
            ui_only = True
            reason = f"call near string xref@{hex(xref_addr)}"
            ret_guess = 0
            for a in range(n + 1, min(len(insns), n + 8)):
                am = insns[a].mnemonic
                ao = insns[a].op_str or ""
                if am in ("test", "cmp") and ("eax" in ao or "rax" in ao or "al" in ao):
                    score = 70
                    ui_only = False
                    ret_guess = 1
                    reason = f"call then {am} ret near xref@{hex(xref_addr)}"
                    if am == "cmp" and (", 1" in ao or ",1" in ao):
                        score = 90
                        reason = f"call then cmp==1 ret near xref@{hex(xref_addr)}"
                    break
            cands.append(
                {
                    "kind": "ret_imm" if not ui_only else "nop_bytes",
                    "addr": hex(insn.address),
                    "size": insn.size,
                    "reason": reason,
                    "nearby_fn": _nearby_fn(img, insn.address),
                    "score": score,
                    "ui_label_only": ui_only,
                    "ret_guess": ret_guess,
                    "call_target": _call_target(insn),
                }
            )
    # Caller Walking: If this function is a leaf/dialog/formatter, find who calls/references it
    try:
        from argus.disasm.recovery import function_covering

        bound = function_covering(img, xref_addr)
        if bound and bound.start:
            caller_xrefs = find_string_xrefs_multi(img, [bound.start]).get(bound.start, [])
            for cx in caller_xrefs[:6]:
                ca = int(cx.get("addr") or "0", 16)
                if not ca or ca == xref_addr:
                    continue
                cbound = function_covering(img, ca)
                if cbound and cbound.start:
                    c_start = cbound.start
                    c_len = min(max(cbound.end - cbound.start, 64), 0x2000)
                else:
                    c_start = max(0, ca - 128)
                    c_len = 160
                c_data = img.read_bytes(c_start, c_len)
                if not c_data:
                    continue
                c_insns = list(md.disasm(c_data, c_start))
                for ci, c_insn in enumerate(c_insns):
                    if c_insn.address > ca + 8:
                        continue
                    cm = c_insn.mnemonic
                    if cm.startswith("j") and cm not in ("jmp", "jecxz", "jrcxz"):
                        target_addr = None
                        try:
                            target_addr = int(c_insn.op_str, 16)
                        except (ValueError, TypeError):
                            pass

                        # Determine if jump bypasses the error call @ ca or jumps into it
                        if target_addr and target_addr > ca:
                            taken = True
                        elif target_addr and target_addr <= ca:
                            taken = False
                        elif cm in ("jne", "jnz"):
                            taken = True
                        else:
                            taken = False

                        val_call = None
                        for b in range(ci - 1, max(-1, ci - 9), -1):
                            if c_insns[b].mnemonic == "call":
                                ct_val = _call_target(c_insns[b])
                                if ct_val:
                                    vbound = function_covering(img, ct_val)
                                    vsz = (vbound.end - vbound.start) if vbound else 0
                                    nc = count_function_callers(img, ct_val)
                                    if 3 <= nc <= 200 and vsz >= 0x80 and _is_safe_boolean_validator(img, ct_val):
                                        val_call = (ct_val, nc, vsz)
                                        break

                        score = 220
                        why = f"caller gate: skips error/dialog call@{hex(ca)} (taken={taken})"
                        if val_call:
                            score += 40
                            why += f" after validator hub@{hex(val_call[0])} (in-degree={val_call[1]})"

                        cands.append(
                            {
                                "kind": "force_branch",
                                "addr": hex(c_insn.address),
                                "mnemonic": f"{cm} {c_insn.op_str}",
                                "taken": taken,
                                "reason": why,
                                "nearby_fn": _nearby_fn(img, c_insn.address),
                                "score": score,
                                "ui_label_only": False,
                                "ret_guess": 1,
                            }
                        )

                        if val_call:
                            hub_score = 350 + min(val_call[1] * 5, 100)
                            cands.append(
                                {
                                    "kind": "ret_imm",
                                    "addr": hex(val_call[0]),
                                    "reason": f"primary validator hub (in-degree={val_call[1]}, size={val_call[2]}B) called before gate@{hex(c_insn.address)}",
                                    "nearby_fn": _nearby_fn(img, val_call[0]),
                                    "score": hub_score,
                                    "ui_label_only": False,
                                    "ret_guess": 1,
                                    "value": 1,
                                }
                            )
    except Exception:
        pass

    enriched = []
    for c in cands:
        addr_int = int(c.get("addr") or "0", 16)
        if c.get("kind") == "ret_imm" and c.get("call_target"):
            ct = c["call_target"]
            boost = 10
            try:
                from argus.disasm.recovery import function_covering

                bound = function_covering(img, ct)
                if bound:
                    sz = bound.end - bound.start
                    if sz >= 0x400:
                        boost = 55
                    elif sz < 0x80:
                        boost = -30
                nc = count_function_callers(img, ct)
                if 3 <= nc <= 200:
                    boost += 50
            except Exception:
                pass
            enriched.append(
                {
                    **c,
                    "addr": hex(ct),
                    "reason": c["reason"] + f" → stub callee@{hex(ct)}",
                    "score": int(c["score"]) + boost,
                    "asm_preview": generate_asm_preview(img, ct),
                }
            )
        else:
            enriched.append(
                {
                    **c,
                    "asm_preview": generate_asm_preview(img, addr_int) if addr_int else "",
                }
            )

    enriched.sort(key=lambda x: -int(x.get("score") or 0))
    seen = set()
    out = []
    for c in enriched:
        key = (c["kind"], c["addr"])
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
        if len(out) >= 12:
            break
    return out


def count_function_callers(img, func_va: int) -> int:
    """Count direct rel32 calls/jmps to func_va in .text section."""
    sec = None
    for s in getattr(img, "sections", []):
        if getattr(s, "name", "") in (".text", "code", "text"):
            sec = s
            break
    if not sec or not getattr(sec, "data", None):
        return 0
    try:
        import numpy as np

        data = sec.data
        base = sec.addr
        count = 0
        C = func_va - base - 4
        for shift in range(4):
            chunk_len = (len(data) - shift) // 4 * 4
            arr = np.frombuffer(data[shift : shift + chunk_len], dtype=np.int32)
            offsets = (np.arange(len(arr), dtype=np.int64) * 4 + shift).astype(np.int64)
            hits = np.flatnonzero(arr.astype(np.int64) + offsets == C)
            for h in hits:
                idx = int(offsets[h])
                if idx > 0 and data[idx - 1] in (0xE8, 0xE9):
                    count += 1
        return count
    except Exception:
        return 0


def generate_asm_preview(img, target_addr: int, count_before: int = 3, count_after: int = 4) -> str:
    """Disassemble a clean annotated instruction snippet around target_addr."""
    if not target_addr:
        return ""
    try:
        import capstone as cs

        mode = cs.CS_MODE_64 if getattr(img, "bits", 64) == 64 else cs.CS_MODE_32
        md = cs.Cs(cs.CS_ARCH_X86, mode)
        start = max(0, target_addr - 36)
        data = img.read_bytes(start, 80)
        if not data:
            return ""
        insns = list(md.disasm(data, start))
        target_idx = None
        for idx, insn in enumerate(insns):
            if insn.address == target_addr:
                target_idx = idx
                break
        if target_idx is None:
            return ""
        lo = max(0, target_idx - count_before)
        hi = min(len(insns), target_idx + count_after + 1)
        lines = []
        for insn in insns[lo:hi]:
            tag = "  <-- GATE" if insn.address == target_addr else ""
            lines.append(f"0x{insn.address:x}: {insn.mnemonic:8} {insn.op_str}{tag}")
        return "\n".join(lines)
    except Exception:
        return ""


def _call_target(insn) -> Optional[int]:
    try:
        import capstone as cs

        if getattr(insn, "operands", None):
            op = insn.operands[0]
            if op.type == cs.CS_OP_IMM:
                return int(op.imm)
    except Exception:
        pass
    try:
        op_str = getattr(insn, "op_str", "") or ""
        if op_str.startswith("0x"):
            return int(op_str, 16)
        if op_str.isdigit():
            return int(op_str)
    except Exception:
        pass
    return None


def rank_gate_candidates(
    img,
    string_hits: List[Dict[str, Any]],
    *,
    limit: int = 12,
) -> List[Dict[str, Any]]:
    """From top license string hits → ranked gate patch sites (no vendor names)."""
    addrs: List[int] = []
    for h in string_hits:
        if h.get("kind") != "string":
            continue
        try:
            addrs.append(int(h["addr"], 0))
        except (TypeError, ValueError):
            continue
        if len(addrs) >= 5:
            break
    if not addrs:
        return []
    xref_map = find_string_xrefs_multi(img, addrs, max_per_target=6)
    ranked: List[Dict[str, Any]] = []
    for sa in addrs:
        for xr in xref_map.get(sa) or []:
            try:
                xa = int(xr["addr"], 0)
            except (TypeError, ValueError):
                continue
            for c in suggest_patches_near(img, xa):
                ranked.append(
                    {
                        **c,
                        "string_addr": hex(sa),
                        "xref_addr": xr["addr"],
                    }
                )
    ranked.sort(key=lambda x: (-int(x.get("score") or 0), x.get("ui_label_only", True)))
    seen = set()
    out = []
    for c in ranked:
        key = (c.get("kind"), c.get("addr"))
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
        if len(out) >= limit:
            break
    return out


def find_in_binary(
    path: str,
    query: Optional[str] = None,
    *,
    limit: int = 30,
    with_xrefs: bool = True,
) -> Dict[str, Any]:
    """Search symbols/strings; rank phrases; optionally attach xrefs + patch hints."""
    img = load_binary(path)
    q = (query or "").strip()
    if not q:
        from argus.flow import discover_reject_ui_strings

        candidates = discover_reject_ui_strings(img, limit=12)
        return {
            "ok": True,
            "summary": f"find: no query= — reject_ui_candidates={len(candidates)}",
            "observations": [
                "query= required for targeted string/symbol search",
                f"reject_ui_candidates={len(candidates)}",
            ],
            "evidence": {
                "hits": [],
                "reject_ui_candidates": candidates,
                "query": "",
                "fmt": img.fmt,
                "entry": hex(img.entry),
            },
            "hints": {
                "reject_ui_candidates": candidates,
                "suggested_tools": [
                    {"tool": "argus_find", "reason": "pass query= from user task", "confidence": 0.9},
                    {"tool": "argus_xrefs", "reason": "after find hit", "confidence": 0.5},
                ],
            },
            "hits": [],
            "limits": {"limit": limit, "returned": 0},
            "next_hint": (
                "no query=: pass query= from user task or pick needle from reject_ui_candidates"
            ),
        }

    keywords = list(DEFAULT_KEYWORDS)
    if query:
        # keep multi-word phrases from query intact
        q = query.strip()
        if len(q) >= 3:
            keywords.insert(0, q.lower())
        for tok in re.split(r"[\s,;/|]+", q):
            t = tok.strip().lower()
            if len(t) >= 3 and t not in keywords:
                keywords.insert(0, t)

    scored: List[Tuple[int, Dict[str, Any]]] = []
    seen: set[tuple] = set()

    def add(addr: int, kind: str, preview: str, needle: str) -> None:
        if addr == 0:
            return
        key = (addr, kind, preview[:48])
        if key in seen:
            return
        seen.add(key)
        hit = {
            "addr": hex(addr),
            "kind": kind,
            "preview": preview[:120],
            "nearby_fn": _nearby_fn(img, addr),
            "needle": needle,
            "score": _score_hit(preview, needle, kind),
        }
        scored.append((hit["score"], hit))

    if not keywords:
        for name, sym in img.symbols.items():
            if sym.is_function and not sym.is_import and sym.addr:
                add(sym.addr, "symbol", name, "symbol")
                if len(scored) >= limit * 2:
                    break

    for name, sym in img.symbols.items():
        if not sym.addr or sym.is_import:
            continue
        low = name.lower()
        for kw in keywords:
            if len(kw) >= 3 and kw in low:
                add(sym.addr, "symbol", name, kw)
                break

    for kw in keywords:
        raw = kw.encode("utf-8", errors="ignore")
        if len(raw) < 4:
            continue
        for sec in img.sections:
            if not sec.data or sec.executable:
                continue  # strings live in rodata
            for off in _scan_section_ci(sec.data, raw):
                end = off
                while end < len(sec.data) and 32 <= sec.data[end] < 127 and end - off < 100:
                    end += 1
                preview = sec.data[off:end].decode("latin1", errors="replace")
                if _junk_preview(preview) and len(kw) < 10:
                    continue
                add(sec.addr + off, "string", preview, kw)
                if len(scored) >= limit * 4:
                    break

    scored.sort(key=lambda x: -x[0])
    hits = [h for _, h in scored[:limit]]

    local_n = sum(1 for s in img.symbols.values() if s.is_function and not s.is_import and s.addr)
    stripped = local_n < 40 and any(
        (s.executable and s.data and len(s.data) >= 2_000_000) for s in img.sections
    )

    gate_candidates: List[Dict[str, Any]] = []
    patch_candidates: List[Dict[str, Any]] = []
    next_hint_slice: Optional[str] = None
    if with_xrefs:
        top = [h for h in hits if h["kind"] == "string" and h["score"] >= 80][:5]
        if not top:
            top = [h for h in hits if h["kind"] == "string"][:3]
        addrs = []
        for h in top:
            try:
                addrs.append(int(h["addr"], 0))
            except ValueError:
                pass
        xref_map = find_string_xrefs_multi(img, addrs, max_per_target=6) if addrs else {}
        for h in top:
            try:
                addr = int(h["addr"], 0)
            except ValueError:
                continue
            h["xrefs"] = xref_map.get(addr) or []
        gate_candidates = rank_gate_candidates(img, top, limit=12)
        patch_candidates = list(gate_candidates)

    # On stripped binaries or explicit query, merge universal gate_scan gates
    if with_xrefs and (stripped or query):
        try:
            from argus.find_slice import gate_scan

            sliced = gate_scan(path, query, limit=12)
            seen_g = {(g.get("kind"), g.get("addr")) for g in gate_candidates}
            for g in sliced.get("gate_candidates") or []:
                key = (g.get("kind"), g.get("addr"))
                if key in seen_g:
                    continue
                seen_g.add(key)
                gate_candidates.append(g)
            gate_candidates.sort(
                key=lambda g: (-int(g.get("score") or 0), g.get("ui_label_only", True))
            )
            gate_candidates = gate_candidates[:12]
            patch_candidates = list(gate_candidates)
            if sliced.get("next_hint") and any(
                not g.get("ui_label_only") for g in gate_candidates
            ):
                next_hint_slice = sliced["next_hint"]
        except Exception:
            next_hint_slice = None

    uniq_p = patch_candidates[:12]

    next_hint = (
        "use patch_candidates / gate_candidates with argus_patch on evidence VAs; "
        "never stub main/entry"
    )
    gate_symbols = _collect_gate_symbols(img, query, limit=16)
    suggested_stubs = [
        {"name": g["name"], "addr": g["addr"], "value": g["ret_value"]} for g in gate_symbols[:8]
    ]
    intent = _query_intent(query)

    if intent == "ui":
        top_str = [h for h in hits if h.get("kind") == "string"][:6]
        if top_str:
            examples = [f"{h.get('preview')!r}@{h.get('addr')}" for h in top_str[:4]]
            next_hint = (
                "UI/text request: argus_patch kind=replace_string with exact old= from hits; "
                "new MUST be ≤ len(old) bytes (pad with spaces). "
                f"hits={examples}. Do NOT ret_imm / suggested_stubs for string-only prompts."
            )
        else:
            next_hint = (
                "UI/text request: argus_find with the exact phrase to change, then "
                "replace_string (new ≤ old length). Do NOT ret_imm for titles/labels."
            )
    elif suggested_stubs:
        names = [s["name"] for s in suggested_stubs[:6]]
        addrs0 = [s["addr"] for s in suggested_stubs if int(s["value"]) == 0][:6]
        addrs1 = [s["addr"] for s in suggested_stubs if int(s["value"]) == 1][:4]
        parts = [
            f"PREFERRED gate path: stub ranked gate_symbols (not UI Callback/Widget from string xrefs). "
            f"Top gates={names}."
        ]
        if addrs0:
            parts.append(
                f"argus_patch kind=ret_imm addrs={addrs0} value=0 "
                f"(Is/Check/Verify/Validate OK-style)."
            )
        if addrs1:
            parts.append(
                f"Then chain binary=.patched kind=ret_imm addrs={addrs1} value=1 "
                f"(bool isActivated/Has* style)."
            )
        parts.append("Do NOT ret_imm *Callback* / *Widget* alone — that usually leaves PRO locked.")
        if intent == "mixed":
            parts.append("After gate transform, use replace_string for any UI text the user asked for.")
        next_hint = " ".join(parts)
    elif gate_candidates:
        top_g = gate_candidates[0]
        non_ui = [g for g in gate_candidates if not g.get("ui_label_only")]
        pick = non_ui[0] if non_ui else top_g
        if next_hint_slice and non_ui:
            next_hint = next_hint_slice
        else:
            taken_bit = ""
            if pick.get("kind") == "force_branch" and "taken" in pick:
                taken_bit = f" taken={pick.get('taken')}"
            next_hint = (
                f"gate_candidates ranked: prefer score>=40 and ui_label_only=false. "
                f"Try argus_patch kind={pick.get('kind')} addr={pick.get('addr')} "
                f"value={pick.get('ret_guess', 1)}{taken_bit} — {pick.get('reason')}. "
                f"If ui_label_only, do NOT claim behavior change; try next candidate then re-find strings."
            )
        if stripped:
            next_hint += " Stripped: prefer argus_slice then force_branch/ret_imm on non_ui gates."
    else:
        next_hint = (
            "no suggested_stubs and no gate_candidates; binary may be stripped — "
            "do not claim behavior verified; dig with more queries/xrefs/lift or report incomplete"
        )
        if stripped:
            next_hint = (
                "STRIPPED commercial-like binary: call argus_slice then argus_apply_plan. "
                "Patch patch_plan only; never claim behavior change from UI strings alone."
            )

    return {
        "ok": True,
        "summary": (
            f"find hits={len(hits)} gate_candidates={len(gate_candidates)}"
            + (f" gate_symbols={len(gate_symbols)}" if gate_symbols else "")
            + (f" stripped_hint={stripped}" if stripped else "")
        ),
        "evidence": {
            "hits": hits,
            "patch_candidates": uniq_p,
            "gate_candidates": gate_candidates,
            "gate_symbols": gate_symbols,
            "suggested_stubs": suggested_stubs,
            "stripped_like": stripped,
            "local_funcs": local_n,
            "entry": hex(img.entry),
            "fmt": img.fmt,
        },
        "hits": hits,
        "patch_candidates": uniq_p,
        "gate_candidates": gate_candidates,
        "gate_symbols": gate_symbols,
        "suggested_stubs": suggested_stubs,
        "stripped_like": stripped,
        "limits": {"limit": limit, "returned": len(hits)},
        "next_hint": next_hint,
    }
