from __future__ import annotations

"""Keyword / string / symbol find + xrefs for agent grounding."""

import re
from typing import Any, Dict, List, Optional, Tuple

from argus.binary import load_binary

# Longer / more specific first — short tokens like "serial" flood Qt binaries
PHRASE_KEYWORDS = [
    "running free version",
    "running free",
    "free version",
    "invalid license",
    "license expired",
    "license key",
    "no license",
    "trial expired",
    "unregistered",
    "activation required",
    "license check",
]

DEFAULT_KEYWORDS = PHRASE_KEYWORDS + [
    "license",
    "licence",
    "trial",
    "activate",
    "activation",
    "expired",
    "subscription",
    "лиценз",
    "активац",
    "парол",
    "password",
]

# Soft gate-name filter — structural patterns only (not a vendor unlock recipe)
# Prefix must be a CamelCase/API token (not "ise" inside Premise)
_GATE_NAME_RE = re.compile(
    r"(?:^|[^A-Za-z])(Is|Check|Verify|Validate|Has)"
    r"(?=[A-Z0-9_])[A-Za-z0-9_]*"
    r"(Licen[cs]e|Trial|Genuine|Activat)"
)
# Unmangled C-style API: IsLicenseGenuine, CheckTrial, …
_GATE_SHORT_RE = re.compile(
    r"^(Is|Check|Verify|Validate|Has)"
    r"(?=([A-Z0-9_]))[A-Za-z0-9_]{0,48}"
    r"(Licen[cs]e|Trial|Genuine|Valid|Activat)[A-Za-z0-9_]*$"
)
# Mangled C++ method leaf: …12isActivatedEv / …14isTrialValidEv (no product names)
_GATE_MANGLED_BOOL_RE = re.compile(
    r"_ZN\d+\w+\d+(isActivated|isActivatedOffline|isTrialValid|hasLicense|isLicensed)Ev$"
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
    return min(max(total, 8_000_000), 80_000_000)


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
    import struct

    if img.arch not in ("x86_64", "x86") or not target:
        return []
    lo, hi = target - radius, target + radius
    out: List[Dict[str, Any]] = []
    seen: set[int] = set()
    for sec in img.sections:
        if not sec.executable or not sec.data:
            continue
        data = sec.data
        for i in range(0, len(data) - 3):
            for fmt in ("<I", "<Q") if img.bits == 64 else ("<I",):
                if fmt == "<Q" and i + 8 > len(data):
                    continue
                if fmt == "<I" and i + 4 > len(data):
                    continue
                size = 8 if fmt == "<Q" else 4
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
                    # walk back up to 15 bytes to find a disassembled insn that uses this imm
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

    mode = cs.CS_MODE_64 if img.bits == 64 else cs.CS_MODE_32
    md = cs.Cs(cs.CS_ARCH_X86, mode)
    md.detail = True
    remaining = {t for t, bucket in want.items() if len(bucket) < max_per_target}
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
                for insn in md.disasm(chunk[:take], base):
                    if not remaining:
                        break
                    hit_t = None
                    for op in insn.operands:
                        ea = None
                        if op.type == cs.CS_OP_MEM and op.mem.base == X86_REG_RIP:
                            ea = insn.address + insn.size + op.mem.disp
                        elif op.type == cs.CS_OP_IMM and op.imm in remaining:
                            ea = int(op.imm)
                        if ea in remaining:
                            hit_t = ea
                            break
                    if hit_t is None:
                        continue
                    bucket = want[hit_t]
                    # dedupe near same site
                    if any(b.get("addr") == hex(insn.address) for b in bucket):
                        continue
                    if len(bucket) >= max_per_target:
                        remaining.discard(hit_t)
                        continue
                    bucket.append(
                        {
                            "addr": hex(insn.address),
                            "mnemonic": insn.mnemonic,
                            "op_str": insn.op_str,
                            "nearby_fn": _nearby_fn(img, insn.address),
                            "kind": "rip" if "rip" in (insn.op_str or "").lower() else "imm",
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
    enriched = []
    for c in cands:
        if c.get("kind") == "ret_imm" and c.get("call_target"):
            ct = c["call_target"]
            boost = 10
            # Prefer stubbing large validators over tiny string parsers
            try:
                from argus.disasm.recovery import function_covering

                bound = function_covering(img, ct)
                if bound:
                    sz = bound.end - bound.start
                    if sz >= 0x400:
                        boost = 55
                    elif sz < 0x80:
                        boost = -30  # likely parser/helper, not the gate
            except Exception:
                pass
            enriched.append(
                {
                    **c,
                    "addr": hex(ct),
                    "reason": c["reason"] + f" → stub callee@{hex(ct)}",
                    "score": int(c["score"]) + boost,
                }
            )
        enriched.append(c)

    enriched.sort(key=lambda x: -int(x.get("score") or 0))
    seen = set()
    out = []
    for c in enriched:
        key = (c["kind"], c["addr"])
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
        if len(out) >= 10:
            break
    return out


def _call_target(insn) -> Optional[int]:
    try:
        import capstone as cs

        if not insn.operands:
            return None
        op = insn.operands[0]
        if op.type == cs.CS_OP_IMM:
            return int(op.imm)
    except Exception:
        return None
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
    keywords = list(DEFAULT_KEYWORDS)
    if query:
        # keep multi-word phrases from query intact
        q = query.strip()
        if len(q) >= 4:
            keywords.insert(0, q.lower())
        for tok in re.split(r"[\s,;/|]+", q):
            t = tok.strip().lower()
            if len(t) >= 4 and t not in keywords:
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

    for name, sym in img.symbols.items():
        if not sym.addr or sym.is_import:
            continue
        low = name.lower()
        for kw in keywords:
            if len(kw) >= 5 and kw in low:
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

    # On stripped / license-ish queries, merge universal gate_scan gates
    qlow = (query or "").lower()
    license_ish = any(
        k in qlow
        for k in ("license", "unlock", "register", "activat", "trial", "unregistered")
    )
    if with_xrefs and (stripped or license_ish):
        try:
            from argus.find_slice import gate_scan

            sliced = gate_scan(path, query if license_ish else "invalid license", limit=12)
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
