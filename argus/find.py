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
    "authenticate",
    "check_password",
]


def _nearby_fn(img, addr: int) -> Optional[str]:
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


def find_string_xrefs_multi(
    img,
    targets: List[int],
    *,
    max_per_target: int = 8,
) -> Dict[int, List[Dict[str, Any]]]:
    """One pass over executable sections → xrefs for many string VAs."""
    import capstone as cs
    from capstone.x86 import X86_REG_RIP

    want = {t: [] for t in targets if t}
    if not want or img.arch not in ("x86_64", "x86"):
        return want
    mode = cs.CS_MODE_64 if img.bits == 64 else cs.CS_MODE_32
    md = cs.Cs(cs.CS_ARCH_X86, mode)
    md.detail = True
    remaining = set(want)
    for sec in img.sections:
        if not remaining:
            break
        if not sec.executable or not sec.data or len(sec.data) > 12_000_000:
            continue
        for insn in md.disasm(sec.data, sec.addr):
            hit_t = None
            for op in insn.operands:
                ea = None
                if op.type == cs.CS_OP_MEM and op.mem.base == X86_REG_RIP:
                    ea = insn.address + insn.size + op.mem.disp
                elif op.type == cs.CS_OP_IMM and op.imm in remaining:
                    ea = op.imm
                if ea in remaining:
                    hit_t = ea
                    break
            if hit_t is None:
                continue
            bucket = want[hit_t]
            if len(bucket) >= max_per_target:
                if all(len(want[t]) >= max_per_target for t in remaining):
                    remaining.clear()
                    break
                continue
            bucket.append(
                {
                    "addr": hex(insn.address),
                    "mnemonic": insn.mnemonic,
                    "op_str": insn.op_str,
                    "nearby_fn": _nearby_fn(img, insn.address),
                }
            )
            if len(bucket) >= max_per_target:
                # keep target in remaining until all filled; cheap check
                if all(len(want[t]) >= max_per_target for t in list(remaining)):
                    remaining.clear()
                    break
    return want


def find_string_xrefs(img, target: int, *, max_hits: int = 24) -> List[Dict[str, Any]]:
    return find_string_xrefs_multi(img, [target], max_per_target=max_hits).get(target, [])


def suggest_patches_near(img, xref_addr: int, window: int = 96) -> List[Dict[str, Any]]:
    """Heuristic patch sites: jcc near a string xref (license flag / branch)."""
    import capstone as cs

    mode = cs.CS_MODE_64 if img.bits == 64 else cs.CS_MODE_32
    md = cs.Cs(cs.CS_ARCH_X86, mode)
    start = xref_addr - window
    if start < 0:
        start = 0
    data = img.read_bytes(start, window * 2 + 16)
    cands: List[Dict[str, Any]] = []
    for insn in md.disasm(data, start):
        m = insn.mnemonic
        if m.startswith("j") and m not in ("jmp", "jecxz"):
            cands.append(
                {
                    "kind": "force_branch",
                    "addr": hex(insn.address),
                    "mnemonic": f"{m} {insn.op_str}",
                    "taken": True,
                    "reason": f"conditional near string xref@{hex(xref_addr)}",
                    "nearby_fn": _nearby_fn(img, insn.address),
                }
            )
        if m == "call" and abs(insn.address - xref_addr) < 40:
            cands.append(
                {
                    "kind": "nop_bytes",
                    "addr": hex(insn.address),
                    "size": insn.size,
                    "reason": f"call near string xref@{hex(xref_addr)}",
                    "nearby_fn": _nearby_fn(img, insn.address),
                }
            )
    seen = set()
    out = []
    for c in cands:
        if c["addr"] in seen:
            continue
        seen.add(c["addr"])
        out.append(c)
        if len(out) >= 8:
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

    patch_candidates: List[Dict[str, Any]] = []
    if with_xrefs:
        # Only top-scoring strings — one .text pass for all of them
        top = [h for h in hits if h["kind"] == "string" and h["score"] >= 80][:3]
        if not top:
            top = [h for h in hits if h["kind"] == "string"][:2]
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
            xrefs = xref_map.get(addr) or []
            h["xrefs"] = xrefs
            for xr in xrefs[:3]:
                try:
                    xa = int(xr["addr"], 0)
                except ValueError:
                    continue
                patch_candidates.extend(suggest_patches_near(img, xa))

    # unique patch candidates
    seen_p = set()
    uniq_p = []
    for c in patch_candidates:
        if c["addr"] in seen_p:
            continue
        seen_p.add(c["addr"])
        uniq_p.append(c)
        if len(uniq_p) >= 12:
            break

    next_hint = (
        "use patch_candidates with argus_patch force_branch/nop_bytes; "
        "never stub main/entry"
    )
    lex_apis = [
        n
        for n in (
            "IsLicenseGenuine",
            "IsLicenseValid",
            "IsTrialGenuine",
            "IsLocalTrialGenuine",
        )
        if n in img.symbols
    ]
    if lex_apis:
        next_hint = (
            f"LexActivator APIs found {lex_apis}: use argus_patch kind=unlock_license "
            f"(returns LA_OK=0) to unlock PRO — string replaces alone do not unlock features"
        )
    elif uniq_p:
        next_hint = (
            f"try argus_patch kind={uniq_p[0]['kind']} addr={uniq_p[0]['addr']} "
            f"— then safety-check; on unsafe try next candidate"
        )

    return {
        "ok": True,
        "summary": (
            f"find hits={len(hits)} patch_candidates={len(uniq_p)}"
            + (f" lex_apis={len(lex_apis)}" if lex_apis else "")
        ),
        "evidence": {
            "hits": hits,
            "patch_candidates": uniq_p,
            "license_apis": [
                {"name": n, "addr": hex(img.symbols[n].addr)} for n in lex_apis
            ],
            "entry": hex(img.entry),
            "fmt": img.fmt,
        },
        "hits": hits,
        "patch_candidates": uniq_p,
        "license_apis": lex_apis,
        "limits": {"limit": limit, "returned": len(hits)},
        "next_hint": next_hint,
    }
