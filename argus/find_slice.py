from __future__ import annotations

"""Gate scan: string → xref → covering fn → ranked gates + patch_plan (universal)."""

from typing import Any, Dict, List, Optional, Tuple

from argus.binary import load_binary
from argus.disasm.recovery import function_covering
from argus.find import find_string_xrefs_multi, suggest_patches_near

# Generic validate / failure messaging (no vendor / product-specific names)
_VALIDATE_SUBS = [
    b"doesn't appear to be valid",
    b"does not appear to be valid",
    b"is no longer valid",
    b"has been invalidated",
    b"invalid license",
    b"invalid serial",
    b"license expired",
    b"trial has expired",
    b"BEGIN LICENSE",
    b"END LICENSE",
    b"activation",
    b"ACTIVATION",
    b"license key",
    b"serial number",
    b"license expired",
    b"not a valid",
]

_UI_SUBS = [
    b"Unregistered",
    b"unregistered",
    b"Buy License",
    b"buy license",
    b"trial expired",
    b"Thanks for trying",
    b"not registered",
    b"Free Trial",
]

# Phrase-class boosts (matched as substr of recovered needle)
_VALIDATE_BOOST = {
    "doesn't appear to be valid": 80,
    "does not appear to be valid": 80,
    "is no longer valid": 50,
    "has been invalidated": 50,
    "invalid license": 55,
    "invalid serial": 55,
    "BEGIN LICENSE": 55,
    "license key": 25,
    "activation": 20,
    "not a valid": 40,
}

_LARGE_FN = 0x800
_MAX_COVER_STUB = 0x1800  # bigger → likely UI/app shell; stubbing entry kills launch
_PARSER_FN = 0xC00

_PASSWORD_SUBS = [
    b"Password:",
    b"password",
    b"Go away",
    b"Welcome",
    b"Username:",
]


def _sym_addr(sym: Any) -> int:
    if isinstance(sym, int):
        return sym
    return int(getattr(sym, "addr", sym))


def _password_crackme_signals(img) -> bool:
    syms = img.symbols or {}
    if "authenticate" not in syms:
        return False
    blob = b""
    for sec in getattr(img, "sections", []) or []:
        if getattr(sec, "data", None):
            blob += sec.data[: min(len(sec.data), 128 * 1024)]
    low = blob.lower()
    return any(s.lower() in low for s in _PASSWORD_SUBS)


def _scan_password_auth_jmp(
    img,
    auth_addr: int,
    module_path: str,
    *,
    seen_gate: set[str],
) -> List[Dict[str, Any]]:
    """After authenticate: test eax; unconditional jmp over success → force_branch."""
    import capstone as cs

    out: List[Dict[str, Any]] = []
    mode = cs.CS_MODE_64 if getattr(img, "bits", 64) == 64 else cs.CS_MODE_32
    md = cs.Cs(cs.CS_ARCH_X86, mode)
    md.detail = True
    auth_lo = auth_addr & 0xFFFFFFFF
    syms = img.symbols or {}
    fn_ranges: List[Tuple[int, int, str]] = []
    for name, sym in syms.items():
        if not getattr(sym, "is_function", True):
            continue
        start = _sym_addr(sym)
        size = int(getattr(sym, "size", 0) or 0)
        if size <= 0:
            size = 0x200
        fn_ranges.append((start, start + min(size, 0x800), str(name)))
    if not fn_ranges:
        fn_ranges.append((max(0, auth_addr - 0x100), auth_addr + 0x400, "unknown"))

    for fn_start, fn_end, fn_name in fn_ranges:
        data = img.read_bytes(fn_start, fn_end - fn_start)
        if not data:
            continue
        insns = list(md.disasm(data, fn_start))
        for n, insn in enumerate(insns):
            if insn.mnemonic != "call":
                continue
            target = None
            try:
                if insn.operands and insn.operands[0].type == cs.x86.X86_OP_IMM:
                    target = int(insn.operands[0].imm) & 0xFFFFFFFF
            except Exception:
                target = None
            if target != auth_lo:
                continue
            test_i = jmp_i = None
            for a in range(n + 1, min(len(insns), n + 8)):
                am = insns[a].mnemonic
                ao = insns[a].op_str or ""
                if test_i is None and am == "test" and "eax" in ao:
                    test_i = a
                    continue
                if test_i is not None and am == "jmp":
                    jmp_i = a
                    break
            if jmp_i is None:
                continue
            j = insns[jmp_i]
            key = f"force_branch:{hex(j.address)}"
            if key in seen_gate:
                continue
            seen_gate.add(key)
            call_fn = fn_name
            try:
                cov = function_covering(img, insn.address)
                if cov and cov.name:
                    call_fn = cov.name
            except Exception:
                pass
            out.append(
                {
                    "kind": "force_branch",
                    "addr": hex(j.address),
                    "score": 530,
                    "ui_label_only": False,
                    "taken": True,
                    "ret_guess": 1,
                    "reason": "password: jmp over success after authenticate → redirect fallthrough",
                    "nearby_fn": call_fn,
                    "string_kind": "password",
                    "mnemonic": f"{j.mnemonic} {j.op_str}",
                    "module": module_path,
                }
            )
            return out
    return out


def _password_crackme_gates(img, module_path: str) -> List[Dict[str, Any]]:
    """Emit ret_imm on authenticate + wire gates near password strings."""
    gates: List[Dict[str, Any]] = []
    syms = img.symbols or {}
    auth = syms.get("authenticate")
    if auth is not None:
        addr = _sym_addr(auth)
        seen: set[str] = set()
        gates.extend(_scan_password_auth_jmp(img, addr, module_path, seen_gate=seen))
        if not any(g.get("reason", "").startswith("password: jmp") for g in gates):
            gates.append(
                {
                    "kind": "ret_imm",
                    "addr": hex(addr),
                    "score": 520,
                    "ui_label_only": False,
                    "ret_guess": 1,
                    "value": 1,
                    "reason": "password crackme: stub authenticate → return 1",
                    "nearby_fn": "authenticate",
                    "fn_start": hex(addr),
                    "string_kind": "password",
                }
            )
    seen: set[str] = set()
    hits: List[Dict[str, Any]] = []
    for substr in _PASSWORD_SUBS:
        for va, preview in _find_cstring_vas(img, substr, limit=2):
            if va in {int(h["addr"], 0) for h in hits}:
                continue
            hits.append(
                {
                    "addr": hex(va),
                    "preview": preview.decode("utf-8", errors="replace")[:80],
                    "kind": "password",
                    "substr": substr.decode("utf-8", errors="replace"),
                }
            )
    targets = [int(h["addr"], 0) for h in hits]
    xref_map = find_string_xrefs_multi(img, targets, max_per_target=6) if targets else {}
    for sh in hits:
        sva = int(sh["addr"], 0)
        for xr in xref_map.get(sva) or []:
            try:
                xref_va = int(xr["addr"], 0)
            except (TypeError, ValueError):
                continue
            cov = function_covering(img, xref_va)
            meta = {
                "nearby_fn": cov.name if cov else "main",
                "fn_start": hex(cov.start) if cov else None,
                "string_addr": sh.get("addr"),
                "string_kind": "password",
                "string_preview": sh.get("preview"),
                "xref_addr": xr["addr"],
            }
            ranges: List[Tuple[int, int]] = []
            if cov:
                ranges.append((cov.start, cov.end))
            ranges.append((max(0, xref_va - 0x400), xref_va + 0x80))
            for a0, a1 in ranges:
                for g in _scan_call_cmp1_gates(img, a0, a1, meta=meta, seen_gate=seen):
                    g["module"] = module_path
                    gates.append(g)
    for g in gates:
        g.setdefault("module", module_path)
    return gates


# Substrings safe to treat as "validate body lives here" (not generic chrome)
_COVER_STUB_SUBS = {
    "doesn't appear to be valid",
    "does not appear to be valid",
    "is no longer valid",
    "has been invalidated",
    "invalid license",
    "invalid serial",
    "BEGIN LICENSE",
    "not a valid",
}


def _find_cstring_vas(img, substr: bytes, limit: int = 6) -> List[Tuple[int, bytes]]:
    """Find C-string VAs containing substr (rewind to previous NUL)."""
    out: List[Tuple[int, bytes]] = []
    seen: set[int] = set()
    for sec in img.sections:
        if not sec.data:
            continue
        start = 0
        data = sec.data
        while len(out) < limit:
            i = data.find(substr, start)
            if i < 0:
                break
            s = i
            while s > 0 and data[s - 1] != 0 and i - s < 240:
                s -= 1
            va = sec.addr + s
            if va not in seen:
                seen.add(va)
                preview = data[s : s + 80].split(b"\0")[0]
                out.append((va, preview))
            start = i + 1
    return out


def _boost_for_substr(substr: str) -> int:
    best = 0
    low = substr.lower()
    for needle, score in _VALIDATE_BOOST.items():
        if needle.lower() in low or needle in substr:
            best = max(best, score)
    return best


def _fn_size(img, addr: Optional[int]) -> int:
    if addr is None:
        return 0
    try:
        b = function_covering(img, int(addr))
        if b:
            return max(0, b.end - b.start)
    except Exception:
        pass
    return 0


def _fn_entry(img, addr: Optional[int]) -> Optional[int]:
    if addr is None:
        return None
    try:
        b = function_covering(img, int(addr))
        if b:
            return int(b.start)
    except Exception:
        pass
    return None


def _is_bool_return_cmp(mnemonic: str, op_str: str) -> bool:
    """cmp eax/rax/al, 1 — not refcount-style cmp dword ptr [rax±off], 1."""
    if mnemonic != "cmp":
        return False
    ao = (op_str or "").lower().replace(" ", "")
    if ",1" not in ao and ",0x1" not in ao:
        return False
    # Reject memory operands that merely mention rax in an address.
    if "[" in ao:
        return False
    return ao.startswith(("eax,1", "eax,0x1", "rax,1", "rax,0x1", "al,1", "al,0x1"))


def _call_cmp_linked(insns: list, call_idx: int, cmp_idx: int) -> bool:
    """Return-value check must follow call closely — no unrelated control flow."""
    if cmp_idx <= call_idx or cmp_idx - call_idx > 4:
        return False
    for a in range(call_idx + 1, cmp_idx):
        m = insns[a].mnemonic
        if m in ("jmp", "ret", "call"):
            return False
    return True


def _ret_imm_target_ok(img, addr: int) -> bool:
    """ret_imm must land on a real entry, not a label mid-function."""
    entry = _fn_entry(img, addr)
    return entry is not None and int(entry) == int(addr)


def _scan_call_cmp1_gates(
    img,
    start: int,
    end: int,
    *,
    meta: Dict[str, Any],
    seen_gate: set[str],
) -> List[Dict[str, Any]]:
    """Find call → cmp eax/rax,1 → jcc; emit ret_imm on large callees + force_branch."""
    import capstone as cs

    out: List[Dict[str, Any]] = []
    if end <= start:
        return out
    length = min(0x1800, end - start)
    data = img.read_bytes(start, length)
    if not data:
        return out
    mode = cs.CS_MODE_64 if getattr(img, "bits", 64) == 64 else cs.CS_MODE_32
    md = cs.Cs(cs.CS_ARCH_X86, mode)
    md.detail = True
    insns = list(md.disasm(data, start))
    for n, insn in enumerate(insns):
        if insn.mnemonic != "call":
            continue
        ct = None
        try:
            if insn.operands and insn.operands[0].type == cs.x86.X86_OP_IMM:
                ct = int(insn.operands[0].imm)
        except Exception:
            ct = None
        cmp_i = None
        jcc_i = None
        for a in range(n + 1, min(len(insns), n + 6)):
            am = insns[a].mnemonic
            ao = insns[a].op_str or ""
            if _is_bool_return_cmp(am, ao):
                cmp_i = a
                continue
            if cmp_i is not None and am.startswith("j") and am not in ("jmp", "jecxz", "jrcxz"):
                jcc_i = a
                break
            if am in ("jmp", "ret", "call"):
                break
        if ct is None or cmp_i is None:
            continue
        if not _call_cmp_linked(insns, n, cmp_i):
            continue
        csz = _fn_size(img, ct)
        key = f"ret_imm:{hex(ct)}"
        if (
            _LARGE_FN <= csz <= _MAX_COVER_STUB
            and key not in seen_gate
            and _ret_imm_target_ok(img, ct)
        ):
            seen_gate.add(key)
            out.append(
                {
                    "kind": "ret_imm",
                    "addr": hex(ct),
                    "score": 460 + min(csz // 64, 40),
                    "ui_label_only": False,
                    "ret_guess": 1,
                    "reason": f"call→cmp==1 large callee size=0x{csz:x}",
                    "nearby_fn": meta.get("nearby_fn"),
                    "fn_start": meta.get("fn_start"),
                    "string_addr": meta.get("string_addr"),
                    "string_kind": meta.get("string_kind"),
                    "string_preview": meta.get("string_preview"),
                    "xref_addr": meta.get("xref_addr"),
                    "call_site": hex(insn.address),
                }
            )
        if jcc_i is not None:
            j = insns[jcc_i]
            jk = f"force_branch:{hex(j.address)}"
            if jk not in seen_gate:
                seen_gate.add(jk)
                if j.mnemonic in ("jne", "jnz"):
                    taken = False
                elif j.mnemonic in ("je", "jz"):
                    taken = True
                else:
                    taken = False
                out.append(
                    {
                        "kind": "force_branch",
                        "addr": hex(j.address),
                        "score": 430,
                        "ui_label_only": False,
                        "taken": taken,
                        "ret_guess": 1,
                        "reason": f"jcc after call→cmp==1 (taken={taken})",
                        "mnemonic": f"{j.mnemonic} {j.op_str}",
                        "nearby_fn": meta.get("nearby_fn"),
                        "fn_start": meta.get("fn_start"),
                        "string_addr": meta.get("string_addr"),
                        "string_kind": meta.get("string_kind"),
                        "string_preview": meta.get("string_preview"),
                        "xref_addr": meta.get("xref_addr"),
                    }
                )
    return out


def build_patch_plan(
    gates: List[Dict[str, Any]],
    *,
    max_steps: int = 5,
) -> List[Dict[str, Any]]:
    """
    Collapse ranked gates into an ordered apply plan:
    1) primary logic (large ret_imm or call+cmp/test force_branch)
    2) wire fail-jcc near same xref
    3) up to 2 UI-state force_branch gates
    """
    non_ui = [g for g in gates if not g.get("ui_label_only")]
    if not non_ui:
        # allow weakly-scored UI predicates if they still have taken polarity
        non_ui = [g for g in gates if g.get("kind") == "force_branch" and "taken" in g]

    plan: List[Dict[str, Any]] = []
    seen_addr: set[str] = set()

    def add(g: Dict[str, Any], why: str, priority: int) -> None:
        addr = str(g.get("addr") or "")
        mod = str(g.get("module") or "")
        key = f"{mod}:{addr}" if mod else addr
        if not addr or key in seen_addr:
            return
        if len(plan) >= max_steps:
            return
        seen_addr.add(key)
        step: Dict[str, Any] = {
            "kind": g.get("kind"),
            "addr": addr,
            "why": why,
            "priority": priority,
            "nearby_fn": g.get("nearby_fn"),
            "xref_addr": g.get("xref_addr"),
            "module": g.get("module"),
        }
        if g.get("kind") == "force_branch":
            step["taken"] = bool(g.get("taken", False))
        if g.get("kind") == "ret_imm":
            step["value"] = int(g.get("ret_guess") if g.get("ret_guess") is not None else 1)
        plan.append(step)

    # Primary: prefer call→cmp==1 large callee; never tiny parsers / giant UI shells
    primary = None
    for g in non_ui:
        if g.get("kind") != "ret_imm":
            continue
        reason = (g.get("reason") or "").lower()
        if "call→cmp==1 large callee" in reason:
            primary = g
            break
    if primary is None:
        for g in non_ui:
            if g.get("kind") != "ret_imm":
                continue
            reason = (g.get("reason") or "").lower()
            if "validate-covering" in reason:
                if "size=0x" in reason:
                    try:
                        hx = reason.split("size=0x", 1)[1].split()[0]
                        if int(hx, 16) > _MAX_COVER_STUB:
                            continue
                    except Exception:
                        pass
                primary = g
                break
    if primary is None:
        for g in non_ui:
            if g.get("kind") != "ret_imm":
                continue
            reason = (g.get("reason") or "").lower()
            if "stub callee" in reason and int(g.get("score") or 0) >= 400:
                primary = g
                break
    if primary is None:
        for g in non_ui:
            if g.get("kind") == "force_branch" and "call→cmp==1" in (g.get("reason") or ""):
                primary = g
                break
    if primary is None:
        for g in non_ui:
            if g.get("kind") == "force_branch" and g.get("string_kind") in ("validate", "query"):
                primary = g
                break
    if primary is None and non_ui:
        for g in non_ui:
            if g.get("kind") == "ret_imm" and int(g.get("score") or 0) < 200:
                continue
            primary = g
            break
        if primary is None:
            primary = non_ui[0]

    if primary:
        add(primary, primary.get("reason") or "primary license gate", 1)

    # Wire fail-jcc: same xref as primary, different addr, force_branch
    if primary and primary.get("kind") == "ret_imm":
        xref = primary.get("xref_addr")
        for g in non_ui:
            if g.get("kind") != "force_branch":
                continue
            if xref and g.get("xref_addr") != xref:
                # also accept same nearby_fn
                if g.get("nearby_fn") and g.get("nearby_fn") == primary.get("nearby_fn"):
                    pass
                else:
                    continue
            if "after call" in (g.get("reason") or "") or "after cmp" in (g.get("reason") or "") or "after test" in (
                g.get("reason") or ""
            ):
                add(g, g.get("reason") or "wire fail-jcc after validate", 2)
                break
        # fallback: any high-score force_branch near primary fn
        if len(plan) < 2:
            for g in non_ui:
                if g.get("kind") == "force_branch" and g.get("nearby_fn") == primary.get("nearby_fn"):
                    add(g, g.get("reason") or "wire jcc same fn", 2)
                    break

    # UI state gates: string_kind ui OR reason mentions unregistered-ish xref with predicate
    ui_added = 0
    for g in gates:
        if ui_added >= 2:
            break
        if g.get("kind") != "force_branch":
            continue
        sk = g.get("string_kind")
        preview = (g.get("string_preview") or "").lower()
        is_ui = sk == "ui" or any(
            x in preview for x in ("unregistered", "buy license", "trial", "purchase", "not registered")
        )
        if not is_ui:
            continue
        # Prefer non-ui_label_only; still allow if score decent after demotion
        if g.get("ui_label_only") and int(g.get("score") or 0) < 40:
            continue
        add(g, g.get("reason") or "UI license-state branch", 3 + ui_added)
        ui_added += 1

    return plan


def gate_scan(
    path: str,
    query: Optional[str] = None,
    *,
    limit: int = 16,
) -> Dict[str, Any]:
    """
    Universal license-check discovery for stripped or named binaries.
    Uses substring string recovery + one batched xref pass + patch_plan.
    """
    img = load_binary(path)
    module_path = str(path)
    hits: List[Dict[str, Any]] = []
    seen: set[int] = set()

    work: List[Tuple[bytes, str]] = [(s, "validate") for s in _VALIDATE_SUBS]
    if query:
        qb = query.encode("utf-8", errors="replace")
        if len(qb) >= 8 or (b" " in qb and len(qb) >= 5):
            work.append((qb, "query"))
        elif len(qb) >= 3:
            if b"_" in qb or any(c.isupper() for c in query):
                work.append((qb, "query"))
    work.extend((s, "ui") for s in _UI_SUBS)

    for substr, kind in work:
        cap = 4 if kind != "query" else 3
        for va, preview in _find_cstring_vas(img, substr, limit=cap):
            if va in seen:
                continue
            seen.add(va)
            hits.append(
                {
                    "addr": hex(va),
                    "preview": preview.decode("utf-8", errors="replace")[:80],
                    "kind": kind,
                    "substr": substr.decode("utf-8", errors="replace"),
                }
            )

    prefer = [h for h in hits if h["kind"] in ("validate", "query")]
    ui_hits = [h for h in hits if h["kind"] == "ui"]
    scan_hits = prefer[:14] + ui_hits[:4]
    targets = [int(h["addr"], 0) for h in scan_hits]
    hit_by_va = {int(h["addr"], 0): h for h in scan_hits}

    xref_map = find_string_xrefs_multi(img, targets, max_per_target=6) if targets else {}

    gates: List[Dict[str, Any]] = []
    seen_gate: set[str] = set()

    # Large covering functions of *specific* validate strings → ret_imm at fn start
    # Cap size: stubbing a 13KB UI shell (e.g. generic ACTIVATION) prevents launch.
    for sh in scan_hits:
        if sh.get("kind") not in ("validate", "query"):
            continue
        substr = sh.get("substr") or ""
        if substr not in _COVER_STUB_SUBS and not any(s in substr for s in _COVER_STUB_SUBS):
            continue
        sva = int(sh["addr"], 0)
        for xr in xref_map.get(sva) or []:
            try:
                xref_va = int(xr["addr"], 0)
            except (TypeError, ValueError):
                continue
            cov = function_covering(img, xref_va)
            if not cov:
                continue
            sz = cov.end - cov.start
            if sz < _LARGE_FN or sz > _MAX_COVER_STUB:
                continue
            key = f"ret_imm:{hex(cov.start)}"
            if key in seen_gate:
                continue
            seen_gate.add(key)
            score = 400 + _boost_for_substr(substr)
            if sz >= 0x1000:
                score += 20
            gates.append(
                {
                    "kind": "ret_imm",
                    "addr": hex(cov.start),
                    "score": score,
                    "ui_label_only": False,
                    "ret_guess": 1,
                    "reason": f"validate-covering fn size=0x{sz:x} substr={substr!r}",
                    "nearby_fn": cov.name,
                    "fn_start": hex(cov.start),
                    "string_addr": sh.get("addr"),
                    "string_kind": sh.get("kind"),
                    "string_preview": sh.get("preview"),
                    "xref_addr": xr["addr"],
                }
            )
            for c in suggest_patches_near(img, xref_va, window=256):
                ck = f"{c.get('kind')}:{c.get('addr')}"
                if ck in seen_gate:
                    continue
                seen_gate.add(ck)
                cc = dict(c)
                cc["score"] = int(cc.get("score") or 0) + 100
                cc["ui_label_only"] = bool(cc.get("ui_label_only"))
                if not cc["ui_label_only"]:
                    cc["score"] = int(cc["score"]) + 20
                cc["string_addr"] = sh.get("addr")
                cc["string_kind"] = sh.get("kind")
                cc["string_preview"] = sh.get("preview")
                cc["xref_addr"] = xr["addr"]
                cc["nearby_fn"] = cov.name
                cc["fn_start"] = hex(cov.start)
                gates.append(cc)

    for sva, xrefs in xref_map.items():
        sh = hit_by_va.get(sva) or {}
        val_boost = sh.get("kind") in ("validate", "query")
        ui_boost = sh.get("kind") == "ui"
        substr = sh.get("substr") or ""
        for xr in xrefs:
            try:
                xref_va = int(xr["addr"], 0)
            except (TypeError, ValueError):
                continue
            if xr.get("kind") == "absolute" and not xr.get("nearby_fn"):
                continue
            cands = suggest_patches_near(img, xref_va, window=128)
            cov = function_covering(img, xref_va)
            for c in cands:
                key = f"{c.get('kind')}:{c.get('addr')}"
                if key in seen_gate:
                    continue
                seen_gate.add(key)
                score = int(c.get("score") or 0)
                ui_only = bool(c.get("ui_label_only"))
                if ui_boost:
                    score -= 40
                    # Keep as UI candidate for patch_plan UI steps; mark ui_label_only
                    # only when no predicate
                    if ui_only:
                        score = max(score, 20)
                if val_boost and not ui_only:
                    score += 60
                    score += _boost_for_substr(substr)
                if val_boost and c.get("kind") == "force_branch" and not ui_only:
                    if "after call" in (c.get("reason") or "") or "after test" in (c.get("reason") or ""):
                        score += 30
                    if "cmp==1" in (c.get("reason") or "") or "cmp eax, 1" in (c.get("reason") or ""):
                        score += 40
                if val_boost and c.get("kind") == "ret_imm" and not ui_only:
                    score += 40
                    try:
                        tgt = int(str(c.get("addr")), 0)
                        if _fn_size(img, tgt) < _PARSER_FN:
                            score -= 80
                    except Exception:
                        pass
                # UI predicate branches (cmp byte / flag) near Unregistered-class strings
                if ui_boost and c.get("kind") == "force_branch" and not ui_only:
                    score += 50
                c = dict(c)
                if cov:
                    c["nearby_fn"] = cov.name
                    c["fn_start"] = hex(cov.start)
                c["score"] = score
                c["ui_label_only"] = ui_only
                c["string_addr"] = sh.get("addr")
                c["string_kind"] = sh.get("kind")
                c["string_preview"] = sh.get("preview")
                c["xref_addr"] = xr["addr"]
                gates.append(c)

    # Universal: inside validate-covering functions, find call→cmp==1→jcc (crypto gate)
    scanned_fns: set[int] = set()
    for sh in scan_hits:
        if sh.get("kind") not in ("validate", "query"):
            continue
        sva = int(sh["addr"], 0)
        for xr in xref_map.get(sva) or []:
            try:
                xref_va = int(xr["addr"], 0)
            except (TypeError, ValueError):
                continue
            cov = function_covering(img, xref_va)
            if not cov:
                continue
            meta = {
                "nearby_fn": cov.name,
                "fn_start": hex(cov.start),
                "string_addr": sh.get("addr"),
                "string_kind": sh.get("kind"),
                "string_preview": sh.get("preview"),
                "xref_addr": xr["addr"],
            }
            ranges = [(cov.start, cov.end)]
            # Tiny thunk (error dialog helper): scan preceding code for apply/wire fn
            if cov.end - cov.start < 0x80:
                ranges.append((max(0, xref_va - 0x800), xref_va + 0x40))
                ranges.append((max(0, cov.start - 0x800), cov.start + 0x40))
            for a0, a1 in ranges:
                key = (a0, a1)
                if key in scanned_fns:
                    continue
                scanned_fns.add(key)
                gates.extend(
                    _scan_call_cmp1_gates(img, a0, a1, meta=meta, seen_gate=seen_gate)
                )

    if _password_crackme_signals(img):
        pwd_gates = _password_crackme_gates(img, module_path)
        for g in pwd_gates:
            key = f"{g.get('kind')}:{g.get('addr')}"
            if key not in seen_gate:
                seen_gate.add(key)
                gates.append(g)
        if pwd_gates and not hits:
            for substr in _PASSWORD_SUBS[:3]:
                for va, preview in _find_cstring_vas(img, substr, limit=1):
                    hits.append(
                        {
                            "addr": hex(va),
                            "preview": preview.decode("utf-8", errors="replace")[:80],
                            "kind": "password",
                            "substr": substr.decode("utf-8", errors="replace"),
                        }
                    )

    gates.sort(key=lambda g: (-int(g.get("score") or 0), g.get("ui_label_only", True)))
    for g in gates:
        g["module"] = module_path
    # Keep a wider pool for plan building, then trim display list
    pool = gates[: max(limit * 2, 24)]
    gates_out = gates[:limit]
    non_ui = [g for g in gates_out if not g.get("ui_label_only")]
    patch_plan = build_patch_plan(pool, max_steps=5)
    for s in patch_plan:
        s.setdefault("module", module_path)

    if patch_plan:
        s0 = patch_plan[0]
        if s0.get("string_kind") == "password" or s0.get("nearby_fn") == "authenticate":
            next_hint = (
                f"PASSWORD crackme: argus_apply_plan patch_plan ({len(patch_plan)} steps); "
                f"first {s0.get('kind')} addr={s0.get('addr')} (authenticate stub). "
                f"Not a gate transform — behavior verify must pass."
            )
        else:
            next_hint = (
                f"APPLY: argus_apply_plan with patch_plan ({len(patch_plan)} steps); "
                f"first {s0.get('kind')} addr={s0.get('addr')}. "
                f"Do not freestyle-patch parser gates outside the plan. "
                f"Success = patch_bytes verify only (rodata Unregistered may remain)."
            )
    elif non_ui:
        pick = non_ui[0]
        next_hint = (
            f"No structured plan — try argus_apply_plan or patch "
            f"kind={pick.get('kind')} addr={pick.get('addr')} ui_label_only=false."
        )
    elif gates_out:
        next_hint = (
            "Only UI-ish gates — PIVOT: argus_discover / argus_slice modules= other DLL/SO; "
            "do not claim license removed."
        )
    else:
        next_hint = (
            "No license xrefs here — PIVOT: argus_discover then slice linked/candidates "
            "(gate often lives in a sibling .dll/.so), not only this binary."
        )

    return {
        "ok": True,
        "summary": (
            f"gate_scan strings={len(hits)} gates={len(gates_out)} "
            f"non_ui={len(non_ui)} plan={len(patch_plan)}"
        ),
        "string_hits": hits[:24],
        "gate_candidates": gates_out,
        "patch_plan": patch_plan,
        "suggested_stubs": [
            {
                "name": g.get("nearby_fn"),
                "addr": g.get("addr"),
                "value": g.get("ret_guess", 1),
            }
            for g in non_ui[:6]
            if g.get("kind") == "ret_imm"
        ],
        "next_hint": next_hint,
        "stripped_like": True,
        "module": module_path,
    }


def gate_scan_modules(
    primary: str,
    *,
    modules: Optional[List[str]] = None,
    query: Optional[str] = None,
    limit: int = 16,
    max_modules: int = 8,
    auto_widen: bool = True,
) -> Dict[str, Any]:
    """
    Slice primary + related modules; merge gates and build a cross-module patch_plan.
    If modules omitted, discover linked modules with license score > 0.
    If plan still empty and auto_widen: search nearby binaries (siblings / install dir).
    """
    from argus.discover import discover_targets, linked_modules, signal_score, resolve_link_base, widen_modules

    paths: List[str] = [primary]
    install_root: Optional[str] = None
    try:
        from argus.llm.session import get_session

        install_root = get_session().install_dir or None
    except Exception:
        pass
    link_primary = str(resolve_link_base(primary, install_root))
    if modules:
        for m in modules:
            if m and m not in paths:
                paths.append(m)
    else:
        disc = discover_targets(binary=link_primary, root=install_root, max_linked=max_modules)
        for m in disc.get("linked") or []:
            p = m.get("path")
            if p and int(m.get("score") or 0) > 0 and p not in paths:
                paths.append(p)
        if len(paths) == 1:
            for lp in linked_modules(link_primary, limit=max_modules):
                if str(lp) not in paths and signal_score(lp) > 0:
                    paths.append(str(lp))

    paths = paths[: max_modules + 1]
    all_gates: List[Dict[str, Any]] = []
    all_hits: List[Dict[str, Any]] = []
    per_module: List[Dict[str, Any]] = []
    pivoted = False
    widened_from: List[str] = []

    def _slice_into(mod_paths: List[str]) -> None:
        for p in mod_paths:
            if any(pm.get("module") == p for pm in per_module):
                continue
            try:
                d = gate_scan(p, query, limit=limit)
            except Exception as e:
                per_module.append({"module": p, "ok": False, "error": str(e)})
                continue
            per_module.append(
                {
                    "module": p,
                    "ok": True,
                    "summary": d.get("summary"),
                    "plan_len": len(d.get("patch_plan") or []),
                    "gates": len(d.get("gate_candidates") or []),
                }
            )
            for g in d.get("gate_candidates") or []:
                gg = dict(g)
                gg["module"] = p
                all_gates.append(gg)
            for h in d.get("string_hits") or []:
                hh = dict(h)
                hh["module"] = p
                all_hits.append(hh)

    _slice_into(paths)

    patch_plan = build_patch_plan(
        sorted(all_gates, key=lambda g: (-int(g.get("score") or 0), g.get("ui_label_only", True)))[
            :48
        ],
        max_steps=5,
    )

    # Pivot: nothing usable yet → widen to other nearby files
    if auto_widen and not patch_plan:
        extra = widen_modules(link_primary, tried=paths, limit=max_modules, root=install_root)
        extra_paths = [e["path"] for e in extra if e.get("path")]
        if extra_paths:
            pivoted = True
            widened_from = list(extra_paths)
            paths = list(dict.fromkeys(paths + extra_paths))[: max_modules + 1]
            _slice_into(extra_paths)
            all_gates.sort(key=lambda g: (-int(g.get("score") or 0), g.get("ui_label_only", True)))
            patch_plan = build_patch_plan(all_gates[:48], max_steps=5)

    for s in patch_plan:
        if not s.get("module"):
            for g in all_gates:
                if g.get("addr") == s.get("addr") and g.get("kind") == s.get("kind"):
                    s["module"] = g.get("module")
                    break
            s.setdefault("module", primary)

    non_ui = [g for g in all_gates[:limit] if not g.get("ui_label_only")]
    if patch_plan:
        s0 = patch_plan[0]
        pivot_note = f" (pivoted into {widened_from[0]})" if pivoted and widened_from else ""
        next_hint = (
            f"APPLY: argus_apply_plan patch_plan ({len(patch_plan)} steps); "
            f"first {s0.get('kind')} addr={s0.get('addr')} module={s0.get('module')}"
            f"{pivot_note}. Patches apply per-module."
        )
    elif pivoted:
        next_hint = (
            "Pivoted across nearby binaries — still no patch_plan. "
            "Call argus_discover for more candidates, or argus_slice with modules=[...] / another query."
        )
    else:
        next_hint = (
            "No patch_plan in primary/linked. "
            "PIVOT: argus_discover then argus_slice on other candidates "
            "(license often in DLL/SO), or pass modules=[]."
        )

    return {
        "ok": True,
        "summary": (
            f"gate_scan_modules modules={len(paths)} gates={len(all_gates[:limit])} "
            f"plan={len(patch_plan)}"
            + (" pivoted" if pivoted else "")
        ),
        "primary": primary,
        "modules": paths,
        "per_module": per_module,
        "pivoted": pivoted,
        "widened_from": widened_from,
        "string_hits": all_hits[:24],
        "gate_candidates": all_gates[:limit],
        "patch_plan": patch_plan,
        "next_hint": next_hint,
        "module": primary,
    }
