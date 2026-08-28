from __future__ import annotations

"""Investigation orchestrator: observe → hypothesize → suggest next tool."""

from typing import Any, Dict, List, Optional, Tuple

from argus.llm.intent import TaskKind, classify_task_intent


def _top_string_hits(find_payload: Dict[str, Any], *, limit: int = 4) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for h in find_payload.get("hits") or []:
        if isinstance(h, dict) and h.get("addr"):
            out.append(h)
    if out:
        return out[:limit]
    for h in (find_payload.get("evidence") or {}).get("hits") or []:
        if isinstance(h, dict) and h.get("addr"):
            out.append(h)
    return out[:limit]


def _plan_confidence(plan: List[Dict[str, Any]]) -> str:
    if not plan:
        return "none"
    p0 = plan[0]
    return str(p0.get("confidence") or "unknown")


def suggest_next_tool(
    *,
    intent: TaskKind,
    analyze_ok: bool,
    find_ok: bool,
    slice_data: Optional[Dict[str, Any]],
    tools_tried: Optional[List[str]] = None,
    verify_ok: Optional[bool] = None,
) -> Tuple[str, str]:
    """Return (tool_name, reason)."""
    tried = set(tools_tried or [])
    plan = list((slice_data or {}).get("patch_plan") or [])
    conf = _plan_confidence(plan)

    if intent == TaskKind.PASSWORD:
        if "argus_ai" not in tried and "argus_solve" not in tried:
            return "argus_ai", "password/crackme — try NL solve or argus_solve"
        if plan and "argus_apply_plan" not in tried:
            return "argus_apply_plan", "slice plan available for authenticate stub"
        return "argus_research", "password path stuck — research alternate strategy"

    if not slice_data and "argus_slice" not in tried:
        return "argus_slice", "no gate scan yet — map strings→xrefs→gates (multi=true)"

    if not plan:
        if "argus_discover" not in tried:
            return "argus_discover", "empty patch_plan — find linked modules in install dir"
        return "argus_slice", "re-slice with modules= from discover or different query"

    if conf in ("low", "none", "unknown") and "argus_slice" in tried:
        return "argus_slice", f"weak plan confidence={conf} — scan linked SO/DLL (multi, modules=)"

    if verify_ok is False:
        return "argus_research", "verify failed — rethink hypothesis before re-patch"

    if plan and "argus_apply_plan" not in tried:
        return "argus_apply_plan", f"patch_plan ready ({len(plan)} steps, confidence={conf})"

    if "argus_xrefs" not in tried and find_ok:
        return "argus_xrefs", "inspect xrefs on top string hit before freestyle patch"

    return "argus_research", "gather more evidence or pivot module"


def run_investigate(
    binary: str,
    query: str = "",
    *,
    original_binary: Optional[str] = None,
    discover: Optional[Dict[str, Any]] = None,
    task_text: str = "",
) -> Dict[str, Any]:
    """Run analyze + find + slice preview; return structured investigation report."""
    from argus.binary import load_binary
    from argus.deobf import detect_protection
    from argus.find import find_in_binary
    from argus.find_slice import gate_scan_modules, patch_site_previews, plan_is_confident
    from argus.find import find_string_xrefs, suggest_patches_near

    observations: List[str] = []
    hypotheses: List[str] = []
    xref_previews: List[Dict[str, Any]] = []

    # --- analyze ---
    img = load_binary(binary)
    prot = detect_protection(img)
    sym_count = sum(1 for s in img.symbols.values() if s.is_function and not s.is_import)
    observations.append(
        f"Binary {img.fmt}/{img.arch} entry={hex(img.entry)} protection={prot.kind} symbols≈{sym_count}"
    )
    if prot.kind not in ("none", "stripped", "unknown"):
        hypotheses.append(f"Protection {prot.kind} may block naive patch — consider deobf/solve path")

    # --- find ---
    find_q = (query or task_text or "").strip()[:120]
    found = find_in_binary(binary, find_q or None)
    hits = _top_string_hits(found)
    if hits:
        observations.append(
            "Top string hits: "
            + "; ".join(f"{h.get('addr')} {str(h.get('preview') or '')[:40]!r}" for h in hits[:3])
        )
    else:
        observations.append("No strong string hits from find — binary may be stripped or query mismatch")
        hypotheses.append("Try argus_slice with explicit query= from user task wording")

    stripped_like = bool(found.get("stripped_like"))
    if stripped_like:
        hypotheses.append("Stripped-like — prefer slice/xrefs over symbol names")

    # --- slice (multi-module aware) ---
    slice_data: Dict[str, Any] = {}
    try:
        slice_data = gate_scan_modules(binary, query=find_q or None, auto_widen=True, max_modules=6)
    except Exception as e:
        observations.append(f"gate_scan_modules error: {e}")
    else:
        plan = list(slice_data.get("patch_plan") or [])
        gates = slice_data.get("gate_candidates") or []
        non_ui = [g for g in gates if not g.get("ui_label_only")]
        observations.append(
            f"Gate scan: modules={len(slice_data.get('per_module') or [])} "
            f"gates={len(gates)} non_ui={len(non_ui)} plan={len(plan)}"
        )
        if plan:
            p0 = plan[0]
            observations.append(
                f"Primary plan: {p0.get('kind')} addr={p0.get('addr')} "
                f"module={p0.get('module')} confidence={p0.get('confidence')}"
            )
            previews = slice_data.get("patch_site_previews") or patch_site_previews(plan)
            if previews and previews[0].get("disasm"):
                observations.append("Disasm @ primary: " + " | ".join(previews[0]["disasm"][:3]))
        if plan and not plan_is_confident(plan):
            hypotheses.append(
                "Primary plan confidence low — real gate may live in linked module; widen modules="
            )
        elif not plan and non_ui:
            hypotheses.append("Gates exist but no plan — inspect force_branch candidates via xrefs")
        elif not plan:
            hypotheses.append("No gates in primary+linked — argus_discover then slice other candidates")

    # --- xrefs on best hit ---
    if hits:
        try:
            va = int(str(hits[0]["addr"]), 0)
            xrefs = find_string_xrefs(img, va, max_hits=4)
            for xr in xrefs[:2]:
                xa = int(xr["addr"], 0)
                cands = suggest_patches_near(img, xa, window=128)[:3]
                xref_previews.append(
                    {
                        "string_addr": hex(va),
                        "xref": xr,
                        "patch_candidates": cands,
                    }
                )
            if xrefs:
                observations.append(f"Xrefs to top hit {hex(va)}: {len(xrefs)} code sites")
        except (TypeError, ValueError):
            pass

    intent = classify_task_intent(task_text or query, binary=original_binary or binary, discover=discover)
    next_tool, next_reason = suggest_next_tool(
        intent=intent,
        analyze_ok=True,
        find_ok=bool(hits),
        slice_data=slice_data,
    )

    if intent == TaskKind.GATE_TRANSFORM and slice_data.get("patch_plan"):
        hypotheses.append("Gate transform path: argus_apply_plan with slice patch_plan only (no invented steps)")
    if intent == TaskKind.PASSWORD:
        hypotheses.append("Password task: argus_ai / argus_solve — not gate_transform apply_plan unless authenticate stub")

    summary = (
        f"investigate {img.fmt}/{img.arch} plan={len(slice_data.get('patch_plan') or [])} "
        f"→ next={next_tool}"
    )
    return {
        "ok": True,
        "summary": summary,
        "observations": observations,
        "hypotheses": hypotheses,
        "suggested_next_tool": next_tool,
        "suggested_next_reason": next_reason,
        "intent": intent.value,
        "analyze": {
            "fmt": img.fmt,
            "arch": img.arch,
            "entry": hex(img.entry),
            "protection": prot.kind,
            "symbol_functions": sym_count,
        },
        "find": {
            "query": find_q,
            "hits": hits,
            "stripped_like": stripped_like,
            "gate_candidates": (found.get("gate_candidates") or [])[:6],
        },
        "slice": {
            "summary": slice_data.get("summary"),
            "patch_plan": slice_data.get("patch_plan") or [],
            "patch_site_previews": slice_data.get("patch_site_previews") or [],
            "per_module": slice_data.get("per_module") or [],
            "next_hint": slice_data.get("next_hint"),
            "plan_confident": plan_is_confident(slice_data.get("patch_plan") or []),
            "modules": slice_data.get("modules") or [],
        },
        "_slice_full": slice_data,
        "xref_previews": xref_previews,
        "next_hint": f"Call {next_tool}: {next_reason}",
        "evidence": {
            "observations": observations,
            "hypotheses": hypotheses,
            "suggested_next_tool": next_tool,
        },
    }
