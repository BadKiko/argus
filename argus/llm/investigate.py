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


def rank_tool_suggestions(
    *,
    intent: TaskKind,
    analyze_ok: bool,
    find_ok: bool,
    slice_data: Optional[Dict[str, Any]],
    tools_tried: Optional[List[str]] = None,
    verify_ok: Optional[bool] = None,
) -> List[Dict[str, Any]]:
    """Ranked tool hints for the LLM — not executed automatically."""
    tried_list = list(tools_tried or [])
    tried = set(tried_list)
    plan = list((slice_data or {}).get("patch_plan") or [])
    conf = _plan_confidence(plan)
    out: List[Dict[str, Any]] = []

    def add(tool: str, reason: str, confidence: float) -> None:
        if any(x.get("tool") == tool for x in out):
            return
        out.append({"tool": tool, "reason": reason, "confidence": round(confidence, 2)})

    def seen(*names: str) -> bool:
        return any(n in tried for n in names)

    if not seen("argus_find", "argus_atlas"):
        add(
            "argus_find",
            "query= task nouns or an observed fragment (string_addr= maps callers)",
            0.82 if not plan else 0.52,
        )
    if find_ok and not plan and intent != TaskKind.PASSWORD:
        add(
            "argus_diagnose",
            "error_text= verbatim top find preview, then argus_apply from that plan",
            0.93,
        )
    if not seen("argus_look", "argus_discover") and not plan:
        add("argus_look", "empty patch_plan — classify host vs payload, list siblings", 0.5)
    if not plan:
        add("argus_find", "try query= from user task wording", 0.65)

    if conf in ("low", "none", "unknown") and plan:
        add("argus_diagnose", f"weak confidence={conf} — widen error_text or another module", 0.6)

    if verify_ok is False:
        add("argus_diagnose", "verify failed — error_text from sandbox/user verbatim", 0.85)
        if plan:
            add("argus_apply", "corrective steps from diagnose", 0.6)

    if plan and not seen("argus_apply", "argus_apply_plan") and intent != TaskKind.PASSWORD:
        add("argus_peek", "inspect gates before apply", 0.55)
        add("argus_apply", f"patch_plan ready ({len(plan)} steps, confidence={conf})", 0.7)

    out.sort(key=lambda x: x.get("confidence", 0), reverse=True)
    return out


def suggest_next_tool(
    *,
    intent: TaskKind,
    analyze_ok: bool,
    find_ok: bool,
    slice_data: Optional[Dict[str, Any]],
    tools_tried: Optional[List[str]] = None,
    verify_ok: Optional[bool] = None,
) -> Tuple[str, str]:
    """Legacy: first ranked suggestion."""
    ranked = rank_tool_suggestions(
        intent=intent,
        analyze_ok=analyze_ok,
        find_ok=find_ok,
        slice_data=slice_data,
        tools_tried=tools_tried,
        verify_ok=verify_ok,
    )
    if not ranked:
        return "argus_look", "no suggestions — argus_look then argus_find"
    top = ranked[0]
    return str(top.get("tool") or "argus_look"), str(top.get("reason") or "")


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
        observations.append(
            f"No string hits for query={find_q!r} — text may be constructed or query too generic"
        )
        hypotheses.append(
            "Observe runtime once (CLI banner / UI dialog) and pass that verbatim fragment to "
            "argus_find(query=) then argus_diagnose(error_text=). Do not assume an architecture."
        )

    if hits:
        preview = str(hits[0].get("preview") or "").strip().replace("\n", " ")[:80]
        hypotheses.append(
            f"Top hit is an observe fragment — argus_diagnose(error_text={preview!r}), "
            "then argus_apply. Do not invent force_branch."
        )

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
            hypotheses.append(
                "No gates near current query — argus_diagnose(error_text=find preview). "
                "Empty diagnose is not failure."
            )

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
    ranked = rank_tool_suggestions(
        intent=intent,
        analyze_ok=True,
        find_ok=bool(hits),
        slice_data=slice_data,
    )
    next_tool = ranked[0]["tool"] if ranked else "argus_look"
    next_reason = ranked[0]["reason"] if ranked else "investigate"

    if intent == TaskKind.GATE_TRANSFORM and slice_data.get("patch_plan"):
        hypotheses.append(
            "patch_plan is evidence only — inspect with argus_peek, then argus_apply (omit steps=)"
        )
    if intent == TaskKind.PASSWORD:
        hypotheses.append(
            "Task looks like password recovery — map the check with find/peek/run; do not invent the secret"
        )

    summary = (
        f"investigate {img.fmt}/{img.arch} plan={len(slice_data.get('patch_plan') or [])} "
        f"ranked_tools={len(ranked)}"
    )
    return {
        "ok": True,
        "summary": summary,
        "observations": observations,
        "hypotheses": hypotheses,
        "suggested_next_tool": next_tool,
        "suggested_next_reason": next_reason,
        "hints": {"suggested_tools": ranked},
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
        "next_hint": (
            f"plan_steps={len(slice_data.get('patch_plan') or [])} "
            f"ranked_tools={len(ranked)} top={next_tool}"
        ),
        "evidence": {
            "observations": observations,
            "hypotheses": hypotheses,
            "suggested_next_tool": next_tool,
        },
    }
