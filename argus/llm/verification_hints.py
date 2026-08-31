"""Universal verification gap hints — no vendor/product wording."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

_SINK_RX = re.compile(r"(?:call|dialog|error sink|reject)@(\s*0x[0-9a-fA-F]+)", re.IGNORECASE)


def _parse_addr(raw: Any) -> Optional[int]:
    if raw is None or raw == "":
        return None
    try:
        return int(raw, 0) if isinstance(raw, str) else int(raw)
    except (TypeError, ValueError):
        return None


def task_requires_outcome_change(task_text: str) -> bool:
    """True when the task likely needs validation/check outcome changed, not just launch."""
    from argus.llm.intent import is_bypass_license_task, task_signals

    text = (task_text or "").strip()
    if not text:
        return False
    if is_bypass_license_task(text):
        return True
    sig = task_signals(text)
    if sig.get("gate_transform", 0) >= 0.55:
        return True
    if re.search(
        r"(accept\s+any|any\s+\w+\s+key|reject|invalid|denied|bypass|unlock|register|trial|"
        r"without\s+error|must\s+not\s+appear|should\s+accept)",
        text,
        re.IGNORECASE,
    ):
        return True
    return False


def _parse_result(entry: Dict[str, Any]) -> Dict[str, Any]:
    raw = entry.get("result")
    if isinstance(raw, dict):
        return raw
    preview = entry.get("result_preview") or entry.get("result_json")
    if isinstance(preview, dict):
        return preview
    return {}


def patch_addrs_from_trace(tool_trace: List[Dict[str, Any]]) -> Set[int]:
    applied: Set[int] = set()
    for entry in tool_trace:
        tool = entry.get("tool") or ""
        payload = _parse_result(entry)
        if tool == "argus_apply_plan" and payload.get("ok"):
            for row in payload.get("applied") or []:
                if row.get("ok"):
                    a = _parse_addr(row.get("addr"))
                    if a is not None:
                        applied.add(a)
        elif tool == "argus_patch" and payload.get("ok"):
            a = _parse_addr((entry.get("args") or {}).get("addr"))
            if a is not None:
                applied.add(a)
    return applied


def diagnose_plan_addrs(tool_trace: List[Dict[str, Any]]) -> Set[int]:
    plan_addrs: Set[int] = set()
    for entry in tool_trace:
        if entry.get("tool") != "argus_diagnose_failure":
            continue
        payload = _parse_result(entry)
        if payload.get("ok") is not True:
            continue
        plan = (
            payload.get("corrective_patch")
            or (payload.get("evidence") or {}).get("corrective_patch")
            or []
        )
        for step in plan:
            a = _parse_addr(step.get("addr"))
            if a is not None:
                plan_addrs.add(a)
    return plan_addrs


def diagnose_sink_addrs(tool_trace: List[Dict[str, Any]]) -> Set[int]:
    """Addresses mentioned as error/dialog sinks in diagnose explanations."""
    sinks: Set[int] = set()
    for entry in tool_trace:
        if entry.get("tool") != "argus_diagnose_failure":
            continue
        payload = _parse_result(entry)
        blob = " ".join(
            str(x)
            for x in (
                payload.get("summary"),
                payload.get("explanation"),
                (payload.get("evidence") or {}).get("explanation"),
                (payload.get("evidence") or {}).get("root_cause"),
            )
            if x
        )
        for m in _SINK_RX.finditer(blob):
            a = _parse_addr(m.group(1))
            if a is not None:
                sinks.add(a)
    return sinks


def had_gui_launch_oracle_ok(tool_trace: List[Dict[str, Any]]) -> bool:
    for entry in tool_trace:
        if entry.get("tool") != "argus_gui_oracle":
            continue
        payload = _parse_result(entry)
        verify = payload.get("verify") or {}
        if verify.get("ok") is True or (payload.get("ok") is True and verify.get("ok") is not False):
            return True
    return False


def diagnose_coverage_detail(tool_trace: List[Dict[str, Any]]) -> Optional[str]:
    """Factual: corrective_patch sites not present in applied patches."""
    plan = diagnose_plan_addrs(tool_trace)
    if not plan:
        return None
    applied = patch_addrs_from_trace(tool_trace)
    missing = sorted(plan - applied)
    if not missing:
        return None
    covered = len(plan & applied)
    return (
        f"diagnose corrective_patch={len(plan)} sites, applied overlap={covered}, "
        f"missing={', '.join(hex(a) for a in missing[:8])}"
    )


def verification_gap_hint(
    tool_trace: List[Dict[str, Any]],
    task_text: str,
) -> str:
    """Observations for the planner when launch oracle != outcome change."""
    lines: List[str] = []
    if not task_requires_outcome_change(task_text):
        return ""

    if had_gui_launch_oracle_ok(tool_trace):
        lines.append(
            "verification_tier: gui_oracle=EXECUTION_VERIFIED only "
            "(idle launch: no crash, reject_texts not visible). "
            "Does NOT exercise the validation input path or prove check outcome changed."
        )

    cov = diagnose_coverage_detail(tool_trace)
    if cov:
        lines.append(f"patch_coverage_gap: {cov}")

    sinks = diagnose_sink_addrs(tool_trace)
    applied = patch_addrs_from_trace(tool_trace)
    if sinks and not sinks & applied:
        lines.append(
            "error_sink_coverage: diagnose named error/dialog sink(s) "
            f"{', '.join(hex(a) for a in sorted(sinks)[:4])} — "
            "none appear in applied patch addrs; pivot via argus_disasm/xrefs on sink "
            "or apply remaining corrective_patch steps."
        )

    if lines and had_gui_launch_oracle_ok(tool_trace):
        lines.append(
            "planner_note: launch smoke passing while outcome-change task open usually means "
            "wrong gate patched or incomplete chain — use diagnose corrective_patch + disasm, do not stop."
        )
    return "\n".join(lines)


def gate_outcome_verified(tool_trace: List[Dict[str, Any]], task_text: str) -> Tuple[bool, str]:
    """Stricter done gate for outcome-change tasks (actionable gaps only)."""
    if not task_requires_outcome_change(task_text):
        return True, ""
    cov = diagnose_coverage_detail(tool_trace)
    if cov:
        return False, f"patch_coverage_gap: {cov}"
    sinks = diagnose_sink_addrs(tool_trace)
    applied = patch_addrs_from_trace(tool_trace)
    if sinks and not sinks & applied:
        return (
            False,
            "error_sink_coverage: diagnose named sink(s) not covered by applied patch addrs",
        )
    return True, ""
