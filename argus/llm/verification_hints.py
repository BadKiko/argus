"""Universal verification gap hints — no vendor/product wording."""

from __future__ import annotations

import json
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


def _is_apply_entry(entry: Dict[str, Any]) -> bool:
    return (entry.get("tool") or "") in ("argus_apply_plan", "argus_apply")


def _is_diagnose_entry(entry: Dict[str, Any]) -> bool:
    return (entry.get("tool") or "") in ("argus_diagnose_failure", "argus_diagnose")


def _is_gui_oracle_entry(entry: Dict[str, Any]) -> bool:
    tool = entry.get("tool") or ""
    if tool == "argus_gui_oracle":
        return True
    if tool == "argus_run":
        args = entry.get("args") or {}
        return bool(args.get("reject_texts") or args.get("main_window_hint"))
    return False


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
    if isinstance(raw, str) and raw.strip().startswith("{"):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass
    preview = entry.get("result_preview") or entry.get("result_json")
    if isinstance(preview, dict):
        return preview
    if isinstance(preview, str) and preview.strip().startswith("{"):
        try:
            parsed = json.loads(preview)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass
    return {}


def patch_addrs_from_trace(tool_trace: List[Dict[str, Any]]) -> Set[int]:
    applied: Set[int] = set()
    for entry in tool_trace:
        tool = entry.get("tool") or ""
        payload = _parse_result(entry)
        if _is_apply_entry(entry):
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
        if not _is_diagnose_entry(entry):
            continue
        payload = _parse_result(entry)
        if payload.get("ok") is not True:
            continue
        plan = (
            payload.get("corrective_patch")
            or (payload.get("evidence") or {}).get("corrective_patch")
            or payload.get("patch_plan")
            or (payload.get("evidence") or {}).get("patch_plan")
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
        if not _is_diagnose_entry(entry):
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
        if not _is_gui_oracle_entry(entry):
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


def _needle_in(haystack: str, needle: str) -> bool:
    n = (needle or "").lower().strip()
    t = (haystack or "").lower()
    if len(n) < 8 or not t:
        return False
    if n in t:
        return True
    head = n.split("%")[0].strip(" :\t")
    return len(head) >= 8 and head in t


def _exec_stdouts(tool_trace: List[Dict[str, Any]]) -> List[Tuple[int, str]]:
    out: List[Tuple[int, str]] = []
    for i, entry in enumerate(tool_trace):
        if entry.get("tool") != "argus_exec":
            continue
        payload = _parse_result(entry)
        stdout = str(
            (payload.get("evidence") or {}).get("stdout")
            or payload.get("stdout")
            or ""
        )
        if stdout.strip():
            out.append((i, stdout))
    return out


def _diagnose_needles(tool_trace: List[Dict[str, Any]]) -> List[str]:
    needles: List[str] = []
    seen: Set[str] = set()
    for entry in tool_trace:
        if not _is_diagnose_entry(entry):
            continue
        et = str((entry.get("args") or {}).get("error_text") or "").strip()
        if len(et) < 8:
            continue
        key = et.lower()
        if key in seen:
            continue
        seen.add(key)
        needles.append(et)
    return needles


def _apply_indices_with_bytes(tool_trace: List[Dict[str, Any]]) -> List[int]:
    idxs: List[int] = []
    for i, entry in enumerate(tool_trace):
        if not _is_apply_entry(entry):
            continue
        payload = _parse_result(entry)
        applied = payload.get("applied") or []
        if any(isinstance(a, dict) and a.get("ok") for a in applied) or payload.get("ok") is True:
            idxs.append(i)
    return idxs


def cli_reject_cleared(tool_trace: List[Dict[str, Any]]) -> Tuple[bool, str]:
    """True when a diagnose reject fragment was in stdout before patch and gone after."""
    needles = _diagnose_needles(tool_trace)
    execs = _exec_stdouts(tool_trace)
    applies = _apply_indices_with_bytes(tool_trace)
    if not needles or not execs or not applies:
        return False, ""
    apply_i = applies[-1]
    early = [(i, s) for i, s in execs if i <= apply_i]
    late = [(i, s) for i, s in execs if i > apply_i]
    if not early or not late:
        return False, ""
    last = late[-1][1]
    for needle in needles:
        frag = needle.strip()[:80]
        if len(frag) < 8:
            continue
        if not any(_needle_in(s, frag) for _, s in early):
            continue
        if not _needle_in(last, frag):
            return True, f"CLI reject {needle[:48]!r} gone from stdout after patch"
    return False, ""


def looks_post_patch_success_banner(error_text: str, tool_trace: List[Dict[str, Any]]) -> bool:
    """True when error_text showed up in stdout only after a patch (new banner, not reject)."""
    needle = (error_text or "").strip().lower()[:80]
    if len(needle) < 8:
        return False
    execs = _exec_stdouts(tool_trace)
    applies = _apply_indices_with_bytes(tool_trace)
    if len(execs) < 2 or not applies:
        return False
    apply_i = applies[0]
    early = [s for i, s in execs if i <= apply_i]
    late = [s for i, s in execs if i > apply_i]
    if not early or not late:
        return False
    if any(_needle_in(s, needle) for s in early):
        return False
    return any(_needle_in(s, needle) for s in late)


def gate_outcome_verified(tool_trace: List[Dict[str, Any]], task_text: str) -> Tuple[bool, str]:
    """Stricter done gate for outcome-change tasks (actionable gaps only)."""
    if not task_requires_outcome_change(task_text):
        return True, ""
    cli_ok, cli_detail = cli_reject_cleared(tool_trace)
    if cli_ok:
        return True, cli_detail
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
