"""Build structured case reports from agent sessions."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from argus.memory.features import extract_binary_features

_GATE_SIGNAL_RX = re.compile(
    r"(unlock|license|лиценз|активац|register|unregistered|trial|serial|"
    r"restriction|entitlement|activation|verify|check|bypass|gate|"
    r"убери\s+про|remove\s+licen|transform)",
    re.IGNORECASE,
)
_PATCH_RX = re.compile(r"(patch|замен|replace|строк|text|title|ui)", re.IGNORECASE)
_LIFT_RX = re.compile(r"(lift|deobf|cff|unpack|декомп)", re.IGNORECASE)

from argus.llm.tools import ARGUS_TOOLS

_ARGUS_TOOLS = {
    t["function"]["name"]
    for t in ARGUS_TOOLS
    if isinstance(t, dict) and isinstance(t.get("function"), dict) and t["function"].get("name")
}
_ARGUS_TOOLS.update(
    {
        "argus_apply_plan",
        "argus_diagnose_failure",
        "argus_slice",
        "argus_gui_oracle",
        "argus_atlas",
        "argus_disasm",
        "argus_lift",
        "argus_cfg",
        "argus_ai",
        "argus_deobf",
        "argus_discover",
        "argus_analyze",
        "argus_investigate",
        "argus_patch",
        "argus_xrefs",
        "argus_decision_flow",
        "argus_research",
        "argus_detect",
        "argus_sandbox_test",
        "argus_state_flags",
    }
)


def _task_kinds(task: str) -> List[str]:
    kinds: List[str] = []
    if _GATE_SIGNAL_RX.search(task):
        kinds.append("gate_transform")
    if _PATCH_RX.search(task):
        kinds.append("patch")
    if _LIFT_RX.search(task):
        kinds.append("lift")
    if not kinds:
        kinds.append("general")
    return kinds


def _parse_trace_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    raw = entry.get("result")
    payload: Dict[str, Any] = {}
    if isinstance(raw, dict):
        payload = raw
    elif isinstance(raw, str):
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = {}
    tool = entry.get("tool") or entry.get("name") or ""
    verify = payload.get("verify") or {}
    return {
        "tool": tool,
        "ok": payload.get("ok"),
        "summary": (payload.get("summary") or "")[:200],
        "verify_kind": verify.get("kind") if isinstance(verify, dict) else None,
    }


def _plan_sourced(tool_trace: List[Dict[str, Any]]) -> bool:
    had_slice_plan, _ = _slice_plan_len(tool_trace)
    if not had_slice_plan:
        return False
    for entry in tool_trace:
        if entry.get("tool") != "argus_apply_plan":
            continue
        raw = entry.get("result")
        payload: Dict[str, Any] = {}
        if isinstance(raw, dict):
            payload = raw
        elif isinstance(raw, str):
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                continue
        ps = payload.get("plan_source") or (payload.get("evidence") or {}).get("plan_source")
        if ps == "slice" and payload.get("ok") is True:
            return True
    return False


def _slice_plan_len(tool_trace: List[Dict[str, Any]]) -> Tuple[bool, int]:
    best = 0
    for entry in tool_trace:
        if entry.get("tool") != "argus_slice":
            continue
        raw = entry.get("result")
        payload: Dict[str, Any] = {}
        if isinstance(raw, dict):
            payload = raw
        elif isinstance(raw, str):
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                continue
        plan = payload.get("patch_plan") or (payload.get("evidence") or {}).get("patch_plan") or []
        if isinstance(plan, list):
            best = max(best, len(plan))
    return best > 0, best


def _verification_level(tool_trace: List[Dict[str, Any]], task_statuses: List[Dict[str, Any]]) -> str:
    for entry in reversed(tool_trace):
        payload: Dict[str, Any] = {}
        raw = entry.get("result")
        if isinstance(raw, dict):
            payload = raw
        elif isinstance(raw, str):
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                continue
        verify = payload.get("verify") or {}
        if verify.get("ok") is not True:
            continue
        kind = verify.get("kind") or ""
        if kind == "patch_composite":
            behavior = verify.get("patch_behavior") or {}
            if behavior.get("ran") and behavior.get("ok") is True:
                return "BEHAVIOR_VERIFIED"
            bytes_v = verify.get("patch_bytes") or {}
            if bytes_v.get("ok") is True:
                return "BYTES_VERIFIED"
        if kind == "patch_bytes":
            return "BYTES_VERIFIED"
        cert = payload.get("certificate") or {}
        if isinstance(cert, dict) and cert.get("proven"):
            return "FORMALLY_VERIFIED"
        if kind in ("behavioral", "concrete"):
            return "BEHAVIOR_VERIFIED"
    return "UNKNOWN"


def _outcome(task_statuses: List[Dict[str, Any]], tool_trace: List[Dict[str, Any]]) -> str:
    if not task_statuses:
        return "incomplete"
    if all(s.get("status") == "done" for s in task_statuses):
        gate_task = any("gate_transform" in _task_kinds(s.get("text") or "") for s in task_statuses)
        if gate_task and not _plan_sourced(tool_trace):
            return "incomplete"
        return "success"
    if any(s.get("status") == "failed" for s in task_statuses):
        return "failed"
    return "incomplete"


def _failure_modes(tool_trace: List[Dict[str, Any]], task_statuses: List[Dict[str, Any]]) -> List[str]:
    modes: List[str] = []
    for s in task_statuses:
        if s.get("status") in ("failed", "incomplete"):
            detail = s.get("detail") or ""
            if detail:
                modes.append(detail[:200])
    for entry in tool_trace:
        step = _parse_trace_entry(entry)
        if step.get("ok") is False and step.get("summary"):
            modes.append(step["summary"])
    return modes[:8]


def _modules_patched(tool_trace: List[Dict[str, Any]]) -> List[str]:
    names: List[str] = []
    for entry in tool_trace:
        raw = entry.get("result")
        payload: Dict[str, Any] = {}
        if isinstance(raw, dict):
            payload = raw
        elif isinstance(raw, str):
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                continue
        plan = payload.get("patch_plan") or []
        for s in plan:
            mod = s.get("module")
            if mod:
                from pathlib import Path

                names.append(Path(str(mod)).name)
        paths = payload.get("patched_paths") or []
        for p in paths:
            from pathlib import Path

            names.append(Path(str(p)).name)
    return list(dict.fromkeys(names))[:8]


def build_case_report(
    binary: str,
    task: str,
    tool_trace: List[Dict[str, Any]],
    task_statuses: List[Dict[str, Any]],
    *,
    discover: Optional[dict] = None,
    steps: int = 0,
    outcome_override: Optional[str] = None,
    user_feedback: str = "",
    user_confirmed: bool = False,
    runtime_launch: Optional[Dict[str, Any]] = None,
    planner: str = "llm",
) -> Optional[Dict[str, Any]]:
    strategies = [_parse_trace_entry(e) for e in tool_trace]
    strategies = [s for s in strategies if s.get("tool") in _ARGUS_TOOLS]
    if not strategies:
        return None

    feats = extract_binary_features(binary, discover=discover)
    features = dict(feats.get("features") or {})
    if any(
        isinstance(e.get("result"), str) and "pivoted" in str(e.get("result"))
        for e in tool_trace
    ):
        features["pivoted"] = True
    for entry in tool_trace:
        raw = entry.get("result")
        if isinstance(raw, str) and '"pivoted": true' in raw.replace(" ", ""):
            features["pivoted"] = True
            break

    plan_sourced = _plan_sourced(tool_trace)
    features["plan_sourced"] = plan_sourced
    features["planner"] = planner
    tool_sequence = [
        str(e.get("tool") or "")
        for e in tool_trace
        if str(e.get("tool") or "").startswith("argus_")
    ]
    if tool_sequence:
        features["tool_sequence"] = tool_sequence
    if user_confirmed:
        features["user_confirmed"] = True
    if user_feedback:
        features["user_feedback"] = user_feedback[:500]
    if runtime_launch:
        features["runtime_launch"] = {
            k: runtime_launch[k]
            for k in (
                "exit_code",
                "stderr",
                "stdout",
                "detail",
                "error_kind",
                "cwd",
                "ld_library_path",
                "patched_path",
            )
            if k in runtime_launch and runtime_launch[k] not in (None, "")
        }

    verification_level = _verification_level(tool_trace, task_statuses)
    outcome = outcome_override or _outcome(task_statuses, tool_trace)
    failure_modes = _failure_modes(tool_trace, task_statuses)
    if runtime_launch:
        rk = runtime_launch.get("error_kind") or "launch"
        detail = runtime_launch.get("detail") or runtime_launch.get("stderr") or ""
        exit_code = runtime_launch.get("exit_code")
        prefix = f"runtime {rk}"
        if exit_code is not None:
            prefix += f" exit={exit_code}"
        if detail:
            prefix += f": {str(detail)[:160]}"
        failure_modes = [prefix] + failure_modes
    if user_feedback and outcome in ("failed", "incomplete"):
        failure_modes = [user_feedback[:200]] + failure_modes
        failure_modes = failure_modes[:8]

    return {
        "binary_hash": feats["binary_hash"],
        "binary_name": feats["binary_name"],
        "format": feats["format"],
        "arch": feats["arch"],
        "protection": feats["protection"],
        "features": features,
        "task": task[:500],
        "task_kinds": _task_kinds(task),
        "strategies": strategies,
        "outcome": outcome,
        "plan_sourced": plan_sourced,
        "verification_level": verification_level,
        "failure_modes": failure_modes[:8],
        "cost": {"steps": steps, "tool_calls": len(tool_trace), "planner": planner},
        "modules_patched": _modules_patched(tool_trace),
        "client_version": feats["client_version"],
    }
