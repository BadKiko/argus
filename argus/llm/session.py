from __future__ import annotations

"""Per-agent-run session state for strict patch-plan gates."""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def strict_plan_enabled() -> bool:
    return os.environ.get("ARGUS_STRICT_PLAN", "1").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )


@dataclass
class SessionContext:
    strict_plan: bool = True
    last_patch_plan_len: int = 0
    last_slice_patch_plan: List[Dict[str, Any]] = field(default_factory=list)
    last_slice_binary: str = ""
    last_gate_scan_full: Dict[str, Any] = field(default_factory=dict)
    last_gate_scan_query: Optional[str] = None
    last_gate_scan_modules: Tuple[str, ...] = ()
    last_gate_scan_multi: bool = True
    fauxware_loop_warned: bool = False
    original_binary: str = ""
    work_binary: str = ""
    install_dir: str = ""
    deploy_backups: Dict[str, str] = field(default_factory=dict)
    research_round: int = 0
    last_investigate: Dict[str, Any] = field(default_factory=dict)
    tools_tried: List[str] = field(default_factory=list)
    exec_calls: int = 0
    verified_plans: List[Dict[str, Any]] = field(default_factory=list)
    tool_trace: List[Dict[str, Any]] = field(default_factory=list)
    slice_repeat: int = 0
    last_slice_key: str = ""
    auto_pivot_done: bool = False
    gate_fast_path_done: bool = False
    user_task_text: str = ""
    logic_patch_counts: Dict[str, int] = field(default_factory=dict)


def _default_apply_batch() -> int:
    raw = os.environ.get("ARGUS_APPLY_BATCH", "1").strip()
    try:
        return max(1, int(raw))
    except ValueError:
        return 1


def _apply_fix_steps_enabled() -> bool:
    return os.environ.get("ARGUS_APPLY_FIX_STEPS", "1").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )


def max_research_rounds() -> int:
    raw = os.environ.get("ARGUS_MAX_RESEARCH_ROUNDS", "5").strip()
    try:
        return max(1, int(raw))
    except ValueError:
        return 5


def _slice_loop_limit() -> int:
    raw = os.environ.get("ARGUS_SLICE_LOOP_LIMIT", "2").strip()
    try:
        return max(1, int(raw))
    except ValueError:
        return 2


def _bin_key(path: str) -> str:
    try:
        return str(Path(path).resolve())
    except Exception:
        return str(path)


def note_slice_call(binary: str, query: Optional[str], plan_len: int) -> int:
    """Track repeated slice on same binary+query; return repeat count."""
    sess = get_session()
    key = f"{_bin_key(binary)}|{query or ''}"
    if key == sess.last_slice_key:
        sess.slice_repeat += 1
    else:
        sess.last_slice_key = key
        sess.slice_repeat = 1
    return sess.slice_repeat


def slice_loop_detected(binary: str, query: Optional[str]) -> bool:
    sess = get_session()
    key = f"{_bin_key(binary)}|{query or ''}"
    return key == sess.last_slice_key and sess.slice_repeat >= _slice_loop_limit()


def resolve_apply_steps(
    binary: str,
    steps: Optional[List[Dict[str, Any]]],
    *,
    max_steps: Optional[int] = None,
) -> tuple[Optional[List[Dict[str, Any]]], str, str]:
    """
    Resolve patch steps for apply_plan.
    Returns (steps, source, note) where source is explicit|session_slice|session_verified|missing.
    """
    batch = _default_apply_batch() if max_steps is None else max(1, int(max_steps))
    sess = get_session()

    if steps:
        explicit = list(steps)
        if (
            sess.last_slice_patch_plan
            and _apply_fix_steps_enabled()
            and sess.last_slice_binary
            and _bin_key(sess.last_slice_binary) == _bin_key(binary)
        ):
            from argus.apply_plan import _steps_subset_of_plan

            allowed = list(sess.last_slice_patch_plan) + get_verified_plan_steps()
            if allowed and not _steps_subset_of_plan(explicit, allowed, binary):
                fixed = allowed[:batch]
                return (
                    fixed,
                    "session_slice",
                    "model steps mismatched slice — using session patch_plan batch",
                )
        return explicit, "explicit", ""

    plan = list(sess.last_slice_patch_plan or [])
    if plan and sess.last_slice_binary and _bin_key(sess.last_slice_binary) == _bin_key(binary):
        return plan[:batch], "session_slice", f"auto from last argus_slice ({min(batch, len(plan))} step(s))"

    verified = get_verified_plan_steps()
    if verified:
        return verified[:batch], "session_verified", f"auto from verified plan ({min(batch, len(verified))} step(s))"

    return None, "missing", "run argus_slice first or pass steps="


_current: Optional[SessionContext] = None


def get_session() -> SessionContext:
    global _current
    if _current is None:
        _current = SessionContext(strict_plan=strict_plan_enabled())
    return _current


def reset_session(*, strict_plan: Optional[bool] = None) -> SessionContext:
    global _current
    _current = SessionContext(
        strict_plan=strict_plan if strict_plan is not None else strict_plan_enabled()
    )
    return _current


def add_verified_plan_steps(steps: List[Dict[str, Any]], *, replace: bool = False) -> None:
    """Record diagnose/slice plan. replace=True: latest diagnosis is the only session plan."""
    sess = get_session()
    clean = [s for s in (steps or []) if isinstance(s, dict)]
    if replace:
        sess.verified_plans = list(clean)
        return
    for s in clean:
        if s not in sess.verified_plans:
            sess.verified_plans.append(s)


def get_verified_plan_steps() -> List[Dict[str, Any]]:
    return list(get_session().verified_plans)


def _norm_modules(modules: Optional[List[str]]) -> Tuple[str, ...]:
    if not modules:
        return ()
    out: List[str] = []
    for m in modules:
        if m:
            out.append(str(m))
    return tuple(sorted(set(out)))


def record_gate_scan_result(
    binary: str,
    patch_plan: List[Dict[str, Any]],
    *,
    full: Optional[Dict[str, Any]] = None,
    query: Optional[str] = None,
    modules: Optional[List[str]] = None,
    multi: bool = True,
) -> None:
    sess = get_session()
    sess.last_slice_binary = binary
    sess.last_slice_patch_plan = list(patch_plan or [])
    sess.last_patch_plan_len = len(sess.last_slice_patch_plan)
    if full is not None:
        sess.last_gate_scan_full = dict(full)
        sess.last_gate_scan_query = query
        sess.last_gate_scan_modules = _norm_modules(modules)
        sess.last_gate_scan_multi = multi


def cached_gate_scan(
    binary: str,
    *,
    query: Optional[str] = None,
    modules: Optional[List[str]] = None,
    multi: bool = True,
) -> Optional[Dict[str, Any]]:
    """Reuse last argus_slice gate_scan_modules result in the same agent session."""
    sess = get_session()
    if not sess.last_gate_scan_full or sess.last_slice_binary != binary:
        return None
    if query is not None and sess.last_gate_scan_query != query:
        return None
    if modules is not None and sess.last_gate_scan_modules != _norm_modules(modules):
        return None
    if sess.last_gate_scan_multi != multi:
        return None
    return dict(sess.last_gate_scan_full)


def record_tool_call(name: str) -> None:
    sess = get_session()
    if name and name not in sess.tools_tried:
        sess.tools_tried.append(name)


def note_logic_patch_addr(addr: Optional[str]) -> int:
    """Count freestyle logic patches per VA; return new count."""
    key = str(addr or "").strip().lower()
    if not key:
        return 0
    sess = get_session()
    sess.logic_patch_counts[key] = sess.logic_patch_counts.get(key, 0) + 1
    return sess.logic_patch_counts[key]


def logic_patch_count(addr: Optional[str]) -> int:
    key = str(addr or "").strip().lower()
    if not key:
        return 0
    return int(get_session().logic_patch_counts.get(key, 0))


def has_session_plan() -> bool:
    sess = get_session()
    return bool(sess.last_slice_patch_plan) or bool(sess.verified_plans)


def record_investigate(binary: str, payload: Dict[str, Any]) -> None:
    sess = get_session()
    sess.last_investigate = {k: v for k, v in (payload or {}).items() if k != "_slice_full"}
    full = payload.get("_slice_full") or {}
    if full:
        record_gate_scan_result(
            binary,
            full.get("patch_plan") or [],
            full=full,
            query=(payload.get("find") or {}).get("query"),
            multi=True,
        )


def investigation_hint() -> str:
    """Factual hint from last investigate — not an imperative command."""
    sess = get_session()
    inv = sess.last_investigate
    if not inv:
        return ""
    slice_d = inv.get("slice") or {}
    plan_len = len(slice_d.get("patch_plan") or [])
    hits = (inv.get("find") or {}).get("hits") or []
    top = hits[0].get("preview") if hits else None
    parts = [f"last_investigate: patch_plan_steps={plan_len}"]
    if top:
        parts.append(f"top_hit={str(top)[:40]!r}")
    ranked = (inv.get("hints") or {}).get("suggested_tools") or []
    if ranked:
        parts.append(
            "suggested_tools: "
            + ", ".join(f"{x.get('tool')}({x.get('confidence')})" for x in ranked[:3])
        )
    return "Investigation context: " + "; ".join(parts)
