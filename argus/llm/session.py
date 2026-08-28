from __future__ import annotations

"""Per-agent-run session state for strict patch-plan gates."""

import os
from dataclasses import dataclass, field
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
    research_round: int = 0


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
    if sess.last_gate_scan_query != query:
        return None
    if sess.last_gate_scan_modules != _norm_modules(modules):
        return None
    if sess.last_gate_scan_multi != multi:
        return None
    return dict(sess.last_gate_scan_full)
