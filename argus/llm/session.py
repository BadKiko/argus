from __future__ import annotations

"""Per-agent-run session state for strict patch-plan gates."""

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


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


def record_gate_scan_result(binary: str, patch_plan: List[Dict[str, Any]]) -> None:
    sess = get_session()
    sess.last_slice_binary = binary
    sess.last_slice_patch_plan = list(patch_plan or [])
    sess.last_patch_plan_len = len(sess.last_slice_patch_plan)
