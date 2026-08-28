"""Anti-spam validation for case reports."""

from __future__ import annotations

import re
from typing import Set

from fastapi import HTTPException

from app.models import CaseReport

ALLOWED_TOOLS: Set[str] = {
    "argus_ai",
    "argus_analyze",
    "argus_detect",
    "argus_find",
    "argus_lift",
    "argus_patch",
    "argus_slice",
    "argus_unlock_apply",
    "argus_discover",
    "argus_cfg",
    "argus_deobf",
}

_PATH_RX = re.compile(
    r"(?:/home/|/Users/|/opt/|/var/|[A-Za-z]:\\)",
    re.IGNORECASE,
)


def validate_case_report(report: CaseReport) -> None:
    """Reject spam / malformed payloads with 422."""
    if _PATH_RX.search(report.task):
        raise HTTPException(status_code=422, detail="absolute paths not allowed in task")

    for key, val in report.features.items():
        if isinstance(val, str) and _PATH_RX.search(val):
            raise HTTPException(status_code=422, detail=f"absolute path in features.{key}")

    if not report.strategies:
        raise HTTPException(status_code=422, detail="strategies required")

    valid_tools = [s for s in report.strategies if s.tool in ALLOWED_TOOLS]
    if not valid_tools:
        raise HTTPException(status_code=422, detail="at least one argus_* strategy required")

    if len(report.task.strip()) < 3:
        raise HTTPException(status_code=422, detail="task too short")

    if report.format not in ("elf", "pe", "macho", "dex", "unknown"):
        raise HTTPException(status_code=422, detail="invalid format")

    if report.arch not in ("x86_64", "x86", "aarch64", "arm64", "arm", "unknown"):
        raise HTTPException(status_code=422, detail="invalid arch")

    if report.outcome.value == "success" and "unlock" in report.task_kinds:
        plan_sourced = getattr(report, "plan_sourced", None)
        if plan_sourced is None:
            plan_sourced = report.features.get("plan_sourced")
        if plan_sourced is False:
            raise HTTPException(
                status_code=422,
                detail="unlock success requires plan_sourced=true (slice unlock_plan + unlock_apply)",
            )
