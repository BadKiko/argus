"""Build searchable document text from a case report."""

from __future__ import annotations

from app.models import CaseReport


def case_document(report: CaseReport) -> str:
    seq = report.features.get("tool_sequence")
    if isinstance(seq, list) and seq:
        tools = " → ".join(str(t).replace("argus_", "") for t in seq[:12])
    else:
        tools = " → ".join(s.tool.replace("argus_", "") for s in report.strategies[:12])
    failures = ", ".join(report.failure_modes[:5]) or "none"
    kinds = ",".join(report.task_kinds) or "general"
    pivoted = report.features.get("pivoted", False)
    planner = str(report.features.get("planner") or "llm")
    return (
        f"format={report.format} arch={report.arch} protection={report.protection} "
        f"task={report.task[:200]} kinds={kinds}\n"
        f"investigation_path: {tools}\n"
        f"outcome={report.outcome.value} verification={report.verification_level.value} "
        f"pivoted={pivoted} planner={planner}\n"
        f"failure: {failures}"
    )


def hint_summary(report: CaseReport) -> str:
    seq = report.features.get("tool_sequence")
    if isinstance(seq, list) and seq:
        tools = "→".join(str(t).replace("argus_", "") for t in seq[:6])
    else:
        tools = "+".join(s.tool.replace("argus_", "") for s in report.strategies[:4])
    extra = ""
    if report.features.get("pivoted"):
        extra = ", pivoted"
    if report.features.get("planner") == "fast_path_legacy":
        extra += ", fast_path_legacy"
    return f"path:{tools}{extra}"


def query_document(
    *,
    format: str,
    arch: str,
    protection: str,
    task: str,
    task_kinds: list[str] | None = None,
) -> str:
    kinds = ",".join(task_kinds or []) or "general"
    return (
        f"format={format} arch={arch} protection={protection} "
        f"task={task[:200]} kinds={kinds}"
    )
