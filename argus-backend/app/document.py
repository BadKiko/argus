"""Build searchable document text from a case report."""

from __future__ import annotations

from app.models import CaseReport


def case_document(report: CaseReport) -> str:
    tools = " → ".join(s.tool for s in report.strategies[:12])
    failures = ", ".join(report.failure_modes[:5]) or "none"
    kinds = ",".join(report.task_kinds) or "general"
    pivoted = report.features.get("pivoted", False)
    return (
        f"format={report.format} arch={report.arch} protection={report.protection} "
        f"task={report.task[:200]} kinds={kinds}\n"
        f"strategy: {tools}\n"
        f"outcome={report.outcome.value} verification={report.verification_level.value} "
        f"pivoted={pivoted}\n"
        f"failure: {failures}"
    )


def hint_summary(report: CaseReport) -> str:
    tools = "+".join(s.tool.replace("argus_", "") for s in report.strategies[:4])
    extra = ""
    if report.features.get("pivoted"):
        extra = ", pivoted to linked module"
    if report.modules_patched:
        extra += f", patched {report.modules_patched[0]}"
    return f"{tools}{extra}"


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
