"""Interactive agent UI helpers."""

from __future__ import annotations

from argus.cli.agent_ui import build_retry_prompt
from argus.llm.agent import AgentResult
from argus.memory.case import build_case_report


def test_build_retry_prompt_includes_feedback():
    res = AgentResult(
        ok=False,
        answer="",
        tool_trace=[
            {"tool": "argus_slice", "args": {"binary": "x"}, "result": {"ok": True}},
        ],
    )
    p = build_retry_prompt("remove license", "still prompts for password", res)
    assert "remove license" in p
    assert "still prompts" in p
    assert "argus_slice" in p


def test_user_confirmed_success_overrides_outcome():
    from pathlib import Path

    fw = Path(__file__).resolve().parents[1] / "samples" / "fauxware"
    if not fw.is_file():
        return
    trace = [
        {
            "tool": "argus_patch",
            "result": {"ok": True, "verify": {"kind": "none"}},
        }
    ]
    statuses = [{"id": 1, "text": "patch ui", "status": "incomplete", "detail": "no verify"}]
    report = build_case_report(
        str(fw),
        "patch ui",
        trace,
        statuses,
        outcome_override="success",
        user_confirmed=True,
        user_feedback="",
    )
    assert report is not None
    assert report["outcome"] == "success"
    assert report["features"].get("user_confirmed") is True


def test_user_feedback_on_failure():
    from pathlib import Path

    fw = Path(__file__).resolve().parents[1] / "samples" / "fauxware"
    if not fw.is_file():
        return
    report = build_case_report(
        str(fw),
        "unlock",
        [{"tool": "argus_slice", "result": {"ok": True, "unlock_plan": []}}],
        [{"id": 1, "text": "unlock", "status": "incomplete", "detail": "empty plan"}],
        outcome_override="failed",
        user_feedback="Go away still prints",
        user_confirmed=True,
    )
    assert report is not None
    assert report["outcome"] == "failed"
    assert "Go away" in report["features"].get("user_feedback", "")
