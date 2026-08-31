"""Static compliance checks for Argus 0.5 architecture."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8", errors="replace")


def test_agent_no_next_action_in_bootstrap():
    from pathlib import Path

    faux = Path(__file__).resolve().parents[1] / "samples" / "fauxware"
    if not faux.is_file():
        import pytest

        pytest.skip("fauxware missing")
    from argus.llm.autopilot import bootstrap_evidence

    boot = bootstrap_evidence(str(faux), "test task")
    assert "NEXT_ACTION" not in boot["brief"]


def test_agent_no_license_fallback_in_autopilot():
    src = _read("argus/llm/autopilot.py")
    assert 'error_text or "License"' not in src
    assert 'error_text or \'License\'' not in src


def test_agent_system_no_fast_path_workflow():
    src = _read("argus/llm/agent.py")
    assert "Fast-Path Workflow" not in src
    assert "trust this over guessing" not in src.lower()


def test_open_tasks_hint_no_imperative_pivot():
    src = _read("argus/llm/tasks.py")
    assert "PIVOT:" not in src
    assert "Do NOT repeat" not in src


def test_research_brief_no_slice_arrow_apply():
    src = _read("argus/llm/research.py")
    assert "argus_slice → argus_apply_plan" not in src


def test_find_slice_no_apply_imperative():
    src = _read("argus/find_slice.py")
    assert "APPLY:" not in src
    assert "PIVOT:" not in src


def test_no_autopilot_rule_exists():
    assert (ROOT / ".cursor/rules/no-autopilot.mdc").is_file()
