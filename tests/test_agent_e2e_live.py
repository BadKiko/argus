"""Optional live agent E2E — skipped without API key."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
FAUXWARE = SAMPLES / "fauxware"


def _has_gemini() -> bool:
    return bool(os.environ.get("GEMINI_API_KEY") or os.environ.get("ARGUS_GEMINI_API_KEY"))


@pytest.mark.skipif(not _has_gemini(), reason="GEMINI_API_KEY not set")
@pytest.mark.skipif(not FAUXWARE.is_file(), reason="fauxware missing")
def test_agent_live_runs_tools(monkeypatch):
    monkeypatch.delenv("ARGUS_FAST_PATH", raising=False)
    from argus.llm.agent import run_agent

    res = run_agent(
        "find strings related to password in this binary",
        binary=str(FAUXWARE),
        provider="gemini",
        max_steps=5,
        store_memory=False,
    )
    assert res.steps > 0, "LLM agent must run at least one tool step"
    assert res.planner == "llm"
    assert len(res.tool_trace) >= 1
