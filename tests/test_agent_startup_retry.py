"""Auto-retry on agent startup failure."""

from __future__ import annotations

from argus.cli.agent_ui import _startup_failure
from argus.llm.agent import AgentResult


def test_startup_failure_detects_step_zero():
    assert _startup_failure(AgentResult(ok=False, answer="boom", steps=0))
    assert not _startup_failure(AgentResult(ok=False, answer="boom", steps=1))
    assert not _startup_failure(AgentResult(ok=True, answer="ok", steps=0))
