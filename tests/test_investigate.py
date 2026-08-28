"""argus_investigate orchestrator."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from argus.llm.investigate import run_investigate, suggest_next_tool
from argus.llm.intent import TaskKind
from argus.llm.tools import dispatch_tool

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
FAUXWARE = SAMPLES / "fauxware"


def test_suggest_next_tool_password():
    tool, reason = suggest_next_tool(
        intent=TaskKind.PASSWORD,
        analyze_ok=True,
        find_ok=True,
        slice_data={"patch_plan": []},
    )
    assert tool == "argus_ai"
    assert reason


def test_suggest_next_tool_gate_with_plan():
    tool, _ = suggest_next_tool(
        intent=TaskKind.GATE_TRANSFORM,
        analyze_ok=True,
        find_ok=True,
        slice_data={"patch_plan": [{"kind": "ret_imm", "addr": "0x1000", "confidence": "high"}]},
        tools_tried=["argus_slice"],
    )
    assert tool == "argus_apply_plan"


@pytest.mark.skipif(not FAUXWARE.is_file(), reason="samples/fauxware missing")
def test_run_investigate_fauxware():
    d = run_investigate(str(FAUXWARE), "password", task_text="give password")
    assert d.get("ok") is True
    assert d.get("observations")
    assert d.get("suggested_next_tool")
    assert d.get("analyze", {}).get("fmt") == "elf"


@pytest.mark.skipif(not FAUXWARE.is_file(), reason="samples/fauxware missing")
def test_dispatch_investigate_tool():
    raw = dispatch_tool("argus_investigate", {"binary": str(FAUXWARE), "query": "password", "for_task": 1})
    data = json.loads(raw)
    assert data.get("ok") is True
    assert data.get("observations")
    assert "argus_" in (data.get("suggested_next_tool") or "")
