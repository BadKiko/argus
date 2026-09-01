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


def test_suggest_next_tool_gate_empty_plan_diagnoses():
    tool, reason = suggest_next_tool(
        intent=TaskKind.GATE_TRANSFORM,
        analyze_ok=True,
        find_ok=True,
        slice_data={"patch_plan": []},
    )
    assert tool == "argus_diagnose_failure"
    assert "error_text" in reason


def test_suggest_next_tool_password():
    tool, reason = suggest_next_tool(
        intent=TaskKind.PASSWORD,
        analyze_ok=True,
        find_ok=True,
        slice_data={"patch_plan": []},
    )
    assert tool == "argus_atlas"
    assert reason
    from argus.llm.investigate import rank_tool_suggestions

    ranked = rank_tool_suggestions(
        intent=TaskKind.PASSWORD,
        analyze_ok=True,
        find_ok=True,
        slice_data={"patch_plan": []},
    )
    names = [x["tool"] for x in ranked]
    assert names[0] == "argus_atlas"
    assert "argus_ai" in names


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
def test_run_investigate_does_not_inject_archetype_recipe():
    d = run_investigate(
        str(FAUXWARE),
        "license",
        task_text="Сделай чтобы проверка лицензии везде в программе возвращала True",
    )
    blob = json.dumps(d, ensure_ascii=False)
    assert "archetype=" not in blob
    assert "AppState" not in blob
    assert "Global State Struct" not in blob
    obs = " ".join(d.get("observations") or [])
    assert "Hypothesis (unverified)" not in obs
    ranked = (d.get("hints") or {}).get("suggested_tools") or []
    names = [x.get("tool") for x in ranked]
    assert "argus_atlas" in names
    assert names[0] != "argus_ai"


@pytest.mark.skipif(not FAUXWARE.is_file(), reason="samples/fauxware missing")
def test_dispatch_investigate_tool():
    raw = dispatch_tool("argus_investigate", {"binary": str(FAUXWARE), "query": "password", "for_task": 1})
    data = json.loads(raw)
    assert data.get("ok") is True
    assert data.get("observations")
    ranked = (data.get("hints") or {}).get("suggested_tools") or []
    assert ranked and ranked[0].get("tool", "").startswith("argus_")
