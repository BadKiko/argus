"""Session-backed apply_plan and slice loop guard."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from argus.llm.session import (
    note_slice_call,
    record_gate_scan_result,
    reset_session,
    resolve_apply_steps,
    slice_loop_detected,
)
from argus.llm.tools import dispatch_tool

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
FAUXWARE = SAMPLES / "fauxware"


def test_resolve_apply_steps_from_session():
    reset_session()
    plan = [{"kind": "ret_imm", "addr": "0x1000", "value": 1, "module": "/x"}]
    record_gate_scan_result("/work/BCompare", plan)
    steps, src, note = resolve_apply_steps("/work/BCompare", None)
    assert src == "session_slice"
    assert len(steps) == 1
    assert steps[0]["addr"] == "0x1000"


def test_resolve_fixes_mismatched_model_steps():
    reset_session()
    plan = [{"kind": "force_branch", "addr": "0x2000", "taken": False}]
    record_gate_scan_result(str(FAUXWARE), plan)
    wrong = [{"kind": "force_branch", "addr": "0x9999", "taken": True}]
    steps, src, note = resolve_apply_steps(str(FAUXWARE), wrong)
    assert src == "session_slice"
    assert steps[0]["addr"] == "0x2000"
    assert "mismatched" in note


def test_slice_loop_detection():
    reset_session()
    b = "/usr/lib/beyondcompare/BCompare"
    note_slice_call(b, "license", 2)
    note_slice_call(b, "license", 2)
    assert slice_loop_detected(b, "license")


@pytest.mark.skipif(not FAUXWARE.is_file(), reason="fauxware missing")
def test_dispatch_apply_without_steps_after_slice():
    reset_session()
    raw = dispatch_tool(
        "argus_slice",
        {"binary": str(FAUXWARE), "query": "password", "for_task": 1},
    )
    data = json.loads(raw)
    assert data.get("patch_plan") or (data.get("evidence") or {}).get("patch_plan")
    raw2 = dispatch_tool("argus_apply_plan", {"binary": str(FAUXWARE), "for_task": 1})
    data2 = json.loads(raw2)
    summ = (data2.get("summary") or "").lower()
    assert "no steps" not in summ and "missing steps" not in summ
    assert data2.get("step_source") == "session_slice" or "sandbox" in summ
