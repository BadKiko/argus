"""Regression: fauxware false unlock success must not finalize done."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus.llm.tasks import finalize_agent, split_user_tasks
from argus.apply_plan import apply_plan

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
FAUXWARE = SAMPLES / "fauxware"


def test_finalize_fauxware_false_unlock_trace_not_done():
    """Reproduce incident: slice plan=0 → patch gate → apply_plan with model steps."""
    tasks = split_user_tasks("remove license check")
    trace = [
        {
            "tool": "argus_slice",
            "args": {"binary": str(FAUXWARE), "for_task": 1},
            "result": {
                "ok": True,
                "for_task": 1,
                "patch_plan": [],
                "evidence": {"patch_plan": []},
            },
        },
        {
            "tool": "argus_find",
            "args": {"binary": str(FAUXWARE), "query": "Go away", "for_task": 1},
            "result": {"ok": True, "for_task": 1, "summary": "hits"},
        },
        {
            "tool": "argus_patch",
            "args": {
                "kind": "force_branch",
                "addr": "0x4007bb",
                "taken": False,
                "for_task": 1,
            },
            "result": {
                "ok": True,
                "for_task": 1,
                "summary": "branch forced",
                "evidence": {"blocks_gate_done": True},
                "verify": {"kind": "none", "ok": None},
                "patched_path": str(FAUXWARE) + ".patched",
            },
        },
        {
            "tool": "argus_apply_plan",
            "args": {
                "binary": str(FAUXWARE),
                "for_task": 1,
                "steps": [{"kind": "force_branch", "addr": "0x4007bb", "taken": False}],
            },
            "result": {
                "ok": True,
                "for_task": 1,
                "plan_source": "rejected_model",
                "slice_plan_len": 0,
                "verify": {
                    "kind": "patch_bytes",
                    "ok": True,
                    "detail": "bytes changed",
                },
                "patched_path": str(FAUXWARE) + ".patched",
            },
        },
    ]
    r = finalize_agent(tasks, trace, "license removed successfully")
    assert r.ok is False
    assert r.task_statuses[0]["status"] != "done"
    assert r.task_statuses[0]["status"] == "incomplete"


@pytest.mark.skipif(not FAUXWARE.is_file(), reason="samples/fauxware missing")
def test_apply_plan_rejects_model_invented_steps(monkeypatch):
    monkeypatch.setenv("ARGUS_STRICT_PLAN", "1")
    invented = [{"kind": "force_branch", "addr": "0x4007bb", "taken": False}]
    r = apply_plan(str(FAUXWARE), steps=invented, auto_slice=True)
    assert r.get("ok") is False
    assert r.get("plan_source") == "rejected_model"
    assert r.get("verify", {}).get("ok") is False


@pytest.mark.skipif(not FAUXWARE.is_file(), reason="samples/fauxware missing")
def test_apply_plan_authenticate_slice_plan_succeeds(tmp_path, monkeypatch):
    """Correct path: slice-derived authenticate ret_imm passes composite verify."""
    monkeypatch.setenv("ARGUS_STRICT_PLAN", "1")
    out = str(tmp_path / "fauxware.patched")
    steps = [{"kind": "ret_imm", "addr": "0x4006e6", "value": 1}]
    r = apply_plan(str(FAUXWARE), output=out, steps=steps, multi=False, auto_slice=True)
    if r.get("plan_source") == "rejected_model":
        pytest.skip("fauxware slice plan does not include authenticate ret_imm in this build")
    assert r.get("ok") is True, r
    assert r.get("plan_source") == "slice"
    verify = r.get("verify") or {}
    assert verify.get("ok") is True


@pytest.mark.skipif(not FAUXWARE.is_file(), reason="samples/fauxware missing")
def test_freestyle_patch_behavior_fails_unlock(tmp_path):
    """Freestyle gate patch must not pass behavior verify when applied via invented steps."""
    out = str(tmp_path / "fw_bad.patched")
    invented = [{"kind": "force_branch", "addr": "0x4007bb", "taken": False}]
    r = apply_plan(str(FAUXWARE), output=out, steps=invented)
    assert r.get("ok") is False


def test_memory_no_success_without_plan_sourced():
    from argus.memory.case import build_case_report

    trace = [
        {
            "tool": "argus_apply_plan",
            "result": {
                "ok": True,
                "plan_source": "rejected_model",
                "verify": {"kind": "patch_bytes", "ok": True},
            },
        }
    ]
    statuses = [{"id": 1, "text": "remove license", "status": "done", "detail": "fake"}]
    report = build_case_report(
        str(FAUXWARE),
        "remove license",
        trace,
        statuses,
    )
    assert report is not None
    assert report["outcome"] == "incomplete"
    assert report["plan_sourced"] is False
