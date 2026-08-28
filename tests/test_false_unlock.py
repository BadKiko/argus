"""Regression: fauxware false unlock success must not finalize done."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus.llm.tasks import finalize_agent, split_user_tasks
from argus.unlock import unlock_apply

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
FAUXWARE = SAMPLES / "fauxware"


def test_finalize_fauxware_false_unlock_trace_not_done():
    """Reproduce incident: slice plan=0 → patch gate → unlock_apply with model steps."""
    tasks = split_user_tasks("remove license check")
    trace = [
        {
            "tool": "argus_slice",
            "args": {"binary": str(FAUXWARE), "for_task": 1},
            "result": {
                "ok": True,
                "for_task": 1,
                "unlock_plan": [],
                "evidence": {"unlock_plan": []},
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
                "evidence": {"blocks_unlock_done": True},
                "verify": {"kind": "none", "ok": None},
                "patched_path": str(FAUXWARE) + ".patched",
            },
        },
        {
            "tool": "argus_unlock_apply",
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
                    "kind": "unlock_bytes",
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
def test_unlock_apply_rejects_model_invented_steps():
    invented = [{"kind": "force_branch", "addr": "0x4007bb", "taken": False}]
    r = unlock_apply(str(FAUXWARE), steps=invented)
    assert r.get("ok") is False
    assert r.get("plan_source") == "rejected_model"
    assert r.get("verify", {}).get("ok") is False


@pytest.mark.skipif(not FAUXWARE.is_file(), reason="samples/fauxware missing")
def test_unlock_apply_authenticate_slice_plan_succeeds(tmp_path):
    """Correct path: slice-derived authenticate ret_imm passes composite verify."""
    out = str(tmp_path / "fauxware.patched")
    steps = [{"kind": "ret_imm", "addr": "0x4006e6", "value": 1}]
    r = unlock_apply(str(FAUXWARE), output=out, steps=steps, multi=False)
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
    r = unlock_apply(str(FAUXWARE), output=out, steps=invented)
    assert r.get("ok") is False


def test_memory_no_success_without_plan_sourced():
    from argus.memory.case import build_case_report

    trace = [
        {
            "tool": "argus_unlock_apply",
            "result": {
                "ok": True,
                "plan_source": "rejected_model",
                "verify": {"kind": "unlock_bytes", "ok": True},
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
