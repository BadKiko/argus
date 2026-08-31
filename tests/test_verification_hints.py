"""Verification gap hints for outcome-change tasks."""

from __future__ import annotations

from argus.llm.tasks import UserTask, _evaluate_tasks


def test_gate_not_done_when_diagnose_plan_partially_applied():
    tasks = [UserTask(id=1, text="remove license check")]
    trace = [
        {
            "tool": "argus_diagnose_failure",
            "args": {"for_task": 1},
            "result": {
                "ok": True,
                "for_task": 1,
                "corrective_patch": [
                    {"kind": "force_branch", "addr": "0x1000", "taken": False},
                    {"kind": "force_branch", "addr": "0x2000", "taken": False},
                ],
                "explanation": "error/dialog call@0x3000 after validator",
            },
        },
        {
            "tool": "argus_apply_plan",
            "args": {"for_task": 1},
            "result": {
                "ok": True,
                "for_task": 1,
                "plan_source": "diagnose",
                "slice_plan_len": 2,
                "applied": [{"ok": True, "addr": "0x1000"}],
                "verify": {
                    "ok": True,
                    "kind": "patch_composite",
                    "patch_bytes": {"ok": True},
                },
            },
        },
        {
            "tool": "argus_gui_oracle",
            "args": {"for_task": 1},
            "result": {
                "ok": True,
                "for_task": 1,
                "verify": {"ok": True, "kind": "gui_launch_oracle", "level": "EXECUTION_VERIFIED"},
            },
        },
    ]
    statuses = _evaluate_tasks(tasks, trace)
    assert statuses[0].status == "incomplete"
    assert "outcome" in statuses[0].detail.lower() or "missing" in statuses[0].detail.lower()


def test_verification_gap_hint_after_gui_oracle():
    from argus.llm.verification_hints import verification_gap_hint

    trace = [
        {
            "tool": "argus_gui_oracle",
            "result": {"ok": True, "verify": {"ok": True, "level": "EXECUTION_VERIFIED"}},
        },
        {
            "tool": "argus_diagnose_failure",
            "result": {
                "ok": True,
                "corrective_patch": [{"addr": "0x4000", "kind": "force_branch"}],
                "explanation": "dialog call@0x5000",
            },
        },
    ]
    hint = verification_gap_hint(trace, "make check accept any input")
    assert "EXECUTION_VERIFIED" in hint
    assert "patch_coverage_gap" in hint or "error_sink_coverage" in hint
    assert "license" not in hint.lower()
    assert "sublime" not in hint.lower()
