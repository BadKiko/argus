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


def _cli_gate_trace(*, reject: str, success: str, apply_ok_envelope: bool = False) -> list:
    return [
        {
            "tool": "argus_exec",
            "args": {},
            "result": {
                "ok": True,
                "stdout": reject,
                "evidence": {"stdout": reject},
            },
        },
        {
            "tool": "argus_diagnose_failure",
            "args": {"for_task": 1, "error_text": reject},
            "result": {
                "ok": True,
                "for_task": 1,
                "corrective_patch": [
                    {"kind": "force_branch", "addr": "0x1000", "taken": False},
                    {"kind": "force_branch", "addr": "0x2000", "taken": False},
                ],
            },
        },
        {
            "tool": "argus_apply_plan",
            "args": {"for_task": 1},
            "result": {
                "ok": apply_ok_envelope,
                "for_task": 1,
                "plan_source": "diagnose",
                "applied": [
                    {"ok": True, "addr": "0x1000", "before": "7401", "after": "9090"},
                    {"ok": True, "addr": "0x2000", "before": "7402", "after": "9090"},
                ],
                "verify": {"ok": False, "kind": "patch_bytes", "patch_bytes": {"ok": False}},
            },
        },
        {
            "tool": "argus_exec",
            "args": {},
            "result": {
                "ok": True,
                "stdout": success,
                "evidence": {"stdout": success},
            },
        },
    ]


def test_cli_reject_cleared_overrides_coverage_gap():
    from argus.llm.verification_hints import cli_reject_cleared, gate_outcome_verified

    trace = _cli_gate_trace(reject="Trial version. Type rar -? for help", success="Registered to Alice")
    ok, detail = cli_reject_cleared(trace)
    assert ok is True
    assert "gone" in detail.lower()
    gok, _ = gate_outcome_verified(trace, "remove license check")
    assert gok is True


def test_cli_stdout_marks_gate_task_done_without_gui_oracle():
    tasks = [UserTask(id=1, text="remove license check")]
    trace = _cli_gate_trace(reject="Trial version. Type rar -? for help", success="Registered to Alice")
    statuses = _evaluate_tasks(tasks, trace)
    assert statuses[0].status == "done"
    assert "gui_oracle" not in statuses[0].detail.lower() or "gone" in statuses[0].detail.lower()


def test_parser_needle_never_in_stdout_is_not_done():
    from argus.llm.verification_hints import cli_reject_cleared

    trace = _cli_gate_trace(
        reject="Trial version. Type rar -? for help",
        success="Registered to Alice",
    )
    trace[1]["args"]["error_text"] = "Please insert a valid license file into the config directory"
    ok, _ = cli_reject_cleared(trace)
    assert ok is False


def test_looks_post_patch_success_banner():
    from argus.llm.verification_hints import looks_post_patch_success_banner

    trace = _cli_gate_trace(reject="Trial version. Type rar -? for help", success="Registered to Alice")
    assert looks_post_patch_success_banner("Registered to %s", trace) is True
    assert looks_post_patch_success_banner("Trial version. Type rar -? for help", trace) is False
