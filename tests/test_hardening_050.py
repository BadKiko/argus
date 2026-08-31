"""Argus 0.5 — LLM-plans, tools observe (no autopilot in agent path)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from argus.llm.agent import _fast_path_enabled
from argus.llm.autopilot import bootstrap_evidence, extract_failure_context, recovery_hints_from_trace
from argus.llm.tools import dispatch_tool
from argus.llm.session import reset_session
from argus.apply_plan import apply_plan

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
FAUXWARE = SAMPLES / "fauxware"


def test_fast_path_disabled_by_default(monkeypatch):
    monkeypatch.delenv("ARGUS_FAST_PATH", raising=False)
    assert _fast_path_enabled() is False


def test_apply_plan_requires_steps():
    if not FAUXWARE.is_file():
        pytest.skip("fauxware missing")
    r = apply_plan(str(FAUXWARE))
    assert r.get("ok") is False
    assert r.get("plan_source") == "missing_steps"


def test_dispatch_apply_plan_requires_steps():
    if not FAUXWARE.is_file():
        pytest.skip("fauxware missing")
    reset_session()
    raw = dispatch_tool("argus_apply_plan", {"binary": str(FAUXWARE), "for_task": 1})
    data = json.loads(raw)
    assert data.get("ok") is False
    assert "steps" in (data.get("summary") or "").lower() or data.get("next_errors")


def test_diagnose_failure_requires_needle():
    if not FAUXWARE.is_file():
        pytest.skip("fauxware missing")
    reset_session()
    raw = dispatch_tool("argus_diagnose_failure", {"binary": str(FAUXWARE), "for_task": 1})
    data = json.loads(raw)
    assert data.get("ok") is False
    assert data.get("next_errors") or "requires" in (data.get("summary") or "").lower()


def test_bootstrap_no_next_action():
    if not FAUXWARE.is_file():
        pytest.skip("fauxware missing")
    boot = bootstrap_evidence(str(FAUXWARE), "change behavior")
    assert "EVIDENCE REPORT" in boot["brief"]
    assert "NEXT_ACTION" not in boot["brief"]
    assert "trust this over guessing" not in boot["brief"].lower()


def test_extract_failure_no_license_fallback():
    ctx = extract_failure_context({"ok": False, "summary": "sandbox failed: license check"})
    assert ctx.get("error_text") != "License"


def test_recovery_hints_no_license_fallback():
    hints = recovery_hints_from_trace(
        [{"tool": "argus_apply_plan", "result": {"ok": False, "summary": "failed"}}],
        binary=str(FAUXWARE) if FAUXWARE.is_file() else "x.exe",
        user_prompt="test",
        discover=None,
    )
    assert hints is None or "License" not in hints


def test_task_signals():
    from argus.llm.intent import task_signals

    sig = task_signals("accept any license key")
    assert sig.get("gate_transform", 0) > 0.3
    sig2 = task_signals("change toolbar color to dark")
    assert sig2.get("patch_ui", 0) >= 0 or sig2.get("general", 0) >= 0


def test_find_no_query_returns_candidates():
    from pathlib import Path

    faux = Path(__file__).resolve().parents[1] / "samples" / "fauxware"
    if not faux.is_file():
        pytest.skip("fauxware missing")
    reset_session()
    raw = dispatch_tool("argus_find", {"binary": str(faux), "for_task": 1})
    data = json.loads(raw)
    assert data.get("ok") is True
    assert "reject_ui_candidates" in (data.get("evidence") or {}) or data.get("hints")
    assert "query= required" in (data.get("summary") or "").lower() or "no query" in (
        data.get("summary") or ""
    ).lower()


def test_tool_result_schema_find():
    from pathlib import Path

    faux = Path(__file__).resolve().parents[1] / "samples" / "fauxware"
    if not faux.is_file():
        pytest.skip("fauxware missing")
    reset_session()
    raw = dispatch_tool(
        "argus_find", {"binary": str(faux), "query": "password", "for_task": 1}
    )
    data = json.loads(raw)
    assert "summary" in data
    assert "evidence" in data


def test_diagnose_scan_ranked():
    from pathlib import Path

    faux = Path(__file__).resolve().parents[1] / "samples" / "fauxware"
    if not faux.is_file():
        pytest.skip("fauxware missing")
    reset_session()
    raw = dispatch_tool("argus_diagnose_scan", {"binary": str(faux), "for_task": 1})
    data = json.loads(raw)
    assert "summary" in data
    ranked = (data.get("evidence") or {}).get("ranked_diagnoses") or []
    assert isinstance(ranked, list)


def test_weak_model_no_step_cap():
    from argus.llm.autopilot import default_max_steps_for_model

    assert default_max_steps_for_model("gemini-3.5-flash-lite") == 0


def test_certificate_has_planner_field():
    from argus.prove.certificate import PatchCertificate

    cert = PatchCertificate(planner="llm")
    assert cert.to_dict()["planner"] == "llm"


def test_memory_tool_sequence():
    from argus.memory.case import build_case_report

    faux = Path(__file__).resolve().parents[1] / "samples" / "fauxware"
    if not faux.is_file():
        pytest.skip("fauxware missing")
    trace = [
        {"tool": "argus_analyze", "result": {"ok": True}},
        {"tool": "argus_find", "result": {"ok": True, "summary": "hits=1"}},
    ]
    report = build_case_report(
        str(faux),
        "test task",
        trace,
        [{"id": 1, "status": "incomplete"}],
        planner="llm",
    )
    assert report is not None
    assert report["features"].get("tool_sequence") == ["argus_analyze", "argus_find"]
    assert report["cost"]["planner"] == "llm"


def test_suggest_patch_batches():
    from argus.llm.autopilot import suggest_patch_batches

    plan = [
        {"kind": "ret_imm", "addr": "0x1000", "value": 1},
        {"kind": "force_branch", "addr": "0x2000", "taken": True},
        {"kind": "force_branch", "addr": "0x3000", "taken": False},
    ]
    batches = suggest_patch_batches(plan)
    assert batches["full_plan"] and len(batches["full_plan"]) == 3
    assert batches["suggested_batches"]
    labels = {b["label"] for b in batches["suggested_batches"]}
    assert "hub_first" in labels


def test_digest_tool_result():
    from argus.llm.tool_result import digest_tool_result

    raw = json.dumps(
        {
            "ok": True,
            "summary": "slice plan=2",
            "observations": ["a", "b"],
            "hints": {
                "suggested_batches": [
                    {"label": "hub_first", "steps": [{"kind": "ret_imm"}], "rationale": "x"}
                ]
            },
            "evidence": {"patch_plan": [{}, {}]},
        }
    )
    d = digest_tool_result(raw)
    assert d and d["patch_plan_len"] == 2
    assert d["hints"]["suggested_batches"][0]["step_count"] == 1


def test_slice_includes_batch_hints():
    from pathlib import Path

    faux = Path(__file__).resolve().parents[1] / "samples" / "fauxware"
    if not faux.is_file():
        pytest.skip("fauxware missing")
    reset_session()
    raw = dispatch_tool(
        "argus_slice",
        {"binary": str(faux), "query": "password", "multi": False, "for_task": 1},
    )
    data = json.loads(raw)
    hints = data.get("hints") or {}
    if data.get("patch_plan"):
        assert hints.get("suggested_batches") is not None


def test_accept_any_license_not_password_bypass():
    from argus.llm.intent import is_bypass_license_task, is_bypass_password_task

    text = "accept any license key for Sublime Merge"
    assert is_bypass_license_task(text)
    assert is_bypass_password_task(text)  # accept\s*any also matches password rx
    from argus.llm.tasks import _evaluate_tasks, split_user_tasks

    tasks = split_user_tasks(text)
    trace = [
        {
            "tool": "argus_patch",
            "args": {"kind": "force_branch", "for_task": 1},
            "result": {
                "ok": True,
                "for_task": 1,
                "summary": "branch forced",
                "evidence": {"blocks_gate_done": True},
                "patched_path": "x.exe.patched",
            },
        },
    ]
    statuses = _evaluate_tasks(tasks, trace)
    assert statuses[0].status != "done"


def test_gate_task_requires_gui_oracle():
    from argus.llm.tasks import _evaluate_tasks, split_user_tasks

    tasks = split_user_tasks("remove license check")
    patched = str(FAUXWARE) + ".patched" if FAUXWARE.is_file() else "x.exe.patched"
    trace = [
        {
            "tool": "argus_apply_plan",
            "args": {"binary": str(FAUXWARE) if FAUXWARE.is_file() else "x.exe", "for_task": 1},
            "result": {
                "ok": True,
                "for_task": 1,
                "plan_source": "diagnose",
                "slice_plan_len": 1,
                "verify": {
                    "ok": True,
                    "kind": "patch_composite",
                    "patch_bytes": {"ok": True},
                    "patch_behavior": {"skipped": True, "ran": False},
                },
                "patched_path": patched,
            },
        },
    ]
    statuses = _evaluate_tasks(tasks, trace)
    assert statuses[0].status == "incomplete"
    assert "gui_oracle" in statuses[0].detail.lower()


def test_gate_task_done_with_patch_and_gui_oracle():
    from argus.llm.tasks import _evaluate_tasks, split_user_tasks

    tasks = split_user_tasks("accept any license key")
    patched = "merge.exe.patched"
    trace = [
        {
            "tool": "argus_diagnose_failure",
            "args": {"for_task": 1},
            "result": {
                "ok": True,
                "for_task": 1,
                "corrective_patch": [
                    {"kind": "force_branch", "addr": "0x14004a8a3", "taken": False},
                ],
            },
        },
        {
            "tool": "argus_apply_plan",
            "args": {"for_task": 1},
            "result": {
                "ok": True,
                "for_task": 1,
                "plan_source": "diagnose",
                "slice_plan_len": 1,
                "applied": [{"ok": True, "addr": "0x14004a8a3"}],
                "verify": {
                    "ok": True,
                    "kind": "patch_composite",
                    "patch_bytes": {"ok": True},
                    "patch_behavior": {"skipped": True, "ran": False},
                },
                "patched_path": patched,
            },
        },
        {
            "tool": "argus_gui_oracle",
            "args": {"binary": patched, "for_task": 1},
            "result": {
                "ok": True,
                "for_task": 1,
                "verify": {
                    "ok": True,
                    "kind": "gui_launch_oracle",
                    "detail": "GUI launch ok from install cwd",
                    "no_keyboard_input": True,
                },
            },
        },
    ]
    statuses = _evaluate_tasks(tasks, trace)
    assert statuses[0].status == "done"


def test_gui_oracle_no_pywinauto_import():
    import importlib

    import argus.patch.gui_oracle as go

    importlib.reload(go)
    src = Path(go.__file__).read_text(encoding="utf-8")
    assert "pywinauto" not in src


def test_gui_observation_headless_degrades(monkeypatch, tmp_path):
    from argus.patch import gui_oracle as go

    exe = tmp_path / "app.bin"
    exe.write_bytes(b"MZ")

    monkeypatch.setattr(go, "gui_observation_available", lambda: False)
    monkeypatch.setattr(
        "argus.binary.launch_env.stage_native_executable",
        lambda *a, **k: type("S", (), {"path": exe, "cwd": str(tmp_path)})(),
    )
    monkeypatch.setattr(
        "argus.binary.launch_env.launch_env_for",
        lambda _p: (str(tmp_path), {}),
    )
    monkeypatch.setattr(go, "close_process", lambda *_: None)

    class FakeProc:
        pid = 4242

        def poll(self):
            return None

        def terminate(self):
            pass

        def wait(self, timeout=0):
            pass

        def kill(self):
            pass

    monkeypatch.setattr(go.subprocess, "Popen", lambda *a, **k: FakeProc())
    monkeypatch.setattr(go.time, "sleep", lambda *_: None)

    res = go.observe_gui_launch(str(exe))
    assert res.get("ok") is True
    assert res.get("gui_observation") is False
    assert "alive" in (res.get("detail") or "").lower()


def test_terminate_process_by_name_linux(monkeypatch):
    from argus.behavior import terminate_process_by_name

    monkeypatch.setattr("argus.behavior.sys.platform", "linux")
    calls: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        return type("R", (), {"returncode": 0})()

    monkeypatch.setattr("argus.behavior.shutil.which", lambda name: name if name == "pkill" else None)
    monkeypatch.setattr("argus.behavior.subprocess.run", fake_run)
    terminate_process_by_name("myapp.bin")
    assert calls and calls[0][0] == "pkill"
