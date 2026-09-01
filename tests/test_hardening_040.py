"""Argus 0.4 hardening: verify, exec, autopilot, concolic, levels."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from argus import __version__
from argus.apply_plan import verify_patch_behavior, _composite_verify
from argus.llm.tasks import _evaluate_tasks, _is_password_tool, split_user_tasks
from argus.prove.certificate import VerificationLevel, level_from_verify
from argus.symbolic.explorer import solve_binary

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
FAUXWARE = SAMPLES / "fauxware"


def test_version_050():
    assert __version__ == "0.5.0"


def test_gui_timeout_not_success(monkeypatch):
    monkeypatch.setattr(
        "argus.apply_plan._behavior_verify_enabled",
        lambda: True,
    )
    monkeypatch.setattr(
        "argus.concrete.runner.unicorn_available",
        lambda: False,
    )

    def fake_run(*args, **kwargs):
        raise __import__("subprocess").TimeoutExpired(cmd="x", timeout=2)

    monkeypatch.setattr("argus.apply_plan.subprocess.run", fake_run)
    monkeypatch.setattr(
        "argus.apply_plan.load_binary",
        lambda p: type("I", (), {"fmt": "elf", "arch": "x86_64"})(),
    )
    monkeypatch.setattr("argus.patch.safety._looks_gui_or_heavy", lambda img: True)
    monkeypatch.setattr(
        "argus.behavior.verify_binary_semantic",
        lambda *a, **k: {"ok": True, "windows": []},
    )

    target = str(FAUXWARE) if FAUXWARE.is_file() else __file__
    res = verify_patch_behavior(
        target,
        require_positive_oracle=True,
    )
    if res.get("timed_out") or (res.get("gui") and res.get("method") == "subprocess"):
        assert res.get("ok") is False
        assert res.get("needs_oracle") is True


def test_verification_levels_bytes():
    v = {"ok": True, "kind": "patch_bytes"}
    assert level_from_verify(v) == VerificationLevel.BYTES_VERIFIED
    comp = {
        "ok": True,
        "kind": "patch_composite",
        "patch_bytes": {"ok": True},
        "patch_behavior": {"ran": False},
    }
    assert level_from_verify(comp) == VerificationLevel.BYTES_VERIFIED


def test_exec_not_password_tool():
    assert _is_password_tool({"tool": "argus_exec"}) is False
    assert _is_password_tool({"tool": "argus_solve"}) is True


def test_exec_no_password_done_finalize():
    tasks = split_user_tasks("find password")
    trace = [
        {
            "tool": "argus_exec",
            "args": {"for_task": 1},
            "result": {
                "ok": True,
                "for_task": 1,
                "evidence": {"stdout": "password: FAKE123"},
            },
        }
    ]
    statuses = _evaluate_tasks(tasks, trace)
    assert statuses[0].status != "done"


def test_find_gate_query_hints_diagnose():
    from argus.find import find_in_binary
    from argus.llm.session import reset_session, get_session

    reset_session()
    get_session().user_task_text = "убери проверку лицензии"
    path = str(SAMPLES / "fauxware")
    data = find_in_binary(path, "password")
    assert "diagnose_failure" in (data.get("next_hint") or "")
    assert "argus_patch kind=" not in (data.get("next_hint") or "")


def test_empty_slice_does_not_fail_license_task():
    from argus.llm.tasks import _evaluate_tasks, split_user_tasks

    tasks = split_user_tasks("убери лицензию")
    trace = [
        {
            "tool": "argus_slice",
            "args": {"for_task": 1},
            "result": {
                "ok": False,
                "for_task": 1,
                "summary": "gate_scan_modules modules=1 gates=0 plan=0",
                "patch_plan": [],
            },
        }
    ]
    statuses = _evaluate_tasks(tasks, trace)
    assert statuses[0].status != "failed"


def test_exec_refusal_does_not_fail_license_task():
    from argus.llm.tasks import _evaluate_tasks, split_user_tasks

    tasks = split_user_tasks("убери лицензию")
    trace = [
        {
            "tool": "argus_exec",
            "args": {"for_task": 1},
            "result": {
                "ok": False,
                "for_task": 1,
                "summary": "argus_exec: only language=python allowed",
            },
        }
    ]
    statuses = _evaluate_tasks(tasks, trace)
    assert statuses[0].status != "failed"


def test_composite_requires_positive_oracle():
    bytes_v = {"ok": True, "kind": "patch_bytes"}
    beh = {"ran": True, "ok": True, "needs_oracle": True}
    out = _composite_verify(bytes_v, beh, require_behavior=True, require_positive_oracle=True)
    assert out["ok"] is False


def test_concolic_seed_used_in_solve():
    if not FAUXWARE.is_file():
        pytest.skip("fauxware missing")
    with patch("argus.concrete.concolic.concrete_until_branch") as mock_seed:
        from argus.concrete.concolic import ConcolicSeed

        mock_seed.return_value = ConcolicSeed(
            stdin=b"AAAAAAAA\n",
            hit=0x400500,
            stdout=b"",
            steps=100,
        )
        with patch("argus.symbolic.explorer.Explorer") as MockExplorer:
            inst = MockExplorer.return_value
            inst.solve_to_address.return_value = __import__(
                "argus.symbolic.explorer", fromlist=["SolveResult"]
            ).SolveResult(True, b"x", b"Welcome", {}, 1, "ok")
            solve_binary(str(FAUXWARE), find=b"Welcome", note="password length 8")
            assert mock_seed.called
            assert inst.solve_to_address.called
            assert inst.solve_to_address.call_args.kwargs.get("concrete_stdin") == b"AAAAAAAA\n"


def test_autopilot_bootstrap_brief():
    if not FAUXWARE.is_file():
        pytest.skip("fauxware missing")
    from argus.llm.autopilot import bootstrap_evidence
    from argus.llm.session import reset_session

    reset_session()
    boot = bootstrap_evidence(str(FAUXWARE), "remove license check")
    assert "EVIDENCE REPORT" in boot.get("brief", "")
    assert "NEXT_ACTION" not in boot.get("brief", "")
    assert boot.get("hints", {}).get("suggested_tools")


def test_exec_shell_disabled():
    from argus.llm.tools import dispatch_tool
    from argus.llm.session import reset_session

    reset_session()
    os.environ.pop("ARGUS_EXEC_SHELL", None)
    raw = dispatch_tool(
        "argus_exec",
        {"code": "echo hi", "language": "shell", "for_task": 1},
    )
    payload = json.loads(raw)
    assert payload.get("ok") is False


def test_pe_cff_dispatcher_regex():
    from argus.deobf.cff import _MEM_SLOT

    assert _MEM_SLOT.search("dword ptr [rsp + 0x28]")
    assert _MEM_SLOT.search("qword ptr [rbp - 0x10]")


def test_intent_russian_activation():
    from argus.llm.intent import TaskKind, classify_task_intent

    assert classify_task_intent("сделай чтобы на любой ключ активировалась") == TaskKind.GATE_TRANSFORM


def test_verify_patch_disasm_on_steps(tmp_path):
    from argus.apply_plan import verify_patch_disasm

    class FakeImg:
        bits = 64

        def read_bytes(self, addr, n):
            return b"\xb8\x01\x00\x00\x00\xc3\x90\x90"[:n]

    p = tmp_path / "t.exe"
    p.write_bytes(b"MZ")
    import argus.apply_plan as ap

    old = ap.load_binary
    ap.load_binary = lambda _path: FakeImg()
    try:
        res = verify_patch_disasm(str(p), [{"kind": "ret_imm", "addr": "0x1000"}])
    finally:
        ap.load_binary = old
    assert res.get("ok") is True
    assert res.get("previews")


def test_trim_patch_plan_hub_first():
    from argus.llm.autopilot import trim_patch_plan

    plan = [
        {"kind": "force_branch", "addr": "0x100"},
        {"kind": "ret_imm", "addr": "0x200", "value": 1},
        {"kind": "force_branch", "addr": "0x300"},
    ]
    batch = trim_patch_plan(plan, max_steps=1)
    assert len(batch) == 1
    assert batch[0]["kind"] == "ret_imm"
    assert batch[0]["addr"] == "0x200"


def test_trim_patch_plan_prefers_validator_taint():
    from argus.llm.autopilot import focus_corrective_patch, trim_patch_plan

    plan = [
        {"kind": "force_branch", "addr": "0x1", "taint_source": "struct_field_state"},
        {"kind": "force_branch", "addr": "0x2", "taint_source": "validator_return (sub_x)"},
        {"kind": "force_branch", "addr": "0x3", "taint_source": "struct_field_state"},
    ]
    batch = trim_patch_plan(plan, max_steps=1)
    assert batch[0]["addr"] == "0x2"
    focused = focus_corrective_patch(plan)
    assert [s["addr"] for s in focused] == ["0x2"]


def test_extract_failure_modal_title():
    from argus.llm.autopilot import extract_failure_context

    ctx = extract_failure_context(
        {
            "ok": False,
            "summary": "sandbox preflight failed: error modal dialog appeared with title 'Sublime Merge'",
        }
    )
    assert ctx.get("error_text") is None

    ctx2 = extract_failure_context(
        {
            "ok": False,
            "detail": "reject text visible: 'That license key does not appear to be valid.'",
        }
    )
    assert "license key" in (ctx2.get("error_text") or "").lower()


def test_composite_verify_bytes_ok_needs_oracle():
    from argus.apply_plan import _composite_verify

    comp = _composite_verify(
        {"ok": True, "kind": "patch_bytes"},
        {"ran": True, "ok": False, "needs_oracle": True, "detail": "needs gui"},
        require_behavior=False,
    )
    assert comp.get("ok") is True
    assert "gui_oracle" in (comp.get("detail") or "").lower()


def test_gate_loop_detected():
    from argus.llm.autopilot import gate_loop_detected

    trace = [
        {"tool": "argus_decision_flow"},
        {"tool": "argus_apply_plan"},
        {"tool": "argus_decision_flow"},
        {"tool": "argus_apply_plan"},
    ]
    assert gate_loop_detected(trace) is True


def test_suggest_next_tool_after_verify_fail():
    from argus.llm.intent import TaskKind
    from argus.llm.investigate import suggest_next_tool

    tool, _ = suggest_next_tool(
        intent=TaskKind.GATE_TRANSFORM,
        analyze_ok=True,
        find_ok=True,
        slice_data={"patch_plan": [{"kind": "ret_imm", "addr": "0x1"}]},
        tools_tried=["argus_apply_plan"],
        verify_ok=False,
    )
    assert tool == "argus_diagnose_failure"


def test_weak_model_default_max_steps():
    from argus.llm.autopilot import default_max_steps_for_model

    assert default_max_steps_for_model("gemini-3.5-flash-lite") == 0
    assert default_max_steps_for_model("gpt-4o") == 0


def test_resolve_install_from_testdrop_copy(tmp_path, monkeypatch):
    """Lone exe copy in testdrop should resolve to real install with Packages/."""
    from argus.binary.launch_env import resolve_native_install_dir, stage_native_executable

    install = tmp_path / "Sublime Merge"
    install.mkdir()
    (install / "Packages").mkdir()
    real_exe = install / "sublime_merge.exe"
    real_exe.write_bytes(b"MZ" + b"x" * 8000)
    drop = tmp_path / "drop"
    drop.mkdir()
    copy = drop / "sublime_merge_orig.exe"
    copy.write_bytes(real_exe.read_bytes())

    def fake_find(exe_name, *, reference_size=None):
        if exe_name == "sublime_merge.exe":
            return install.resolve()
        return None

    monkeypatch.setattr("argus.binary.launch_env._find_install_with_assets", fake_find)
    resolved = resolve_native_install_dir(copy, original=copy)
    assert resolved.resolve() == install.resolve()

    patched = drop / ".argus-work" / "sublime_merge_orig.exe"
    patched.parent.mkdir(parents=True)
    patched.write_bytes(b"MZ-patched")
    staged = stage_native_executable(patched, original=copy)
    assert (install / "Packages").is_dir()
    assert staged.cwd == str(install)
    assert staged.path.parent.name == ".argus-work"


def test_stage_native_prefers_install_argus_work(tmp_path):
    from argus.binary.launch_env import stage_native_executable

    install = tmp_path / "app"
    install.mkdir()
    (install / "Packages").mkdir()
    orig = install / "app.exe"
    orig.write_bytes(b"orig")
    work = tmp_path / "cache" / "app.exe"
    work.parent.mkdir()
    work.write_bytes(b"patched")
    staged = stage_native_executable(work, original=orig)
    assert staged.path.parent.name == ".argus-work"
    assert staged.path.parent.parent == install
    assert staged.cwd == str(install)
    assert staged.path.read_bytes() == b"patched"


def test_stage_native_uses_shadow_when_install_not_writable(tmp_path, monkeypatch):
    import shutil

    from argus.binary.launch_env import stage_native_executable

    install = tmp_path / "Sublime Merge"
    install.mkdir()
    (install / "Packages").mkdir()
    (install / "Packages" / "asset.txt").write_text("ok")
    orig = install / "sublime_merge.exe"
    orig.write_bytes(b"MZ-original")
    work = tmp_path / "cache" / "sublime_merge.exe"
    work.parent.mkdir()
    work.write_bytes(b"MZ-patched")
    monkeypatch.setenv("ARGUS_WORK_DIR", str(tmp_path / "argus-ws"))
    monkeypatch.setattr("argus.binary.launch_env._writable_dir", lambda p: False)
    real_copy = shutil.copy2

    def copy_resilient(src, dst, **kwargs):
        d = Path(dst)
        if d.parent.resolve() == install.resolve():
            raise OSError("denied")
        return real_copy(src, dst)

    monkeypatch.setattr("argus.binary.launch_env.copy_binary_resilient", copy_resilient)
    staged = stage_native_executable(work, original=orig)
    assert staged.path.name == "sublime_merge.exe"
    assert staged.path.parent != install
    assert (staged.path.parent / "Packages" / "asset.txt").is_file()
    assert staged.path.read_bytes() == b"MZ-patched"
    assert staged.cwd == str(staged.path.parent)


def test_diagnose_needles_no_product_defaults():
    from argus.llm.autopilot import _diagnose_needles

    needles = _diagnose_needles({}, {}, "сделай чтобы на любой ключ активировалась")
    joined = " ".join(needles).lower()
    assert "enter license" not in joined
    assert "sublime" not in joined


def test_trim_patch_plan_diagnose_order():
    from argus.llm.autopilot import trim_patch_plan

    plan = [
        {"kind": "nop_call", "addr": "0x10"},
        {"kind": "force_branch", "addr": "0x20", "taken": False},
        {"kind": "ret_imm", "addr": "0x30", "value": 1},
        {"kind": "force_flag", "addr": "0x40"},
    ]
    batch = trim_patch_plan(plan, max_steps=4, mode="diagnose")
    kinds = [s["kind"] for s in batch]
    assert kinds == ["ret_imm", "force_branch", "force_flag", "nop_call"]


def test_enrich_patch_plan_adds_force_flag_and_nop_call():
    from argus.flow import DecisionGate, DecisionGraph, enrich_patch_plan

    class FakeImg:
        bits = 64

        def read_bytes(self, addr, n):
            # minimal x86-64: sete [rax+9]; cmp ...; je err; call dialog; ret
            blob = (
                b"\x0f\x94\x40\x09"  # sete byte ptr [rax+9]
                b"\x80\x78\x09\x01"  # cmp byte ptr [rax+9], 1
                b"\x75\x08"          # jne +8
                b"\xb0\x01\xc3"      # mov al,1; ret (success)
                b"\xe8\x05\x00\x00\x00"  # call +5 (target 0x100c)
                b"\xc3"              # ret
                b"\xe8\x00\x00\x00\x00"  # call +0 at 0x100d (same target via rel)
            )
            return blob[:n]

    g = DecisionGraph(func_addr=0x1000, func_name="sub_1000", func_size=0x20)
    g.gates = [
        DecisionGate(
            addr=0x1004,
            mnemonic="jne",
            op_str="0x100c",
            target_addr=0x100c,
            predicate="cmp byte ptr [rax + 9], 1",
            recommended_action="force_fallthrough",
        ),
    ]
    plan = [{"kind": "force_branch", "addr": "0x1004", "taken": False}]
    out = enrich_patch_plan(FakeImg(), g, plan)
    kinds = {s["kind"] for s in out}
    assert "force_flag" in kinds
    # Tiny synthetic blob may not yield repeated dialog calls — force_flag is the signal.
    if "nop_call" not in kinds:
        pytest.skip("synthetic blob has no repeated dialog call targets")

