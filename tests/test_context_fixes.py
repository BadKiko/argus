"""Tests for agent context quality fixes (discover, sandbox, find intent, gui oracle)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_discover_prefers_executable_over_scored_so(tmp_path):
    from argus.discover import discover_targets, signal_score

    exe = tmp_path / "BCompare"
    lib = tmp_path / "libcloudstorage.so.22.0"
    shutil.copy(SAMPLES / "fauxware", exe)
    shutil.copy(SAMPLES / "fauxware", lib)
    raw = bytearray(lib.read_bytes())
    raw.extend(b"\x00invalid license\x00Unregistered\x00trial\x00")
    lib.write_bytes(raw)
    exe.chmod(0o755)

    assert signal_score(lib) > signal_score(exe)
    d = discover_targets("remove license check", root=str(tmp_path))
    assert d["ok"] is True
    assert Path(d["primary"]).name == "BCompare"


def test_is_patch_artifact_skipped_in_scan(tmp_path):
    from argus.discover import is_patch_artifact, scan_binaries

    clean = tmp_path / "libfoo.so.1"
    patched = tmp_path / "libfoo.so.1.patched"
    shutil.copy(SAMPLES / "fauxware", clean)
    shutil.copy(SAMPLES / "fauxware", patched)
    found = {p.name for p in scan_binaries(tmp_path, max_depth=1, limit=10)}
    assert "libfoo.so.1" in found
    assert "libfoo.so.1.patched" not in found
    assert is_patch_artifact("libx-patch")


def test_find_intent_gate_task_overrides_string_query():
    from argus.find import _query_intent
    from argus.llm.session import reset_session, get_session

    reset_session()
    get_session().user_task_text = "убери проверку лицензии"
    assert _query_intent("not registered") == "gate_transform"


def test_sandbox_multi_module(tmp_path, monkeypatch):
    from argus.patch.sandbox import test_patch_in_sandbox

    primary = tmp_path / "app"
    helper = tmp_path / "helper.so"
    shutil.copy(SAMPLES / "fauxware", primary)
    shutil.copy(SAMPLES / "fauxware", helper)

    calls: list[tuple[str, dict]] = []

    def fake_apply(path, step):
        calls.append((path, step))
        return True

    monkeypatch.setattr("argus.patch.sandbox._apply_step_direct", fake_apply)
    monkeypatch.setattr(
        "argus.binary.launch_env.stage_native_executable",
        lambda p, **k: type("S", (), {"path": Path(p), "cwd": str(tmp_path), "ephemeral": False})(),
    )
    monkeypatch.setattr(
        "argus.patch.sandbox.verify_binary_semantic",
        lambda *a, **k: {"ok": True, "windows": []},
    )

    steps = [
        {
            "kind": "force_branch",
            "addr": "0x1000",
            "taken": True,
            "module": str(helper),
        }
    ]
    res = test_patch_in_sandbox(str(primary), steps)
    assert res.get("safe") is True
    assert any(Path(p).name == "helper.so" for p, _ in calls)


def test_freestyle_patch_blocked_when_session_plan_exists(tmp_path, monkeypatch):
    from argus.llm.session import reset_session, get_session, record_gate_scan_result
    from argus.llm.tools import dispatch_tool

    monkeypatch.setenv("ARGUS_STRICT_PLAN", "1")
    src = tmp_path / "fw"
    shutil.copy(SAMPLES / "fauxware", src)
    reset_session()
    step = {"kind": "force_branch", "addr": "0x1000", "taken": True, "module": str(src)}
    record_gate_scan_result(str(src), [step], full={"patch_plan": [step]})

    raw = dispatch_tool(
        "argus_patch",
        {"binary": str(src), "kind": "force_branch", "addr": "0x1000", "for_task": 1},
    )
    data = json.loads(raw)
    assert data.get("ok") is False
    assert "freestyle" in (data.get("summary") or "").lower()


def test_gui_oracle_rejects_trial_title():
    from argus.patch.gui_oracle import _merged_reject_texts, _match_reject

    merged = _merged_reject_texts([])
    hits = _match_reject(["Beyond Compare 30-day evaluation"], merged)
    assert hits


def test_module_output_keeps_basename_for_sibling(tmp_path):
    from argus.apply_plan import _module_output

    primary = tmp_path / "BCompare"
    mod = tmp_path / "libcloudstorage.so.22.0"
    out = tmp_path / ".argus-work" / "BCompare.patched"
    out.parent.mkdir(parents=True)
    primary.write_bytes(b"x")
    mod.write_bytes(b"y")
    mapped = _module_output(str(mod), str(out), str(primary))
    assert Path(mapped).name == "libcloudstorage.so.22.0"


def test_slice_empty_plan_incomplete_not_failed(tmp_path, monkeypatch):
    from argus.llm.tools import dispatch_tool

    src = tmp_path / "fw"
    shutil.copy(SAMPLES / "fauxware", src)

    monkeypatch.setattr(
        "argus.find_slice.gate_scan_modules",
        lambda *a, **k: {"ok": True, "summary": "empty", "patch_plan": [], "gate_candidates": []},
    )
    raw = dispatch_tool("argus_slice", {"binary": str(src), "for_task": 1})
    data = json.loads(raw)
    assert data.get("ok") is True
    assert data.get("next_errors")
    hint = (data.get("next_hint") or "") + " ".join(data.get("next_errors") or [])
    assert "argus_diagnose" in hint


def test_freestyle_patch_blocked_without_plan(tmp_path, monkeypatch):
    from argus.llm.session import reset_session
    from argus.llm.tools import dispatch_tool

    monkeypatch.setenv("ARGUS_STRICT_PLAN", "1")
    src = tmp_path / "fw"
    shutil.copy(SAMPLES / "fauxware", src)
    reset_session()
    raw = dispatch_tool(
        "argus_patch",
        {"binary": str(src), "kind": "force_branch", "addr": "0x1000", "for_task": 1},
    )
    data = json.loads(raw)
    assert data.get("ok") is False
    assert (data.get("evidence") or {}).get("error") == "freestyle_blocked"
    assert "argus_diagnose" in (data.get("next_hint") or "")


def test_gui_oracle_skips_cli_elf(tmp_path):
    from argus.llm.session import reset_session
    from argus.llm.tools import dispatch_tool

    reset_session()
    src = tmp_path / "fw"
    shutil.copy(SAMPLES / "fauxware", src)
    raw = dispatch_tool("argus_gui_oracle", {"binary": str(src), "for_task": 1})
    data = json.loads(raw)
    assert data.get("ok") is False
    assert (data.get("evidence") or {}).get("error") == "cli_not_gui"
    assert "stdout" in (data.get("next_hint") or "").lower() or "CLI" in (data.get("next_hint") or "")


def test_diagnose_hint_skips_printf_format_template():
    from argus.find import _diagnose_next_hint, _looks_format_template

    assert _looks_format_template("Available license key is valid only for %s")
    assert not _looks_format_template("Not registered — evaluation period")
    hint = _diagnose_next_hint(
        [
            {
                "kind": "string",
                "preview": "Available license key is valid only for %s",
                "addr": "0x1000",
            }
        ]
    )
    assert "format template" in hint
    assert "diagnose_failure(error_text='Available" not in hint
    mixed = _diagnose_next_hint(
        [
            {"kind": "string", "preview": "key valid only for %s", "addr": "0x1000"},
            {"kind": "string", "preview": "Not registered", "addr": "0x2000"},
        ]
    )
    assert "Not registered" in mixed
    assert "format template" not in mixed
