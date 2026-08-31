"""Universal patch_plan + apply_plan (no vendor hardcode)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from argus.find_slice import build_patch_plan, gate_scan
from argus.llm.tasks import UserTask, finalize_agent
from argus.llm.tools import ARGUS_TOOLS, dispatch_tool
from argus.apply_plan import apply_plan, verify_patch_bytes

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_no_vendor_needles_in_find_slice_source():
    src = Path(__file__).resolve().parents[1] / "argus" / "find_slice.py"
    text = src.read_text(encoding="utf-8")
    assert "sublime" not in text.lower()
    assert "purchase_license_cta" not in text


def test_build_patch_plan_ordering():
    gates = [
        {
            "kind": "ret_imm",
            "addr": "0x1000",
            "score": 400,
            "ui_label_only": False,
            "ret_guess": 1,
            "reason": "large validate-covering fn",
            "nearby_fn": "sub_1000",
            "xref_addr": "0x1100",
        },
        {
            "kind": "force_branch",
            "addr": "0x1110",
            "score": 300,
            "ui_label_only": False,
            "taken": False,
            "reason": "jcc after call near xref",
            "nearby_fn": "sub_1000",
            "xref_addr": "0x1100",
        },
        {
            "kind": "force_branch",
            "addr": "0x2200",
            "score": 80,
            "ui_label_only": False,
            "taken": False,
            "reason": "jcc after cmp",
            "string_kind": "ui",
            "string_preview": "Unregistered",
            "xref_addr": "0x2210",
        },
    ]
    plan = build_patch_plan(gates)
    assert plan
    assert plan[0]["kind"] == "ret_imm" and plan[0]["addr"] == "0x1000"
    kinds = [s["kind"] for s in plan]
    assert "force_branch" in kinds
    assert len(plan) <= 5


def test_gate_scan_fauxware_smoke():
    d = gate_scan(str(SAMPLES / "fauxware"), "password")
    assert d.get("ok") is True
    assert "patch_plan" in d
    assert isinstance(d["patch_plan"], list)


def test_apply_plan_fauxware_rejects_invented_steps(tmp_path, monkeypatch):
    """Fauxware is a password crackme — invented authenticate stub is not slice-sourced."""
    import shutil

    from argus.binary import load_binary

    monkeypatch.setenv("ARGUS_STRICT_PLAN", "1")
    src = tmp_path / "fauxware"
    shutil.copy(SAMPLES / "fauxware", src)
    img = load_binary(str(src))
    auth = img.symbols["authenticate"].addr
    steps = [
        {"kind": "ret_imm", "addr": hex(auth), "value": 1, "why": "test stub"},
    ]
    out = tmp_path / "out.patched"
    d = apply_plan(str(src), output=str(out), steps=steps, auto_slice=True)
    assert d.get("plan_source") == "rejected_model"
    assert d.get("ok") is False
    assert d["verify"]["ok"] is False


def test_dispatch_apply_plan_and_finalize(tmp_path, monkeypatch):
    """Finalize accepts unlock only with slice plan evidence + plan_source=slice."""
    import shutil

    from argus.binary import load_binary

    monkeypatch.setenv("ARGUS_STRICT_PLAN", "1")
    src = tmp_path / "fauxware"
    shutil.copy(SAMPLES / "fauxware", src)
    img = load_binary(str(src))
    auth = img.symbols["authenticate"].addr
    step = {"kind": "ret_imm", "addr": hex(auth), "value": 1}
    with patch("argus.patch.sandbox.test_patch_in_sandbox", return_value={"safe": True}):
        raw = dispatch_tool(
            "argus_apply_plan",
            {
                "binary": str(src),
                "output": str(tmp_path / "u.patched"),
                "steps": [step],
                "for_task": 1,
            },
        )
    data = json.loads(raw)
    assert data.get("ok") is False
    assert data.get("plan_source") == "rejected_model" or (
        data.get("evidence") or {}
    ).get("plan_source") == "rejected_model"

    tasks = [UserTask(id=1, text="unlock license check")]
    trace = [
        {
            "tool": "argus_slice",
            "args": {"for_task": 1},
            "result": {
                "ok": True,
                "for_task": 1,
                "patch_plan": [step],
                "evidence": {"patch_plan": [step]},
            },
        },
        {
            "tool": "argus_apply_plan",
            "args": {"for_task": 1},
            "result": {
                "ok": True,
                "for_task": 1,
                "plan_source": "slice",
                "slice_plan_len": 1,
                "verify": {
                    "kind": "patch_composite",
                    "ok": True,
                    "detail": "bytes+behavior ok",
                    "patch_bytes": {"ok": True},
                    "patch_behavior": {"ok": True, "ran": True},
                },
            },
        },
        {
            "tool": "argus_gui_oracle",
            "args": {"for_task": 1},
            "result": {
                "ok": True,
                "for_task": 1,
                "verify": {
                    "ok": True,
                    "kind": "gui_launch_oracle",
                    "detail": "GUI launch ok from install cwd",
                },
            },
        },
    ]
    result = finalize_agent(tasks, trace, model_answer="done")
    assert result.task_statuses
    assert result.task_statuses[0]["status"] == "done"


def test_optional_commercial_slice_oracle():
    """External binary only as oracle — no vendor strings in Argus source."""
    path = Path("/opt/sublime_merge/sublime_merge")
    if not path.is_file():
        return
    d = gate_scan(str(path), "license key")
    assert d["ok"]
    plan = d.get("patch_plan") or []
    assert plan, "expected patch_plan on license-bearing binary"
    # Primary should be logic gate
    assert plan[0]["kind"] in ("ret_imm", "force_branch")
    if plan[0]["kind"] == "ret_imm":
        assert int(plan[0].get("value") or 1) == 1
