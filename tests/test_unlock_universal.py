"""Universal unlock_plan + unlock_apply (no vendor hardcode)."""

from __future__ import annotations

import json
from pathlib import Path

from argus.find_slice import build_unlock_plan, license_slice
from argus.llm.tasks import UserTask, finalize_agent
from argus.llm.tools import ARGUS_TOOLS, dispatch_tool
from argus.unlock import unlock_apply, verify_unlock_bytes

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_no_vendor_needles_in_find_slice_source():
    src = Path(__file__).resolve().parents[1] / "argus" / "find_slice.py"
    text = src.read_text(encoding="utf-8")
    assert "sublime" not in text.lower()
    assert "purchase_license_cta" not in text


def test_build_unlock_plan_ordering():
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
    plan = build_unlock_plan(gates)
    assert plan
    assert plan[0]["kind"] == "ret_imm" and plan[0]["addr"] == "0x1000"
    kinds = [s["kind"] for s in plan]
    assert "force_branch" in kinds
    assert len(plan) <= 5


def test_license_slice_fauxware_smoke():
    d = license_slice(str(SAMPLES / "fauxware"), "password")
    assert d.get("ok") is True
    assert "unlock_plan" in d
    assert isinstance(d["unlock_plan"], list)


def test_unlock_apply_fauxware_authenticate(tmp_path):
    import shutil

    from argus.binary import load_binary

    src = tmp_path / "fauxware"
    shutil.copy(SAMPLES / "fauxware", src)
    img = load_binary(str(src))
    auth = img.symbols["authenticate"].addr
    steps = [
        {"kind": "ret_imm", "addr": hex(auth), "value": 1, "why": "test stub"},
    ]
    out = tmp_path / "out.patched"
    d = unlock_apply(str(src), output=str(out), steps=steps)
    assert out.exists()
    assert d["verify"]["kind"] == "unlock_bytes"
    assert d["verify"]["ok"] is True
    assert d["ok"] is True
    # byte pattern
    v = verify_unlock_bytes(str(src), str(out), steps)
    assert v["ok"] is True


def test_dispatch_unlock_apply_and_finalize(tmp_path):
    import shutil

    from argus.binary import load_binary

    src = tmp_path / "fauxware"
    shutil.copy(SAMPLES / "fauxware", src)
    img = load_binary(str(src))
    auth = img.symbols["authenticate"].addr
    raw = dispatch_tool(
        "argus_unlock_apply",
        {
            "binary": str(src),
            "output": str(tmp_path / "u.patched"),
            "steps": [{"kind": "ret_imm", "addr": hex(auth), "value": 1}],
            "for_task": 1,
        },
    )
    data = json.loads(raw)
    assert data.get("verify", {}).get("ok") is True
    assert "argus_unlock_apply" in {t["function"]["name"] for t in ARGUS_TOOLS}

    tasks = [UserTask(id=1, text="unlock license check")]
    trace = [
        {
            "tool": "argus_unlock_apply",
            "args": {"for_task": 1},
            "result": data,
        }
    ]
    result = finalize_agent(tasks, trace, model_answer="done")
    assert result.task_statuses
    assert result.task_statuses[0]["status"] == "done"


def test_optional_commercial_slice_oracle():
    """External binary only as oracle — no vendor strings in Argus source."""
    path = Path("/opt/sublime_merge/sublime_merge")
    if not path.is_file():
        return
    d = license_slice(str(path), "license key")
    assert d["ok"]
    plan = d.get("unlock_plan") or []
    assert plan, "expected unlock_plan on license-bearing binary"
    # Primary should be logic gate
    assert plan[0]["kind"] in ("ret_imm", "force_branch")
    if plan[0]["kind"] == "ret_imm":
        assert int(plan[0].get("value") or 1) == 1
