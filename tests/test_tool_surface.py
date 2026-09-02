"""Model-facing tool surface stays small."""

from argus.llm.tools import ARGUS_TOOLS, _canonicalize_tool, dispatch_tool


def test_model_sees_at_most_ten_tools():
    names = [t["function"]["name"] for t in ARGUS_TOOLS]
    assert 5 <= len(names) <= 10
    assert names == sorted(set(names), key=names.index)
    for n in (
        "argus_look",
        "argus_find",
        "argus_peek",
        "argus_diagnose",
        "argus_apply",
        "argus_run",
        "argus_exec",
    ):
        assert n in names
    assert "argus_research" not in names
    assert "argus_atlas" not in names
    assert "argus_patch" not in names
    assert "argus_solve" not in names


def test_aliases_still_dispatch(tmp_path):
    from pathlib import Path

    from tests.conftest import SAMPLES
    import shutil

    bin_path = tmp_path / "app"
    shutil.copy(SAMPLES / "fauxware", bin_path)
    raw = dispatch_tool("argus_look", {"binary": str(bin_path), "for_task": 1})
    import json

    d = json.loads(raw)
    assert d.get("ok") is True
    assert "elf" in str(d.get("summary") or "").lower() or d.get("primary")


def test_canonicalize_diagnose_and_apply():
    assert _canonicalize_tool("argus_apply", {}) == "argus_apply_plan"
    assert (
        _canonicalize_tool("argus_diagnose", {"error_text": "x"}) == "argus_diagnose_failure"
    )
    assert _canonicalize_tool("argus_diagnose", {"query": "x"}) == "argus_slice"
    assert _canonicalize_tool("argus_peek", {"addr": "0x1"}) == "argus_disasm"


def test_dispatch_hints_use_public_names(tmp_path):
    import json
    import shutil

    from tests.conftest import SAMPLES

    bin_path = tmp_path / "app"
    shutil.copy(SAMPLES / "fauxware", bin_path)
    raw = dispatch_tool("argus_find", {"binary": str(bin_path), "query": "password", "for_task": 1})
    d = json.loads(raw)
    blob = json.dumps(d)
    assert "argus_diagnose_failure" not in blob
    assert "argus_apply_plan" not in blob
    assert "argus_atlas" not in blob


def test_task_eval_accepts_public_tool_names():
    from argus.llm.tasks import _is_apply_plan, _is_gui_oracle, _slice_plan_in_trace

    assert _is_apply_plan({"tool": "argus_apply"})
    assert _is_apply_plan({"tool": "argus_apply_plan"})
    assert _is_gui_oracle({"tool": "argus_run", "args": {"reject_texts": ["x"]}})
    assert not _is_gui_oracle({"tool": "argus_run", "args": {}})
    ok, n = _slice_plan_in_trace(
        [{"tool": "argus_diagnose", "result": {"patch_plan": [{"kind": "ret_imm"}]}}]
    )
    assert ok and n == 1
