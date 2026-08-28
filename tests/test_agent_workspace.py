"""Agent workspace + never-give-up research loop."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from argus.llm.research import tasks_all_done
from argus.llm.session import reset_session
from argus.llm.tasks import split_user_tasks
from argus.llm.workspace import prepare_work_binary, rewrite_tool_paths


SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_prepare_work_binary_copies_original(tmp_path):
    src = tmp_path / "fw"
    shutil.copy(SAMPLES / "fauxware", src)
    work, orig = prepare_work_binary(str(src))
    assert Path(work).is_file()
    assert Path(orig).resolve() == src.resolve()
    assert Path(work).resolve() != src.resolve()
    assert Path(work).read_bytes() == src.read_bytes()


def test_prepare_work_binary_uses_cache_when_local_not_writable(tmp_path, monkeypatch):
    src = tmp_path / "fw"
    shutil.copy(SAMPLES / "fauxware", src)
    cache = tmp_path / "cache"
    monkeypatch.setenv("ARGUS_WORK_DIR", str(cache))

    import argus.llm.workspace as ws

    local = src.parent / ".argus-work"
    real_writable = ws._writable_dir

    def fake_writable(p: Path) -> bool:
        if p == local:
            return False
        return real_writable(p)

    monkeypatch.setattr(ws, "_writable_dir", fake_writable)

    work, orig = prepare_work_binary(str(src))
    assert Path(work).is_file()
    assert Path(orig).resolve() == src.resolve()
    assert cache in Path(work).parents


def test_rewrite_tool_paths_blocks_original_output(tmp_path):
    src = tmp_path / "fw"
    shutil.copy(SAMPLES / "fauxware", src)
    work, orig = prepare_work_binary(str(src))
    args = rewrite_tool_paths(
        {"binary": orig, "output": orig, "kind": "ret_imm"},
        work_binary=work,
        original_binary=orig,
    )
    assert args["binary"] == work
    assert args["output"] != orig
    assert "patched" in args["output"] or ".argus-work" in args["output"]


def test_tasks_all_done_after_password_ai():
    from argus.llm.tools import dispatch_tool
    import json

    fw = SAMPLES / "fauxware"
    if not fw.is_file():
        pytest.skip("no fauxware")
    path = str(fw)
    ai = json.loads(dispatch_tool("argus_ai", {"prompt": "какой пароль?", "binary": path, "for_task": 1}))
    tasks = split_user_tasks("какой пароль?")
    trace = [{"tool": "argus_ai", "args": {"binary": path, "for_task": 1}, "result": ai}]
    assert tasks_all_done(tasks, trace, binary=path)


def test_dispatch_never_writes_original(tmp_path):
    from argus.llm.tools import dispatch_tool
    import json

    src = tmp_path / "fw"
    shutil.copy(SAMPLES / "fauxware", src)
    before = src.read_bytes()
    reset_session()
    work, orig = prepare_work_binary(str(src))
    from argus.llm.session import get_session

    sess = get_session()
    sess.work_binary = work
    sess.original_binary = orig

    raw = dispatch_tool(
        "argus_patch",
        {"binary": orig, "kind": "ret_imm", "addr": "0x400664", "value": 1, "output": orig},
    )
    data = json.loads(raw)
    assert data.get("ok") is True
    assert src.read_bytes() == before
    patched = data.get("patched_path") or (data.get("evidence") or {}).get("patched_path")
    assert patched
    assert Path(patched).resolve() != src.resolve()
