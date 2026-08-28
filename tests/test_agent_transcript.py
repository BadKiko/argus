"""Agent transcript + discover primary heuristics."""

from __future__ import annotations

import json
import stat
from pathlib import Path

from argus.discover import _pick_primary, discover_targets


def test_pick_primary_prefers_app_over_near_scored_so(tmp_path):
    app = tmp_path / "BCompare"
    lib = tmp_path / "libcloudstorage.so.22.0"
    app.write_bytes(b"\x7fELF" + b"\0" * 128 + b"invalid license\x00")
    lib.write_bytes(b"\x7fELF" + b"\0" * 128 + b"invalid license\x00Unregistered\x00")
    app.chmod(app.stat().st_mode | stat.S_IXUSR)

    ranked = [
        (3, lib.resolve()),
        (2, app.resolve()),
    ]
    assert _pick_primary(ranked).name == "BCompare"


def test_pick_primary_keeps_clear_so_winner(tmp_path):
    app = tmp_path / "app"
    lib = tmp_path / "libhelper.so"
    app.write_bytes(b"\x7fELF" + b"\0" * 64 + b"license\x00")
    lib.write_bytes(b"\x7fELF" + b"\0" * 64 + b"license\x00" * 20)
    app.chmod(app.stat().st_mode | stat.S_IXUSR)

    ranked = [
        (40, lib.resolve()),
        (2, app.resolve()),
    ]
    assert _pick_primary(ranked).name == "libhelper.so"


def test_transcript_writes_jsonl(tmp_path):
    from argus.llm.transcript import AgentTranscript

    path = tmp_path / "run.jsonl"
    tx = AgentTranscript(path=path)
    tx.session_start(user_prompt="unlock")
    tx.initial_prompt("hello binary")
    tx.step_begin(1, provider="gemini", model="test")
    tx.model_response(1, text="", tool_calls=[{"name": "argus_slice", "args": {"binary": "/x"}}])
    tx.tool_begin(1, "argus_slice", {"binary": "/x"})
    tx.tool_result(1, "argus_slice", {"binary": "/x"}, '{"ok":true}', injected_binary="/work/x")
    tx.session_end(ok=False, steps=1)
    tx.close()

    lines = [json.loads(ln) for ln in path.read_text(encoding="utf-8").splitlines()]
    events = [r["event"] for r in lines]
    assert events == [
        "session_start",
        "initial_prompt",
        "step_begin",
        "model_response",
        "tool_begin",
        "tool_result",
        "session_end",
    ]
    tool_res = [r for r in lines if r["event"] == "tool_result"][0]
    assert tool_res["injected_binary"] == "/work/x"
    assert lines[-1]["event"] == "session_end"


def test_resolve_transcript_default_on(tmp_path, monkeypatch):
    from argus.llm.transcript import resolve_transcript

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("ARGUS_AGENT_TRANSCRIPT", raising=False)
    tx = resolve_transcript()
    assert tx is not None
    assert tx.path == tmp_path / ".cache" / "argus" / "current.jsonl"
    tx.session_start(test=1)
    tx.close()
    assert (tmp_path / ".cache" / "argus" / "current.jsonl").is_file()


def test_note_accepts_detail_kwarg(tmp_path):
    from argus.llm.transcript import AgentTranscript

    path = tmp_path / "n.jsonl"
    tx = AgentTranscript(path=path)
    tx.note("gemini_status", detail="retry in 60s")
    tx.close()
    rec = json.loads(path.read_text(encoding="utf-8").strip())
    assert rec["kind"] == "gemini_status"
    assert rec["detail"] == "retry in 60s"


def test_resolve_transcript_disabled(monkeypatch):
    from argus.llm.transcript import resolve_transcript

    monkeypatch.setenv("ARGUS_AGENT_TRANSCRIPT", "0")
    assert resolve_transcript() is None
    assert resolve_transcript(enabled=False) is None


def test_discover_prefers_executable_in_fixture(tmp_path):
    app = tmp_path / "main_app"
    lib = tmp_path / "liblicense.so"
    needle = b"Unregistered\x00invalid license\x00"
    app.write_bytes(b"\x7fELF" + b"\0" * 200 + needle)
    lib.write_bytes(b"\x7fELF" + b"\0" * 200 + needle + b"extra\x00")
    app.chmod(app.stat().st_mode | stat.S_IXUSR)

    d = discover_targets("remove license", root=str(tmp_path))
    assert Path(d["primary"]).name == "main_app"
