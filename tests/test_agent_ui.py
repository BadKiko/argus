"""Interactive agent UI helpers."""

from __future__ import annotations

from argus.cli.agent_ui import build_retry_prompt
from argus.llm.agent import AgentResult
from argus.memory.case import build_case_report


def test_build_retry_prompt_includes_feedback():
    res = AgentResult(
        ok=False,
        answer="",
        tool_trace=[
            {"tool": "argus_slice", "args": {"binary": "x"}, "result": {"ok": True}},
        ],
    )
    p = build_retry_prompt("remove license", "still prompts for password", res)
    assert "remove license" in p
    assert "still prompts" in p
    assert "argus_slice" in p


def test_user_confirmed_success_overrides_outcome():
    from pathlib import Path

    fw = Path(__file__).resolve().parents[1] / "samples" / "fauxware"
    if not fw.is_file():
        return
    trace = [
        {
            "tool": "argus_patch",
            "result": {"ok": True, "verify": {"kind": "none"}},
        }
    ]
    statuses = [{"id": 1, "text": "patch ui", "status": "incomplete", "detail": "no verify"}]
    report = build_case_report(
        str(fw),
        "patch ui",
        trace,
        statuses,
        outcome_override="success",
        user_confirmed=True,
        user_feedback="",
    )
    assert report is not None
    assert report["outcome"] == "success"
    assert report["features"].get("user_confirmed") is True


def test_user_feedback_on_failure():
    from pathlib import Path

    fw = Path(__file__).resolve().parents[1] / "samples" / "fauxware"
    if not fw.is_file():
        return
    report = build_case_report(
        str(fw),
        "unlock",
        [{"tool": "argus_slice", "result": {"ok": True, "patch_plan": []}}],
        [{"id": 1, "text": "unlock", "status": "incomplete", "detail": "empty plan"}],
        outcome_override="failed",
        user_feedback="Go away still prints",
        user_confirmed=True,
    )
    assert report is not None
    assert report["outcome"] == "failed"
    assert "Go away" in report["features"].get("user_feedback", "")
    assert "Go away" in report["failure_modes"][0]


def test_runtime_launch_in_failure_modes():
    from pathlib import Path

    fw = Path(__file__).resolve().parents[1] / "samples" / "fauxware"
    if not fw.is_file():
        return
    report = build_case_report(
        str(fw),
        "gate transform",
        [{"tool": "argus_apply_plan", "result": {"ok": True, "verify": {"ok": True}}}],
        [{"id": 1, "text": "gate", "status": "done", "detail": "ok"}],
        outcome_override="failed",
        user_feedback="exit=127 loader",
        runtime_launch={
            "exit_code": 127,
            "stderr": "lib7z.so: cannot open shared object file",
            "error_kind": "loader_error",
            "cwd": "/usr/lib/beyondcompare",
            "ld_library_path": "/usr/lib/beyondcompare",
        },
    )
    assert report is not None
    assert report["features"]["runtime_launch"]["exit_code"] == 127
    assert any("lib7z" in m or "loader" in m for m in report["failure_modes"])


def test_launch_env_uses_install_dir(monkeypatch):
    from pathlib import Path

    from argus.cli.agent_ui import _launch_env
    from argus.llm.session import reset_session

    reset_session()
    from argus.llm.session import get_session

    get_session().install_dir = "/usr/lib/beyondcompare"
    cwd, env = _launch_env(Path("/tmp/ws/BCompare.patched"))
    assert cwd == "/usr/lib/beyondcompare"
    assert "/usr/lib/beyondcompare" in env["LD_LIBRARY_PATH"]


def test_launch_failed_detects_loader_error():
    from argus.cli.agent_ui import LaunchResult, launch_failed, launch_failure_feedback

    r = LaunchResult(
        ok=False,
        exit_code=127,
        stderr="error while loading shared libraries: lib7z.so",
        error_kind="loader_error",
        cwd="/usr/lib/beyondcompare",
        ld_library_path="/usr/lib/beyondcompare",
    )
    assert launch_failed(r)
    assert "lib7z" in launch_failure_feedback(r) or "exit=127" in launch_failure_feedback(r)
