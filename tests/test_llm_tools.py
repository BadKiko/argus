"""LLM tools dispatch (no network)."""

from __future__ import annotations

import json
from pathlib import Path

from argus.llm.tools import ARGUS_TOOLS, dispatch_tool
from argus.llm.gemini import openai_tools_to_gemini
from argus.llm.agent import resolve_provider

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_tools_schema_nonempty():
    assert len(ARGUS_TOOLS) >= 5
    names = {t["function"]["name"] for t in ARGUS_TOOLS}
    assert "argus_ai" in names and "argus_solve" in names


def test_dispatch_argus_ai_password():
    path = str(SAMPLES / "fauxware")
    # fauxware has `accepted` symbol — solve works without hardcoded Welcome default
    out = dispatch_tool("argus_ai", {"prompt": "дай пароль", "binary": path})
    data = json.loads(out)
    assert data.get("ok") is True
    assert data.get("answer") == "SOSNEAKY"
    assert "summary" in data


def test_dispatch_detect_and_analyze():
    path = str(SAMPLES / "fauxware_fla")
    d = json.loads(dispatch_tool("argus_detect", {"binary": path}))
    assert "kind" in d or (d.get("evidence") or {}).get("kind")
    a = json.loads(dispatch_tool("argus_analyze", {"binary": path}))
    assert a.get("fmt") == "elf"
    assert "summary" in a


def test_gemini_tool_conversion():
    g = openai_tools_to_gemini(ARGUS_TOOLS)
    assert g and "functionDeclarations" in g[0]
    assert any(d["name"] == "argus_solve" for d in g[0]["functionDeclarations"])


def test_resolve_provider(monkeypatch):
    monkeypatch.delenv("ARGUS_GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("ARGUS_LLM_PROVIDER", raising=False)
    assert resolve_provider("gemini") == "gemini"
    assert resolve_provider("openai") == "openai"
    monkeypatch.setenv("GEMINI_API_KEY", "x")
    assert resolve_provider("auto") == "gemini"


def test_dispatch_argus_exec(tmp_path, monkeypatch):
    # Test python execution
    res1 = json.loads(dispatch_tool("argus_exec", {"binary": "", "code": "print('ARGUS_EXEC_OK')"}))
    assert res1.get("ok") is True
    assert "ARGUS_EXEC_OK" in res1.get("stdout", "")

    # Test python execution with save_as (stored in exec workspace, not install dir)
    script_name = "test_script.py"
    res2 = json.loads(
        dispatch_tool(
            "argus_exec",
            {"binary": str(tmp_path / "dummy"), "code": "print('SAVED_SCRIPT')", "save_as": script_name},
        )
    )
    assert res2.get("ok") is True
    assert "SAVED_SCRIPT" in res2.get("stdout", "")
    script_path = (res2.get("evidence") or {}).get("script_path")
    assert script_path and Path(script_path).is_file()

    # Shell disabled unless ARGUS_EXEC_SHELL=1
    res3 = json.loads(
        dispatch_tool("argus_exec", {"binary": "", "code": "echo SHELL_EXEC_OK", "language": "shell"})
    )
    assert res3.get("ok") is False
    monkeypatch.setenv("ARGUS_EXEC_SHELL", "1")
    res4 = json.loads(
        dispatch_tool("argus_exec", {"binary": "", "code": "echo SHELL_EXEC_OK", "language": "shell"})
    )
    assert res4.get("ok") is True
    assert "SHELL_EXEC_OK" in res4.get("stdout", "")


def test_dispatch_argus_disasm():
    from pathlib import Path
    sample = Path("samples/fauxware_fla")
    if not sample.exists():
        return
    res = json.loads(
        dispatch_tool(
            "argus_disasm",
            {"binary": str(sample), "addr": "0x40071d", "count": 5},
        )
    )
    assert res.get("ok") is True
    assert "disassembly" in res
    assert res.get("count") > 0


def test_dispatch_argus_decision_flow():
    from pathlib import Path
    sample = Path("samples/fauxware_fla")
    if not sample.exists():
        return
    res = json.loads(
        dispatch_tool(
            "argus_decision_flow",
            {"binary": str(sample), "target": "0x40071d"},
        )
    )
    assert res.get("ok") is True
    assert "decision_flow" in res


def test_dispatch_argus_diagnose_failure():
    from pathlib import Path
    sample = Path("samples/fauxware_fla")
    if not sample.exists():
        return
    res = json.loads(
        dispatch_tool(
            "argus_diagnose_failure",
            {"binary": str(sample), "crash_code": "0xC0000005"},
        )
    )
    assert res.get("ok") is True
    assert "root_cause" in res


def test_dispatch_argus_state_flags():
    from pathlib import Path
    sample = Path("samples/fauxware_fla")
    if not sample.exists():
        return
    res = json.loads(
        dispatch_tool(
            "argus_state_flags",
            {"binary": str(sample), "min_reads": 1},
        )
    )
    assert res.get("ok") is True
    assert "flags" in res


def test_dispatch_argus_sandbox_test():
    from pathlib import Path
    sample = Path("samples/fauxware_fla")
    if not sample.exists():
        return
    res = json.loads(
        dispatch_tool(
            "argus_sandbox_test",
            {
                "binary": str(sample),
                "steps": [{"kind": "force_branch", "addr": "0x40071d", "taken": True}],
            },
        )
    )
    assert "safe" in res
