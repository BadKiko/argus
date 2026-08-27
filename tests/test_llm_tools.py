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
    assert any(d["name"] == "argus_ai" for d in g[0]["functionDeclarations"])


def test_resolve_provider(monkeypatch):
    monkeypatch.delenv("ARGUS_GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("ARGUS_LLM_PROVIDER", raising=False)
    assert resolve_provider("gemini") == "gemini"
    assert resolve_provider("openai") == "openai"
    monkeypatch.setenv("GEMINI_API_KEY", "x")
    assert resolve_provider("auto") == "gemini"
