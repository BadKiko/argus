"""Client-side memory tests."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_build_case_report_from_trace():
    from argus.memory.case import build_case_report

    trace = [
        {
            "tool": "argus_slice",
            "result": json.dumps(
                {
                    "ok": True,
                    "summary": "gates=3",
                    "patch_plan": [{"kind": "ret_imm", "addr": "0x1000", "value": 1}],
                    "verify": {"kind": "none"},
                }
            ),
        },
        {
            "tool": "argus_apply_plan",
            "result": json.dumps(
                {
                    "ok": True,
                    "plan_source": "slice",
                    "slice_plan_len": 1,
                    "verify": {"kind": "patch_bytes", "ok": True},
                    "patch_plan": [{"module": "/tmp/libfoo.so", "kind": "ret_imm", "addr": "0x1000"}],
                }
            ),
        },
    ]
    statuses = [{"id": 1, "text": "unlock license", "status": "done", "detail": "patch_bytes ok"}]
    fw = str(SAMPLES / "fauxware")
    report = build_case_report(fw, "unlock license", trace, statuses, steps=5)
    assert report is not None
    assert report["binary_hash"].startswith("sha256:")
    assert report["format"] == "elf"
    assert report["outcome"] == "success"
    assert report["plan_sourced"] is True
    assert report["verification_level"] == "BYTES_VERIFIED"
    assert any(s["tool"] == "argus_apply_plan" for s in report["strategies"])


def test_memory_client_push(monkeypatch):
    from argus.memory.client import MemoryClient

    mock_resp = MagicMock()
    mock_resp.json.return_value = {"ok": True, "case_id": "test-id"}
    mock_resp.raise_for_status = MagicMock()

    mock_http = MagicMock()
    mock_http.__enter__ = MagicMock(return_value=mock_http)
    mock_http.__exit__ = MagicMock(return_value=False)
    mock_http.post.return_value = mock_resp

    with patch("argus.memory.client.httpx") as hx:
        hx.Client.return_value = mock_http
        client = MemoryClient("https://example.com")
        cid = client.push_case({"binary_hash": "sha256:" + "b" * 64, "task": "x"})
        assert cid == "test-id"


def test_retrieve_hints_format(monkeypatch):
    from argus.memory import retrieve_hints

    monkeypatch.setenv("ARGUS_MEMORY_URL", "https://example.com")
    monkeypatch.setenv("ARGUS_MEMORY", "1")

    with patch("argus.memory.retrieve.MemoryClient") as MC:
        inst = MC.return_value
        inst.available = True
        inst.search_hints.return_value = [
            {"score": 0.9, "outcome": "success", "summary": "slice+apply_plan", "verification_level": "EXECUTION_VERIFIED"}
        ]
        block = retrieve_hints(str(SAMPLES / "fauxware"), "unlock license")
        assert "Prior experience" in block
        assert "slice+apply_plan" in block


def test_memory_enabled_by_default():
    import os

    from argus.memory.client import DEFAULT_MEMORY_URL, memory_enabled, memory_url

    old_url = os.environ.pop("ARGUS_MEMORY_URL", None)
    old_flag = os.environ.pop("ARGUS_MEMORY", None)
    try:
        assert memory_url() == DEFAULT_MEMORY_URL
        assert memory_enabled() is True
    finally:
        if old_url is not None:
            os.environ["ARGUS_MEMORY_URL"] = old_url
        if old_flag is not None:
            os.environ["ARGUS_MEMORY"] = old_flag


def test_memory_disabled_with_flag(monkeypatch):
    from argus.memory.client import memory_enabled

    monkeypatch.setenv("ARGUS_MEMORY", "0")
    assert memory_enabled() is False


def test_memory_privacy_notice_mentions_opt_out():
    from argus.memory.client import memory_privacy_notice

    text = memory_privacy_notice()
    assert "ARGUS_MEMORY=0" in text
    assert "argus.cloud.badkiko.ru" in text


def test_memory_disabled_without_url(monkeypatch):
    from argus.memory.client import memory_enabled

    monkeypatch.setenv("ARGUS_MEMORY", "0")
    assert memory_enabled() is False


def test_build_user_content_includes_memory():
    from argus.llm.agent import _build_user_content

    content = _build_user_content(
        "unlock",
        "/tmp/bin",
        "TASKS:\n1. unlock",
        memory_hints="Prior experience:\n  [0.9 success] slice+apply_plan",
    )
    assert "Prior experience" in content
