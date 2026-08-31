"""Tests for resilient binary copy (WinError 32 / post-GUI lock)."""

from __future__ import annotations

from pathlib import Path

import pytest


def test_copy_binary_resilient_roundtrip(tmp_path):
    from argus.binary.file_io import copy_binary_resilient

    src = tmp_path / "app.bin"
    dst = tmp_path / "out" / "app.bin"
    data = b"MZ" + b"\x90" * 64
    src.write_bytes(data)
    copy_binary_resilient(src, dst, fallback_src=src)
    assert dst.read_bytes() == data


def test_release_binary_lock_no_crash(tmp_path):
    from argus.binary.file_io import release_binary_lock

    p = tmp_path / "nope.exe"
    p.write_bytes(b"x")
    release_binary_lock(p)


def test_sandbox_uses_resilient_copy(tmp_path, monkeypatch):
    from argus.patch.sandbox import test_patch_in_sandbox

    src = tmp_path / "fw"
    src.write_bytes(b"MZ" + b"x" * 128)
    calls: list[tuple] = []

    def fake_copy(s, d, **kw):
        calls.append((Path(s), Path(d)))
        Path(d).write_bytes(Path(s).read_bytes())
        return Path(d)

    monkeypatch.setattr("argus.patch.sandbox.copy_binary_resilient", fake_copy)
    monkeypatch.setattr(
        "argus.patch.sandbox._apply_step_direct",
        lambda path, step: True,
    )
    monkeypatch.setattr(
        "argus.binary.launch_env.stage_native_executable",
        lambda p, **k: type("S", (), {"path": Path(p), "cwd": str(tmp_path), "ephemeral": False})(),
    )
    monkeypatch.setattr(
        "argus.patch.sandbox.verify_binary_semantic",
        lambda *a, **k: {"ok": True, "windows": []},
    )
    res = test_patch_in_sandbox(str(src), [{"kind": "ret_imm", "addr": "0x1000", "value": 1}])
    assert res.get("safe") is True
    assert calls
