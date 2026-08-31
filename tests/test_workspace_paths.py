"""Workspace path resolution tests."""

from __future__ import annotations

from pathlib import Path


def test_default_patch_output_no_double_suffix(tmp_path):
    from argus.llm.workspace import default_patch_output

    p = tmp_path / "app.exe.patched"
    assert default_patch_output(str(p)) == str(tmp_path / "app.exe.patched")


def test_resolve_missing_argus_work_path(tmp_path):
    from argus.llm.workspace import resolve_work_binary_path

    orig = tmp_path / "app.exe"
    orig.write_bytes(b"MZ")
    work = tmp_path / ".argus-work" / "app.exe"
    work.parent.mkdir()
    work.write_bytes(b"MZ-work")
    missing = str(tmp_path / ".argus-work" / "app.exe")
    resolved = resolve_work_binary_path(missing, work_binary=str(work), original_binary=str(orig))
    assert Path(resolved).is_file()
