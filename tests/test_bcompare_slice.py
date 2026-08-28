"""Beyond Compare / install-dir + vicinity xref regressions."""

from __future__ import annotations

from pathlib import Path

import pytest

BC = Path("/usr/lib/beyondcompare/BCompare")


@pytest.mark.skipif(not BC.is_file(), reason="Beyond Compare not installed")
def test_bcompare_slice_finds_unlock_plan():
    from argus.find_slice import license_slice

    d = license_slice(str(BC), "license")
    plan = d.get("unlock_plan") or []
    assert len(plan) >= 1
    assert all(s.get("module") for s in plan)


@pytest.mark.skipif(not BC.is_file(), reason="Beyond Compare not installed")
def test_work_copy_slice_uses_install_dir(monkeypatch):
    from argus.find_slice import license_slice_modules
    from argus.llm.session import get_session, reset_session
    from argus.llm.workspace import prepare_work_binary

    reset_session()
    work, orig = prepare_work_binary(str(BC))
    sess = get_session()
    sess.work_binary = work
    sess.original_binary = orig
    sess.install_dir = str(Path(orig).parent)

    d = license_slice_modules(work, query="license", auto_widen=True, max_modules=6)
    plan = d.get("unlock_plan") or []
    assert len(plan) >= 1
    mods = d.get("modules") or []
    assert any(Path(m).name == "BCompare" for m in mods)
