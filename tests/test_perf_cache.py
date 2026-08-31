"""Performance: binary cache, slice cache, lazy module scan."""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import patch

import pytest

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_load_binary_cache_hit():
    from argus.binary.image import clear_binary_cache, load_binary

    fw = SAMPLES / "fauxware"
    if not fw.is_file():
        pytest.skip("no fauxware")
    clear_binary_cache()
    a = load_binary(str(fw))
    b = load_binary(str(fw))
    assert a is b


def test_apply_plan_reuses_session_slice_cache():
    from argus.apply_plan import apply_plan
    from argus.llm.session import record_gate_scan_result, reset_session

    fw = str(SAMPLES / "fauxware")
    if not Path(fw).is_file():
        pytest.skip("no fauxware")
    reset_session()
    fake = {
        "ok": True,
        "patch_plan": [],
        "gate_candidates": [],
        "string_hits": [],
        "summary": "cached",
    }
    record_gate_scan_result(fw, [], full=fake, query="license", modules=None, multi=True)

    calls = []

    def boom(*args, **kwargs):
        calls.append(1)
        raise AssertionError("gate_scan_modules should not run when cache warm")

    with patch("argus.apply_plan.gate_scan_modules", side_effect=boom):
        apply_plan(fw, query="license", multi=True, auto_slice=True)
    assert not calls


def test_gate_scan_modules_lazy_skips_extras_when_primary_has_plan(tmp_path):
    from argus.find_slice import gate_scan_modules

    fw = SAMPLES / "fauxware"
    if not fw.is_file():
        pytest.skip("no fauxware")
    primary = tmp_path / "primary"
    extra = tmp_path / "extra.so"
    primary.write_bytes(fw.read_bytes())
    extra.write_bytes(fw.read_bytes())

    n_scan = 0
    import argus.find_slice as fs

    def fake(path, query=None, limit=16):
        nonlocal n_scan
        n_scan += 1
        if Path(path).name == "primary":
            return {
                "ok": True,
                "summary": "hit",
                "gate_candidates": [
                    {
                        "kind": "ret_imm",
                        "addr": "0x1000",
                        "score": 500,
                        "ui_label_only": False,
                        "ret_guess": 1,
                        "reason": "call→cmp==1 large callee size=0x900",
                    }
                ],
                "patch_plan": [
                    {"kind": "ret_imm", "addr": "0x1000", "value": 1, "module": path},
                ],
                "string_hits": [],
            }
        raise AssertionError(f"extra module scan should be skipped, got {path}")

    with patch.object(fs, "gate_scan", side_effect=fake):
        d = gate_scan_modules(str(primary), modules=[str(primary), str(extra)], query="x")
        assert d.get("patch_plan")
        assert n_scan == 1
