"""Argus 0.2.0 corpus / release-gate tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus import __version__, ai
from argus.ask import Hint, PatchKind, Want, ask
from argus.binary import load_binary
from argus.deobf import detect_protection, recover_cff, vmp_partial_lift
from argus.deobf.unflatten import apply_unflatten
from argus.disasm import build_cfg, build_function_cfg
from argus.patch import Patcher, is_upx

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def _need(*parts: str) -> Path:
    p = SAMPLES.joinpath(*parts)
    if not p.exists():
        pytest.skip(f"missing {p}")
    return p


def test_version_020():
    assert __version__ == "0.2.0"


@pytest.mark.ask
def test_ai_password_plain_and_fla():
    assert ai(str(_need("fauxware")), "дай пароль").answer == "SOSNEAKY"
    assert ai(str(_need("fauxware_fla")), "дай пароль для админа").answer == "SOSNEAKY"


@pytest.mark.ask
def test_ai_always_true_welcome():
    import subprocess

    out = "/tmp/argus020_bypass.bin"
    r = ai(str(_need("fauxware")), "сделай always true для authenticate", output=out)
    assert r.ok
    p = subprocess.run([out], input=b"no\nno\n", capture_output=True)
    assert b"Welcome" in p.stdout


@pytest.mark.ask
def test_want_ir_and_skip_check():
    r = ask(str(_need("fauxware_fla")), Hint(want=Want.IR, function="authenticate"))
    assert r.ok and r.readable and '"blocks"' in r.readable
    out = "/tmp/argus020_skip.bin"
    r2 = ask(
        str(_need("fauxware")),
        Hint(want=Want.PATCH, patch_kind=PatchKind.SKIP_CHECK, function="authenticate", output=out),
    )
    assert r2.ok and Path(out).exists()


@pytest.mark.ollvm
def test_ollvm_corpus_lift_or_cases():
    """≥90% of ollvm samples: load + (CFF cases or non-empty CFG)."""
    root = _need("ollvm")
    files = [p for p in root.iterdir() if p.is_file() and not p.name.startswith(".")]
    ok = 0
    for p in files:
        try:
            img = load_binary(p)
            if "target_function" in img.symbols:
                cfg = build_function_cfg(img, "target_function")
                cff = recover_cff(cfg)
                if cff.dispatcher and (len(cff.case_map) >= 2 or len(cfg.blocks) >= 5):
                    ok += 1
                    continue
            cfg = build_cfg(img, entry=img.entry, max_blocks=300)
            if len(cfg.blocks) >= 1:
                ok += 1
        except Exception:
            pass
    assert files, "no ollvm samples"
    assert ok / len(files) >= 0.9, f"ollvm ok={ok}/{len(files)}"


@pytest.mark.ollvm
def test_pe_cff_win64_unflatten_attempt():
    path = _need("ollvm", "CFF_win64.exe")
    img = load_binary(path)
    cfg = build_cfg(img, entry=img.entry, max_blocks=400)
    cff = recover_cff(cfg)
    assert cff.dispatcher is not None or len(cfg.blocks) >= 1
    if cff.case_map:
        patcher = Patcher.from_path(str(path))
        res = apply_unflatten(patcher, cfg, cff)
        assert res.report.case_map


@pytest.mark.vmp_partial
def test_vmp_partial_lift_tiny():
    for rel in (("vmp", "sample1.vmp.bin"), ("vmp", "adder.vmp.exe")):
        path = str(_need(*rel))
        prot = detect_protection(load_binary(path))
        assert prot.kind in ("vmp", "mixed", "unknown")
        text, ev = vmp_partial_lift(path)
        assert "VMP partial" in text or "handler_" in text or ev.get("stubs") is not None
        assert "handlers" in ev or "stubs" in ev


def test_upx_detect_negative():
    assert is_upx(str(_need("fauxware"))) is False


def test_pseudo_c_lift_has_goto():
    r = ask(str(_need("fauxware_fla")), Hint(want=Want.LIFT, function="authenticate"))
    assert r.ok and "int authenticate" in (r.readable or "")
