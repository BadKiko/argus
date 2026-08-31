"""Wave 1–5 Fast Universal Deobf tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus.binary import load_binary
from argus.deobf import (
    analyze_bogus_cf,
    analyze_vmp_layer,
    deobf_and_patch,
    detect_protection,
    prove_mba_catalog,
    recover_cff,
    solve_after_deobf,
)
from argus.deobf.unflatten import apply_unflatten
from argus.deobf.vmp_layer import DictTraceProvider
from argus.deobf.vm import HandlerSynthesizer
from argus.disasm import build_function_cfg
from argus.patch import Patcher
from argus.pipeline import run_pipeline

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def _need(*parts: str) -> Path:
    p = SAMPLES.joinpath(*parts)
    if not p.exists():
        pytest.skip(f"missing {p}")
    return p


def test_wave1_unflatten_patch_authenticate(tmp_path):
    path = str(_need("fauxware_fla"))
    out = str(tmp_path / "argus_test_fla.deobf")
    img = load_binary(path)
    cfg = build_function_cfg(img, "authenticate")
    before_edges = cfg.graph.number_of_edges()
    report = recover_cff(cfg)
    assert len(report.case_map) >= 4
    patcher = Patcher.from_path(path)
    result = apply_unflatten(patcher, cfg, report)
    assert result.patches_applied >= 3
    assert result.certificate and result.certificate.proven
    patcher.save(out)
    # Patched binary verification
    v = Patcher.from_path(out).verify_runs(stdin=b"SOSNEAKY\nSOSNEAKY\n")
    assert v.get("ok")
    if not v.get("skipped"):
        assert b"Welcome" in (v.get("stdout") or b"")


def test_wave1_solve_after_deobf_fauxware_fla():
    res = solve_after_deobf(str(_need("fauxware_fla")), function="authenticate", find=b"Welcome")
    assert res.success
    assert res.stdin and b"SOSNEAKY" in res.stdin


def test_wave1_ollvm_target_unflatten_certify():
    path = str(_need("ollvm", "CFF_full_linux64.bin"))
    img = load_binary(path)
    cfg = build_function_cfg(img, "target_function")
    report = recover_cff(cfg)
    assert report.dispatcher and report.state_slot
    assert len(report.case_map) >= 2
    patcher = Patcher.from_path(path)
    result = apply_unflatten(patcher, cfg, report)
    # May or may not find constant redirects; certificate present when patches applied
    assert result.report.case_map
    if result.patches_applied:
        assert result.certificate is not None


def test_wave2_mba_catalog_proved():
    rows = prove_mba_catalog()
    proved = [r for r in rows if r.get("proved")]
    assert len(proved) >= 4


def test_wave2_bogus_cf_on_fauxware():
    img = load_binary(_need("fauxware"))
    cfg = build_function_cfg(img, "main")
    rep = analyze_bogus_cf(cfg)
    assert isinstance(rep.hits, list)
    assert any("mba" in n or "proved" in n for n in rep.notes)


def test_wave3_unicorn_runner_optional():
    from argus.concrete import unicorn_available

    if not unicorn_available():
        pytest.skip("unicorn not installed")
    from argus.concrete import concrete_run

    r = concrete_run(str(_need("fauxware")), stdin=b"x\nSOSNEAKY\n")
    assert r.ok or r.steps > 0  # may stop on unsupported syscall; must not crash


def test_wave4_vmp_detect():
    img = load_binary(_need("vmp", "adder.vmp.exe"))
    prot = detect_protection(img)
    assert prot.kind in ("vmp", "mixed", "unknown")
    layer = analyze_vmp_layer(img)
    assert layer.protection.kind == prot.kind
    assert len(layer.stub_blocks) >= 1


def test_wave4_vmp_synth_with_trace():
    synth = HandlerSynthesizer()
    # sanity of synthesizer
    r = synth.synthesize(lambda a, b: (a + b) & 0xFFFFFFFF)
    assert r.name == "add" and r.proved
    img = load_binary(_need("vmp", "sample1.vmp.bin"))
    trace = DictTraceProvider(
        {
            0x10: [(1, 2, 3), (5, 7, 12), (0, 0, 0)],
        }
    )
    layer = analyze_vmp_layer(img, trace=trace)
    assert 0x10 in layer.handlers
    assert layer.handlers[0x10].name == "add"


def test_wave5_run_orchestrator(tmp_path):
    out = str(tmp_path / "argus_run_fla.bin")
    res = run_pipeline(
        str(_need("fauxware_fla")),
        function="authenticate",
        output=out,
        verify_stdin=b"SOSNEAKY\nSOSNEAKY\n",
    )
    assert res.ok
    data = res.report.to_json()
    assert "cff" in data
    assert res.output_path and Path(res.output_path).exists()
