"""Real-world / research corpus tests.

Tiers:
  A — must fully work (solve / certified CFF)
  B — load + CFG + optional CFF recovery
  C — load + entry CFG smoke (heavy protectors: VMP / Themida)
"""

from __future__ import annotations

from pathlib import Path

import pytest

from argus.binary import load_binary
from argus.deobf import recover_cff
from argus.disasm import build_cfg, build_function_cfg
from argus.ml import Pruner
from argus.symbolic import solve_binary

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def _need(*parts: str) -> Path:
    p = SAMPLES.joinpath(*parts)
    if not p.exists():
        pytest.skip(f"missing {p}")
    return p


# --- Tier A -----------------------------------------------------------------

def test_tier_a_fauxware_solve():
    res = solve_binary(str(_need("fauxware")))
    assert res.success and res.stdin and b"SOSNEAKY" in res.stdin


def test_tier_a_fauxware_fla_cff():
    img = load_binary(_need("fauxware_fla"))
    cfg = build_function_cfg(img, "authenticate")
    report = recover_cff(cfg)
    assert report.state_slot and "0x2c" in report.state_slot
    assert len(report.case_map) >= 4


# --- Tier B: OLLVM ----------------------------------------------------------

OLLVM_ELF64 = [
    ("ollvm", "CFF_full_linux64.bin", "target_function"),
    ("ollvm", "CFF_full_linux64.bin", "main"),
    ("ollvm", "CFF_full_linux64.bin", "calculate_factorial"),
]


@pytest.mark.parametrize("parts_fn", OLLVM_ELF64, ids=lambda t: f"{t[1]}:{t[2]}")
def test_tier_b_ollvm_linux64_cff(parts_fn):
    *parts, fn = parts_fn
    img = load_binary(_need(*parts))
    cfg = build_function_cfg(img, fn)
    assert len(cfg.blocks) >= 3
    report = recover_cff(cfg)
    # Flattened functions should expose a dispatcher; tolerate weak recovery
    assert report.dispatcher is not None
    if fn == "target_function":
        assert report.state_slot is not None
        assert len(report.case_map) >= 2


def test_tier_b_ollvm_linux32_known_addr():
    img = load_binary(_need("ollvm", "CFF_full.bin"))
    # Address from ollvm-unflattener README
    cfg = build_cfg(img, entry=0x8049E00, max_blocks=500)
    assert len(cfg.blocks) >= 5
    report = recover_cff(cfg)
    assert report.dispatcher is not None
    assert report.state_slot is not None
    assert len(report.case_map) >= 2


@pytest.mark.parametrize(
    "rel",
    [
        ("ollvm", "CFF.bin"),
        ("ollvm", "CFF_full.bin"),
        ("ollvm", "CFF_win.exe"),
        ("ollvm", "CFF_win64.exe"),
        ("ollvm", "CFF_win64_full.exe"),
    ],
)
def test_tier_b_ollvm_load_and_entry_cfg(rel):
    path = _need(*rel)
    img = load_binary(path)
    cfg = build_cfg(img, entry=img.entry, max_blocks=400)
    assert img.fmt in ("elf", "pe")
    assert len(cfg.blocks) >= 1


# --- Tier C: VMProtect / Themida -------------------------------------------

VMP_SAMPLES = [
    ("vmp", "hello_world.vmp.exe"),
    ("vmp", "adder.vmp.exe"),
    ("vmp", "bitwise.vmp.exe"),
    ("vmp", "switch.vmp.exe"),
    ("vmp", "control_flow_test.vmp.exe"),
    ("vmp", "control_flow_test.vmp_mutated.exe"),
    ("vmp", "sample1.vmp.bin"),
    ("vmp", "sample2.vmp.bin"),
    ("vmp", "sample3.vmp.bin"),
    ("vmp", "ultrasec.vmp.exe"),
    ("pe", "hello_world_themida_protected.exe"),
    ("pe", "angr_test_sample.exe"),
]


@pytest.mark.parametrize("rel", VMP_SAMPLES, ids=lambda t: t[-1])
def test_tier_c_protector_load(rel):
    img = load_binary(_need(*rel))
    assert img.entry != 0
    assert len(img.sections) >= 1


@pytest.mark.parametrize(
    "rel",
    [
        ("vmp", "hello_world.vmp.exe"),
        ("vmp", "adder.vmp.exe"),
        ("vmp", "control_flow_test.vmp.exe"),
        ("vmp", "sample1.vmp.bin"),
        ("pe", "angr_test_sample.exe"),
    ],
    ids=lambda t: t[-1],
)
def test_tier_c_protector_entry_cfg_smoke(rel):
    img = load_binary(_need(*rel))
    cfg = build_cfg(img, entry=img.entry, max_blocks=250)
    # Protectors often start in stub code — we only require a non-empty CFG attempt
    assert cfg.entry == img.entry
    assert len(cfg.blocks) >= 1


def test_tier_c_ultrasec_is_large_vmp():
    p = _need("vmp", "ultrasec.vmp.exe")
    assert p.stat().st_size > 10_000_000
    img = load_binary(p)
    assert img.fmt == "pe" and img.arch == "x86_64"


def test_certified_prune_on_ollvm_target():
    img = load_binary(_need("ollvm", "CFF_full_linux64.bin"))
    cfg = build_function_cfg(img, "target_function")
    pr = Pruner(require_proof=True).prune(cfg)
    assert "+proof" in pr.backend
    # Must not prune everything
    assert len(pr.kept) >= 1
