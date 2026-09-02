"""Commercial protection foundation — detect, brief, observe, find guard."""

from __future__ import annotations

from pathlib import Path

from argus.binary import load_binary
from argus.binary.image import BinaryImage, Section
from argus.deobf import analyze_commercial, detect_protection, is_commercial_kind
from argus.deobf.commercial import commercial_find_guard, commercial_observe_plan
from argus.find import find_in_binary
from argus.payload import build_target_brief, format_brief_text

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def _fake_denuvo_image() -> BinaryImage:
    text = b"\x90" * 8192 + b"Denuvo Anti-Tamper\x00"
    return BinaryImage(
        path="/tmp/fake_denuvo.exe",
        fmt="pe",
        arch="x86_64",
        bits=64,
        entry=0x1000,
        sections=[
            Section(name=".text", addr=0x1000, size=len(text), data=text, executable=True),
            Section(name=".bind", addr=0x3000, size=4096, data=b"\x00" * 4096),
            Section(name=".arch", addr=0x4000, size=4096, data=b"\xcc" * 4096),
        ],
        symbols={},
        imports={},
        memory={},
    )


def test_is_commercial_kind():
    assert is_commercial_kind("vmp")
    assert is_commercial_kind("themida")
    assert is_commercial_kind("denuvo")
    assert is_commercial_kind("mixed")
    assert not is_commercial_kind("stripped")
    assert not is_commercial_kind("none")


def test_themida_sample_commercial_brief():
    path = SAMPLES / "pe" / "hello_world_themida_protected.exe"
    if not path.exists():
        return
    img = load_binary(str(path))
    prot = detect_protection(img)
    assert prot.kind == "themida"
    comm = analyze_commercial(img)
    assert comm.tier == "commercial"
    assert comm.workflow == "themida_vm"
    assert comm.next_hint
    assert "argus_run" in comm.next_hint


def test_vmp_sample_commercial_brief():
    path = SAMPLES / "vmp" / "hello_world.vmp.exe"
    if not path.exists():
        return
    comm = analyze_commercial(load_binary(str(path)))
    assert comm.tier == "commercial"
    assert comm.workflow == "vmp_vm"


def test_denuvo_detect_synthetic():
    img = _fake_denuvo_image()
    prot = detect_protection(img)
    assert prot.kind == "denuvo"
    comm = analyze_commercial(img)
    assert comm.tier == "commercial"
    assert comm.workflow == "denuvo_at"


def test_build_target_brief_includes_commercial():
    path = SAMPLES / "pe" / "hello_world_themida_protected.exe"
    if not path.exists():
        return
    brief = build_target_brief(path)
    assert brief.get("commercial", {}).get("tier") == "commercial"
    text = format_brief_text(brief)
    assert "COMMERCIAL PROTECTION" in text
    assert "themida" in text.lower()


def test_commercial_observe_plan_runtime_first():
    path = SAMPLES / "vmp" / "hello_world.vmp.exe"
    if not path.exists():
        return
    brief = build_target_brief(path)
    plan = commercial_observe_plan(brief, "unlock trial license check")
    assert plan is not None
    assert plan.get("commercial") is True
    assert plan.get("check_first")
    assert "runtime" in (plan.get("notes") or "").lower() or "commercial" in (plan.get("notes") or "").lower()


def test_find_guard_redirects_commercial():
    path = SAMPLES / "vmp" / "hello_world.vmp.exe"
    if not path.exists():
        return
    data = find_in_binary(str(path), "license")
    assert "commercial" in (data.get("summary") or "").lower() or data.get("commercial")
    assert "argus_run" in (data.get("next_hint") or "")


def test_commercial_find_guard_overlay():
    path = SAMPLES / "pe" / "hello_world_themida_protected.exe"
    if not path.exists():
        return
    overlay = commercial_find_guard(load_binary(str(path)))
    assert overlay is not None
    assert overlay.get("commercial_tier") == "commercial"
    assert overlay.get("blocked_patterns")
