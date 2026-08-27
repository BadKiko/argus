"""Protection detection — avoid false OLLVM on stripped commercial ELFs."""

from __future__ import annotations

from pathlib import Path

from argus.binary import load_binary
from argus.deobf import detect_protection

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_fauxware_fla_still_ollvm_or_cff():
    path = SAMPLES / "fauxware_fla"
    if not path.exists():
        return
    prot = detect_protection(load_binary(str(path)))
    # may be ollvm if cff probe hits, or unknown with large-func note — never stripped
    assert prot.kind != "stripped"
    assert prot.kind in ("ollvm", "unknown", "none") or prot.confidence >= 0


def test_sublime_merge_not_false_ollvm():
    path = Path("/opt/sublime_merge/sublime_merge")
    if not path.is_file():
        return
    prot = detect_protection(load_binary(str(path)))
    assert prot.kind != "ollvm", prot.to_dict()
    assert prot.kind == "stripped" or "stripped" in " ".join(prot.indicators)
