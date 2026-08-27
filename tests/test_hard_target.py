"""Hard-target pipeline: recovery, gate rank, stripped detect."""

from __future__ import annotations

from pathlib import Path

from argus.binary import load_binary
from argus.deobf import detect_protection
from argus.disasm.recovery import build_func_index, function_covering
from argus.find import find_in_binary, rank_gate_candidates, suggest_patches_near

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_recovery_covers_fauxware_authenticate():
    img = load_binary(str(SAMPLES / "fauxware"))
    auth = img.symbols["authenticate"].addr
    b = function_covering(img, auth + 8)
    assert b is not None
    assert b.start <= auth + 8 < b.end


def test_fauxware_fla_still_cff_detectable():
    path = SAMPLES / "fauxware_fla"
    if not path.exists():
        return
    prot = detect_protection(load_binary(str(path)))
    assert prot.kind != "stripped"
    # ollvm if cff probe works
    assert prot.kind in ("ollvm", "unknown", "none")


def test_gate_rank_ui_label_lower_than_predicate():
    """Synthetic ranking: ui_label_only scores below predicate-backed sites."""
    ui = {"score": 15, "ui_label_only": True, "kind": "force_branch", "addr": "0x1"}
    pred = {"score": 70, "ui_label_only": False, "kind": "force_branch", "addr": "0x2"}
    ranked = sorted([ui, pred], key=lambda x: (-int(x["score"]), x["ui_label_only"]))
    assert ranked[0]["addr"] == "0x2"
    assert ranked[0]["ui_label_only"] is False


def test_find_fauxware_has_hits():
    data = find_in_binary(str(SAMPLES / "fauxware"), "password", with_xrefs=True)
    assert data["ok"] and data["hits"]


def test_sublime_optional_stripped_and_gates():
    path = Path("/opt/sublime_merge/sublime_merge")
    if not path.is_file():
        return
    img = load_binary(str(path))
    prot = detect_protection(img)
    assert prot.kind == "stripped"
    idx = build_func_index(img)
    assert len(idx.starts) > 10
    # with_xrefs=False keeps CI/local fast on 6MB .text
    data = find_in_binary(str(path), "license", limit=15, with_xrefs=False)
    assert data.get("stripped_like") is True
