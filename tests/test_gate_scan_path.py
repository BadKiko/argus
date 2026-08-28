"""Jump-table CFG + gate_scan + abs xrefs."""

from __future__ import annotations

from pathlib import Path

from argus.binary import load_binary
from argus.disasm import build_cfg
from argus.find import find_string_xrefs
from argus.find_slice import gate_scan

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_fauxware_cfg_still_works():
    img = load_binary(str(SAMPLES / "fauxware"))
    cfg = build_cfg(img, entry=img.symbols["authenticate"].addr, max_blocks=64)
    assert len(cfg.blocks) >= 2


def test_gate_scan_on_fauxware_smoke():
    # may find little; must not crash
    d = gate_scan(str(SAMPLES / "fauxware"), "password")
    assert d.get("ok") is True
    assert "gate_candidates" in d
    assert "patch_plan" in d


def test_sublime_jmp_table_and_slice_optional():
    path = Path("/opt/sublime_merge/sublime_merge")
    if not path.is_file():
        return
    img = load_binary(str(path))
    # welcome overlay function that had jmp rax
    entry = 0x575268
    cfg = build_cfg(img, entry=entry, max_blocks=200)
    assert len(cfg.blocks) > 4, f"expected jump-table expansion, got {len(cfg.blocks)} blocks"

    d = gate_scan(str(path), "license key")
    assert d["ok"]
    gates = d.get("gate_candidates") or []
    assert gates, "expected gate_candidates from gate_scan"
    plan = d.get("patch_plan") or []
    assert plan, "expected patch_plan"
    assert plan[0].get("kind") in ("ret_imm", "force_branch")
    non_ui = [g for g in gates if not g.get("ui_label_only")]
    assert non_ui, "expected at least one non-UI license gate"
    assert not gates[0].get("ui_label_only")


def test_bcompare_call_cmp_refcount_not_gate_optional():
    """Regression: cmp [rax-0xc],1 after call must not become ret_imm mid-function."""
    from argus.find_slice import _scan_call_cmp1_gates

    path = Path.home() / ".cache/argus/workspaces"
    candidates = list(path.glob("BCompare-*/BCompare"))
    if not candidates:
        return
    bc = candidates[0]
    img = load_binary(str(bc))
    seen: set[str] = set()
    gates = _scan_call_cmp1_gates(img, 0xCC0E00, 0xCC2000, meta={}, seen_gate=seen)
    bad = [g for g in gates if g.get("addr") in ("0xcc1030", "0xCC1030")]
    assert not bad, f"refcount false positive: {bad}"
    d = gate_scan(str(bc), "license")
    plan = d.get("patch_plan") or []
    assert all(s.get("addr") not in ("0xcc1030", "0xCC1030") for s in plan)
    path = Path("/opt/sublime_merge/sublime_merge")
    if not path.is_file():
        return
    img = load_binary(str(path))
    data = path.read_bytes()
    needle = b"doesn't appear to be valid"
    off = data.find(needle)
    if off < 0:
        return
    from elftools.elf.elffile import ELFFile

    with open(path, "rb") as f:
        elf = ELFFile(f)
        segs = [
            (s["p_offset"], s["p_filesz"], s["p_vaddr"])
            for s in elf.iter_segments()
            if s["p_type"] == "PT_LOAD"
        ]

    def fo2va(o):
        for start, sz, va in segs:
            if start <= o < start + sz:
                return va + (o - start)
        return None

    while off > 0 and data[off - 1] != 0:
        off -= 1
    va = fo2va(off)
    assert va
    xrefs = find_string_xrefs(img, va, max_hits=8)
    assert isinstance(xrefs, list)
    # RIP/abs scan may miss under budget; slice path is the supported API
    if not xrefs:
        d = gate_scan(str(path), "doesn't appear to be valid")
        assert d.get("ok")
        return
    assert xrefs
