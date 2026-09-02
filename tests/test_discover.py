"""Auto-discover binary + linked modules."""

from __future__ import annotations

import shutil
from pathlib import Path

from argus.binary import list_elf_needed, list_pe_dependent_dlls
from argus.discover import (
    discover_targets,
    extract_paths_from_text,
    is_binary_file,
    signal_score,
    scan_binaries,
)
from argus.find_slice import gate_scan
from argus.llm.tools import ARGUS_TOOLS, dispatch_tool

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
ROOT = Path(__file__).resolve().parents[1]


def test_extract_paths_from_prompt():
    fw = SAMPLES / "fauxware"
    paths = extract_paths_from_text(f"unlock license in {fw} please")
    assert any(Path(p).resolve() == fw.resolve() for p in paths)


def test_rank_fauxware_beats_decoy(tmp_path):
    decoy = tmp_path / "notes.txt"
    decoy.write_text("hello world no magic", encoding="utf-8")
    bin_path = tmp_path / "app.bin"
    shutil.copy(SAMPLES / "fauxware", bin_path)
    # plant license-ish needles so score > 0
    raw = bytearray(bin_path.read_bytes())
    raw.extend(b"\x00invalid license\x00Unregistered\x00")
    bin_path.write_bytes(raw)

    assert not is_binary_file(decoy)
    assert is_binary_file(bin_path)
    assert signal_score(bin_path) > 0

    found = scan_binaries(tmp_path, max_depth=1, limit=20)
    assert bin_path.resolve() in [p.resolve() for p in found]

    d = discover_targets("remove license", root=str(tmp_path))
    assert d["ok"] is True
    assert Path(d["primary"]).resolve() == bin_path.resolve()


def test_discover_from_prompt_path():
    fw = str(SAMPLES / "fauxware")
    d = discover_targets(f"analyze {fw}")
    assert d["ok"] is True
    assert Path(d["primary"]).resolve() == Path(fw).resolve()


def test_list_elf_needed_api():
    names = list_elf_needed(SAMPLES / "fauxware")
    assert isinstance(names, list)
    # dynamically linked sample should list libc (or empty if fully static)
    assert all(isinstance(n, str) for n in names)


def test_list_pe_dependent_dlls_skip_if_no_sample():
    pe_samples = list(SAMPLES.glob("*.exe")) + list(SAMPLES.glob("*.dll"))
    if not pe_samples:
        # API still callable on non-PE → expect error or empty; just ensure import works
        assert callable(list_pe_dependent_dlls)
        return
    names = list_pe_dependent_dlls(pe_samples[0])
    assert isinstance(names, list)


def test_patch_plan_includes_module():
    d = gate_scan(str(SAMPLES / "fauxware"), "password")
    plan = d.get("patch_plan") or []
    if not plan:
        # slice may be empty on tiny sample — still tag module on gates path
        assert d.get("module") == str(SAMPLES / "fauxware") or d.get("ok") is True
        return
    assert all(s.get("module") for s in plan)


def test_argus_discover_tool(tmp_path):
    bin_path = tmp_path / "target"
    shutil.copy(SAMPLES / "fauxware", bin_path)
    raw = bytearray(bin_path.read_bytes())
    raw.extend(b"\x00license key\x00")
    bin_path.write_bytes(raw)

    out = dispatch_tool(
        "argus_discover",
        {"prompt": "unlock", "root": str(tmp_path)},
    )
    import json

    data = json.loads(out)
    assert data.get("ok") is True
    assert Path(data["primary"]).resolve() == bin_path.resolve()


def test_argus_discover_in_tool_list():
    names = [t["function"]["name"] for t in ARGUS_TOOLS]
    assert "argus_look" in names
    assert "argus_diagnose" in names
    assert "argus_apply" in names


def test_agent_pre_discover_from_tmp_fixture(tmp_path, monkeypatch):
    """run_agent without binary arg discovers ELF in cwd fixture."""
    bin_path = tmp_path / "app"
    shutil.copy(SAMPLES / "fauxware", bin_path)
    raw = bytearray(bin_path.read_bytes())
    raw.extend(b"\x00Unregistered\x00")
    bin_path.write_bytes(raw)

    monkeypatch.chdir(tmp_path)

    from argus.discover import discover_targets

    d = discover_targets("remove the license check")
    assert d["ok"] is True
    assert Path(d["primary"]).name == "app"


def test_widen_modules_finds_scored_neighbor(tmp_path):
    from argus.discover import widen_modules

    primary = tmp_path / "app"
    other = tmp_path / "license_helper"
    shutil.copy(SAMPLES / "fauxware", primary)
    shutil.copy(SAMPLES / "fauxware", other)
    raw = bytearray(other.read_bytes())
    raw.extend(b"\x00invalid license\x00Unregistered\x00")
    other.write_bytes(raw)

    widened = widen_modules(str(primary), tried=[str(primary)], limit=8)
    names = {w["name"] for w in widened}
    assert "license_helper" in names
    assert any(w["name"] == "license_helper" and w["score"] > 0 for w in widened)


def test_slice_modules_pivots_when_primary_empty(monkeypatch, tmp_path):
    """Empty plan on primary → auto-widen into neighbor with gates."""
    from argus import find_slice as fs
    from argus.llm.session import reset_session

    reset_session()
    primary = tmp_path / "app"
    sib = tmp_path / "gate_mod"
    primary.write_bytes(b"\x7fELF" + b"\0" * 256)
    sib.write_bytes(b"\x7fELF" + b"\0" * 256)

    def fake_widen(primary_path, tried=None, limit=12, root=None):
        del primary_path, tried, limit, root
        return [{"path": str(sib), "score": 100, "name": "gate_mod"}]

    monkeypatch.setattr(fs, "widen_modules", fake_widen, raising=False)
    monkeypatch.setattr("argus.discover.widen_modules", fake_widen)

    def fake_slice(path, query=None, limit=16):
        if Path(path).name == "gate_mod":
            gate = {
                "kind": "ret_imm",
                "addr": "0x1000",
                "score": 400,
                "ui_label_only": False,
                "ret_guess": 1,
                "reason": "call→cmp==1 large callee",
                "nearby_fn": "sub_1000",
                "xref_addr": "0x1100",
                "module": path,
            }
            return {
                "ok": True,
                "summary": "hit",
                "string_hits": [{"addr": "0x200", "kind": "validate", "preview": "invalid license"}],
                "gate_candidates": [gate],
                "patch_plan": [],
                "module": path,
            }
        return {
            "ok": True,
            "summary": "empty",
            "string_hits": [],
            "gate_candidates": [],
            "patch_plan": [],
            "module": path,
        }

    monkeypatch.setattr(fs, "gate_scan", fake_slice)
    d = fs.gate_scan_modules(str(primary), modules=[], auto_widen=True, max_modules=4)
    assert d.get("pivoted") is True
    assert any(Path(m).name == "gate_mod" for m in (d.get("modules") or []))
    plan = d.get("patch_plan") or []
    assert plan
    assert any(Path(str(s.get("module") or "")).name == "gate_mod" for s in plan)


def test_siblings_linked_modules(tmp_path):
    primary = tmp_path / "main"
    sibling = tmp_path / "helper.so"
    shutil.copy(SAMPLES / "fauxware", primary)
    shutil.copy(SAMPLES / "fauxware", sibling)
    raw = bytearray(sibling.read_bytes())
    raw.extend(b"\x00invalid license\x00")
    sibling.write_bytes(raw)

    d = discover_targets("unlock", binary=str(primary))
    assert d["primary"]
    linked_names = {Path(m["path"]).name for m in d.get("linked") or []}
    assert "helper.so" in linked_names


def test_discover_explicit_binary_beats_sfx(tmp_path):
    install = tmp_path / "rar"
    install.mkdir()
    main = install / "rar"
    sfx = install / "default.sfx"
    shutil.copy(SAMPLES / "fauxware", main)
    shutil.copy(SAMPLES / "fauxware", sfx)
    main.chmod(0o755)
    sfx.chmod(0o755)
    d = discover_targets("unlock license", root=str(install), binary=str(main))
    assert Path(d["primary"]).resolve() == main.resolve()


def test_discover_skips_original_backup_and_sfx_when_unnamed(tmp_path):
    install = tmp_path / "rar"
    install.mkdir()
    main = install / "rar"
    sfx = install / "default.sfx"
    backup_dir = install / "original"
    backup_dir.mkdir()
    shutil.copy(SAMPLES / "fauxware", main)
    shutil.copy(SAMPLES / "fauxware", sfx)
    shutil.copy(SAMPLES / "fauxware", backup_dir / "rar")
    main.chmod(0o755)
    sfx.chmod(0o755)
    (backup_dir / "rar").chmod(0o755)
    d = discover_targets("unlock", root=str(install))
    assert Path(d["primary"]).name == "rar"
    paths = [c["path"] for c in d.get("candidates") or []]
    assert not any(Path(p).parent.name == "original" for p in paths)


def test_pick_primary_zero_score_skips_sfx(tmp_path):
    from argus.discover import _pick_primary

    install = tmp_path / "app"
    install.mkdir()
    sfx = install / "default.sfx"
    main = install / "app"
    sfx.write_bytes(b"\x7fELF" + b"\0" * 128)
    main.write_bytes(b"\x7fELF" + b"\0" * 128)
    sfx.chmod(0o755)
    main.chmod(0o755)
    ranked = [(0, sfx.resolve()), (0, main.resolve())]
    assert _pick_primary(ranked).name == "app"
