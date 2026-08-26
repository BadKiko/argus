from pathlib import Path

from argus.binary import load_binary
from argus.deobf import HandlerSynthesizer, recover_cff
from argus.disasm import build_function_cfg
from argus.ml import Pruner
from argus.patch import Patcher

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_prune_keeps_critical_budget():
    img = load_binary(SAMPLES / "fauxware")
    cfg = build_function_cfg(img, "main")
    pr = Pruner(tau=0.9).prune(cfg)
    # Conservative: should not prune most of main
    assert len(pr.kept) >= len(pr.pruned)


def test_cff_on_fla_or_main():
    path = SAMPLES / "fauxware_fla"
    img = load_binary(path)
    # Prefer main if present
    name = "main" if "main" in img.symbols else next(
        n for n, s in img.symbols.items() if s.is_function and not s.is_import and s.addr
    )
    cfg = build_function_cfg(img, name)
    report = recover_cff(cfg)
    assert isinstance(report.notes, list)


def test_handler_synth_xor():
    syn = HandlerSynthesizer()
    r = syn.synthesize(lambda a, b: (a ^ b) & 0xFFFFFFFF)
    assert r.proved and r.name == "xor"


def test_patch_nop_and_save(tmp_path):
    src = SAMPLES / "fauxware"
    p = Patcher.from_path(str(src))
    # nop a padding area near end of text if possible — use a known nop sled region
    # 0x4007d5 has nops in fauxware
    ok = p.nop(0x4007D5, 4, note="test")
    assert ok
    out = tmp_path / "fauxware.patched"
    p.save(str(out))
    assert out.stat().st_size == src.stat().st_size
