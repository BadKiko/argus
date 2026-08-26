from pathlib import Path

from argus.binary import load_binary
from argus.disasm import build_function_cfg

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_cfg_main_has_blocks():
    img = load_binary(SAMPLES / "fauxware")
    cfg = build_function_cfg(img, "main")
    assert cfg.entry == img.symbols["main"].addr
    assert len(cfg.blocks) >= 3
    assert cfg.graph.number_of_edges() >= 2


def test_cfg_authenticate():
    img = load_binary(SAMPLES / "fauxware")
    cfg = build_function_cfg(img, "authenticate")
    assert len(cfg.blocks) >= 2
    dot = cfg.to_dot()
    assert "digraph" in dot
