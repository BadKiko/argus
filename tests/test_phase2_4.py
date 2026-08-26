from pathlib import Path

import pytest

from argus.deobf import HandlerSynthesizer, decode_toy_bytecode
from argus.eval import ArgusReport
from argus.ml import TORCH_AVAILABLE, train_on_image
from argus.binary import load_binary

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_toy_vm_synth_and_decode():
    syn = HandlerSynthesizer()
    assert syn.synthesize(lambda a, b: (a + b) & 0xFFFFFFFF).name == "add"
    code = bytes([0x10]) + (0xDEADBEEF).to_bytes(4, "little") + bytes([0x20, 0xFF])
    ir = decode_toy_bytecode(code, {0x10: "IMM", 0x20: "xor", 0xFF: "RET"})
    assert ir[0]["op"] == "PUSH" and ir[0]["value"] == 0xDEADBEEF
    assert ir[-1]["op"] == "RET"


def test_report_json_roundtrip(tmp_path):
    rep = ArgusReport(binary="x", fmt="elf", entry="0x0", notes=["ok"])
    p = tmp_path / "r.json"
    p.write_text(rep.to_json())
    assert "notes" in p.read_text()


@pytest.mark.skipif(not TORCH_AVAILABLE, reason="torch not installed")
def test_train_gnn_smoke():
    img = load_binary(SAMPLES / "fauxware")
    model = train_on_image(img, epochs=5, save_path=None)
    assert model is not None
