from pathlib import Path

from argus.binary import load_binary
from argus.deobf import recover_cff
from argus.disasm import build_function_cfg
from argus.ml import Pruner
from argus.prove import certify_nop_patches, certify_prune_proposals
from argus.patch import Patcher

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_proof_rejects_effectful_blocks():
    img = load_binary(SAMPLES / "fauxware")
    cfg = build_function_cfg(img, "main")
    # Propose pruning the entry block — must be rejected (has calls)
    cert = certify_prune_proposals(cfg, [cfg.entry])
    assert cfg.entry in cert.rejected
    assert cfg.entry not in cert.approved


def test_certified_pruner_backend():
    img = load_binary(SAMPLES / "fauxware")
    cfg = build_function_cfg(img, "main")
    pr = Pruner(require_proof=True)
    result = pr.prune(cfg)
    assert "+proof" in result.backend
    assert pr.last_certificate is not None


def test_cff_state_recovery_on_fla():
    img = load_binary(SAMPLES / "fauxware_fla")
    cfg = build_function_cfg(img, "authenticate")
    report = recover_cff(cfg)
    assert report.dispatcher is not None
    assert report.state_slot is not None
    assert "0x2c" in report.state_slot
    assert len(report.case_map) >= 4
    assert len(report.recovered_edges) >= 2


def test_patch_certificate(tmp_path):
    p = Patcher.from_path(str(SAMPLES / "fauxware"))
    assert p.nop(0x4007D5, 4)
    cert = certify_nop_patches(p.patches, {"ok": True, "returncode": 0})
    assert cert.proven
    assert cert.patches
