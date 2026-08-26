from __future__ import annotations

"""End-to-end orchestrator: detect → pipelines → patch → verify → certificate bundle."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from argus.binary import load_binary
from argus.deobf.bogus import analyze_bogus_cf, prove_mba_catalog
from argus.deobf.cff import recover_cff
from argus.deobf.detect import detect_protection
from argus.deobf.unflatten import apply_unflatten
from argus.deobf.vmp_layer import analyze_vmp_layer
from argus.disasm import build_cfg, build_function_cfg
from argus.eval.report import ArgusReport
from argus.ml import Pruner
from argus.patch import Patcher


@dataclass
class RunResult:
    report: ArgusReport
    output_path: Optional[str] = None
    ok: bool = True

    def to_dict(self) -> dict:
        d = self.report.to_dict() if hasattr(self.report, "to_dict") else {}
        # ArgusReport uses to_json; build manually
        import json

        return json.loads(self.report.to_json())


def run_pipeline(
    path: str,
    function: Optional[str] = None,
    output: Optional[str] = None,
    verify_stdin: bytes = b"",
    do_patch: bool = True,
) -> RunResult:
    img = load_binary(path)
    prot = detect_protection(img)
    notes: List[str] = [f"detect={prot.kind} conf={prot.confidence:.2f}"]
    notes.extend(prot.indicators[:8])

    fn = function
    if not fn:
        # pick a large function or main
        if "main" in img.symbols:
            fn = "main"
        elif "authenticate" in img.symbols:
            fn = "authenticate"
        elif "target_function" in img.symbols:
            fn = "target_function"
        else:
            fn = None

    cfg = None
    if fn and fn in img.symbols:
        cfg = build_function_cfg(img, fn)
    else:
        cfg = build_cfg(img, entry=img.entry, max_blocks=400)
        fn = fn or f"entry:{hex(img.entry)}"

    prune_info = None
    try:
        pruner = Pruner(require_proof=True)
        pr = pruner.prune(cfg)
        prune_info = {
            "backend": pr.backend,
            "kept": len(pr.kept),
            "pruned": [hex(a) for a in pr.pruned],
            "certificate": pruner.last_certificate.to_dict() if pruner.last_certificate else None,
        }
    except Exception as e:
        notes.append(f"prune skipped: {e}")

    cff = recover_cff(cfg)
    notes.append(f"cff cases={len(cff.case_map)} edges={len(cff.recovered_edges)}")

    mba = prove_mba_catalog()
    bogus = analyze_bogus_cf(cfg)
    notes.append(f"bogus hits={len(bogus.hits)}")

    vmp = None
    if prot.kind in ("vmp", "themida", "mixed", "unknown"):
        vmp = analyze_vmp_layer(img)
        notes.append(f"vmp stubs={len(vmp.stub_blocks)}")

    patch_meta: Dict[str, Any] = {}
    out_path = output
    if do_patch and (cff.case_map or bogus.hits):
        patcher = Patcher.from_path(path)
        if cff.case_map:
            u = apply_unflatten(patcher, cfg, cff)
            patch_meta["unflatten"] = u.to_dict()
            notes.append(f"unflatten patches={u.patches_applied}")
        if bogus.hits:
            b2 = analyze_bogus_cf(cfg, patcher)
            patch_meta["bogus"] = b2.to_dict()
            notes.append(f"bogus patches={b2.patched}")
        if out_path is None:
            out_path = str(Path(path)) + ".argus"
        patcher.save(out_path)
        if img.fmt == "elf" and verify_stdin is not None:
            v = patcher.verify_runs(stdin=verify_stdin)
            patch_meta["verify"] = {
                "ok": v.get("ok"),
                "returncode": v.get("returncode"),
            }
            notes.append(f"verify ok={v.get('ok')}")

    rep = ArgusReport(
        binary=str(path),
        fmt=img.fmt,
        entry=hex(img.entry),
        functions=[fn or ""],
        prune=prune_info,
        certificate={"protection": prot.to_dict(), "patch": patch_meta, "mba": mba},
        cff=cff.to_dict(),
        solve=None,
        notes=notes,
    )
    # attach extras via notes / certificate
    if vmp:
        rep.certificate = rep.certificate or {}
        rep.certificate["vmp"] = vmp.to_dict()
    if bogus:
        rep.certificate = rep.certificate or {}
        rep.certificate["bogus"] = bogus.to_dict()

    return RunResult(report=rep, output_path=out_path, ok=True)
