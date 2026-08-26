from __future__ import annotations

"""Batch helpers + timing for corpus deobf."""

from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass
class FnTiming:
    path: str
    function: str
    ms: float
    cases: int
    blocks: int


def _deobf_one(args: Tuple[str, str]) -> FnTiming:
    import time

    from argus.binary import load_binary
    from argus.deobf import recover_cff
    from argus.disasm import build_function_cfg

    path, fn = args
    img = load_binary(path)
    t0 = time.perf_counter()
    cfg = build_function_cfg(img, fn)
    cff = recover_cff(cfg)
    ms = (time.perf_counter() - t0) * 1000.0
    return FnTiming(path, fn, ms, len(cff.case_map), len(cfg.blocks))


def batch_deobf_timings(
    jobs: List[Tuple[str, str]],
    workers: int = 2,
) -> List[FnTiming]:
    """Parallel CFF recovery timings across (path, function) jobs."""
    if workers <= 1 or len(jobs) <= 1:
        return [_deobf_one(j) for j in jobs]
    out: List[FnTiming] = []
    with ProcessPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(_deobf_one, j): j for j in jobs}
        for fut in as_completed(futs):
            out.append(fut.result())
    return out


def timings_to_dict(rows: List[FnTiming]) -> Dict[str, float]:
    if not rows:
        return {"mean_ms": 0.0, "n": 0.0}
    return {
        "mean_ms": sum(r.ms for r in rows) / len(rows),
        "max_ms": max(r.ms for r in rows),
        "n": float(len(rows)),
    }
