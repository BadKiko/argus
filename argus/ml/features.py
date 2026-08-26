from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import numpy as np

from argus.disasm.cfg import CFG

FEATURE_DIM = 10
LABEL_CRITICAL = 2
LABEL_DISPATCHER = 1
LABEL_JUNK = 0
LABEL_NAMES = {0: "junk", 1: "dispatcher", 2: "critical"}


def extract_node_features(cfg: CFG) -> Tuple[np.ndarray, np.ndarray, List[int]]:
    """Return adj matrix, feature matrix [N,10], and node address list."""
    addrs = sorted(cfg.blocks)
    index = {a: i for i, a in enumerate(addrs)}
    n = len(addrs)
    adj = np.zeros((n, n), dtype=np.float32)
    for u, v in cfg.graph.edges():
        if u in index and v in index:
            adj[index[u], index[v]] = 1.0

    feats = np.zeros((n, FEATURE_DIM), dtype=np.float32)
    for a, i in index.items():
        blk = cfg.blocks[a]
        nins = len(blk.instructions) or 1
        n_call = sum(1 for ins in blk.instructions if ins.is_call)
        n_ret = sum(1 for ins in blk.instructions if ins.is_ret)
        n_jmp = sum(1 for ins in blk.instructions if ins.is_jmp or ins.is_conditional)
        n_mem = sum(1 for ins in blk.instructions if "[" in ins.op_str)
        n_imm = sum(1 for ins in blk.instructions if "0x" in ins.op_str)
        indeg = cfg.graph.in_degree(a) if a in cfg.graph else 0
        outdeg = cfg.graph.out_degree(a) if a in cfg.graph else 0
        feats[i, 0] = min(nins / 32.0, 1.0)
        feats[i, 1] = min(n_call / max(nins, 1), 1.0)
        feats[i, 2] = min(n_ret / max(nins, 1), 1.0)
        feats[i, 3] = min(n_jmp / max(nins, 1), 1.0)
        feats[i, 4] = min(n_mem / max(nins, 1), 1.0)
        feats[i, 5] = min(n_imm / max(nins, 1), 1.0)
        feats[i, 6] = min(indeg / 8.0, 1.0)
        feats[i, 7] = min(outdeg / 8.0, 1.0)
        feats[i, 8] = 1.0 if outdeg >= 2 else 0.0
        feats[i, 9] = 1.0 if indeg >= 2 else 0.0
    return adj, feats, addrs


def heuristic_labels(cfg: CFG, addrs: List[int]) -> np.ndarray:
    """Weak labels for bootstrapping: high outdegree fan-in → dispatcher, tiny blocks → junk."""
    labels = np.full(len(addrs), LABEL_CRITICAL, dtype=np.int64)
    for i, a in enumerate(addrs):
        blk = cfg.blocks[a]
        indeg = cfg.graph.in_degree(a) if a in cfg.graph else 0
        outdeg = cfg.graph.out_degree(a) if a in cfg.graph else 0
        nins = len(blk.instructions)
        if indeg >= 3 and outdeg >= 2:
            labels[i] = LABEL_DISPATCHER
        elif nins <= 2 and outdeg == 1 and indeg <= 1:
            # possible junk/padding — still keep conservative: mark junk only if nop-heavy
            if all(ins.mnemonic == "nop" for ins in blk.instructions):
                labels[i] = LABEL_JUNK
    return labels


@dataclass
class PruneResult:
    addrs: List[int]
    labels: np.ndarray
    confidence: np.ndarray
    kept: List[int]
    pruned: List[int]
    backend: str


def heuristic_prune(cfg: CFG, tau: float = 0.9) -> PruneResult:
    adj, feats, addrs = extract_node_features(cfg)
    labels = heuristic_labels(cfg, addrs)
    conf = np.where(labels == LABEL_JUNK, 0.95, 0.5).astype(np.float32)
    # Only prune junk with high confidence
    kept, pruned = [], []
    for i, a in enumerate(addrs):
        if labels[i] == LABEL_JUNK and conf[i] >= tau:
            pruned.append(a)
        else:
            kept.append(a)
    return PruneResult(addrs, labels, conf, kept, pruned, backend="heuristic")
