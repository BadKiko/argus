from __future__ import annotations

from pathlib import Path
from typing import List, Optional

import numpy as np

from argus.disasm.cfg import CFG, build_function_cfg
from argus.ml.features import (
    LABEL_JUNK,
    PruneResult,
    extract_node_features,
    heuristic_labels,
    heuristic_prune,
)
from argus.ml.model import TORCH_AVAILABLE, predict, train_res_gcn
from argus.prove.deadness import PruneCertificate, certify_prune_proposals


class Pruner:
    """ML/heuristics propose junk; proof layer must approve every drop."""

    def __init__(self, model=None, tau: float = 0.85, require_proof: bool = True):
        self.model = model
        self.tau = tau
        self.require_proof = require_proof
        self.last_certificate: Optional[PruneCertificate] = None

    def propose(self, cfg: CFG) -> PruneResult:
        if self.model is not None and TORCH_AVAILABLE:
            adj, feats, addrs = extract_node_features(cfg)
            preds, conf = predict(self.model, adj, feats)
            if preds is not None:
                kept, pruned = [], []
                for i, a in enumerate(addrs):
                    if preds[i] == LABEL_JUNK and conf[i] >= self.tau:
                        pruned.append(a)
                    else:
                        kept.append(a)
                return PruneResult(addrs, preds, conf, kept, pruned, backend="gnn")
        return heuristic_prune(cfg, tau=self.tau)

    def prune(self, cfg: CFG) -> PruneResult:
        proposal = self.propose(cfg)
        if not self.require_proof:
            self.last_certificate = None
            return proposal

        # Always include nop-only blocks as proposals even if heuristic missed them
        proposed = set(proposal.pruned)
        for addr, blk in cfg.blocks.items():
            if blk.instructions and all(i.mnemonic in ("nop", "endbr64") for i in blk.instructions):
                proposed.add(addr)

        cert = certify_prune_proposals(cfg, sorted(proposed))
        self.last_certificate = cert
        approved = set(cert.approved)
        addrs = proposal.addrs
        kept = [a for a in addrs if a not in approved]
        pruned = [a for a in addrs if a in approved]
        # Also account for approved not in original addrs list order
        for a in cert.approved:
            if a not in pruned:
                pruned.append(a)
            if a in kept:
                kept.remove(a)
        backend = f"{proposal.backend}+proof"
        return PruneResult(
            addrs=addrs,
            labels=proposal.labels,
            confidence=proposal.confidence,
            kept=kept,
            pruned=pruned,
            backend=backend,
        )


def build_training_graphs_from_binary(image, function_names: Optional[List[str]] = None):
    graphs = []
    names = function_names or [n for n, s in image.symbols.items() if s.is_function and not s.is_import and s.addr]
    for name in names:
        try:
            cfg = build_function_cfg(image, name)
        except Exception:
            continue
        if len(cfg.blocks) < 2:
            continue
        adj, feats, addrs = extract_node_features(cfg)
        labels = heuristic_labels(cfg, addrs)
        graphs.append((adj, feats, labels))
    return graphs


def train_on_image(image, epochs: int = 40, save_path: Optional[str] = None):
    graphs = build_training_graphs_from_binary(image)
    if not graphs:
        return None
    model = train_res_gcn(graphs, epochs=epochs)
    if model is not None and save_path:
        import torch

        Path(save_path).parent.mkdir(parents=True, exist_ok=True)
        torch.save(model.state_dict(), save_path)
    return model


def eval_prune_metrics(y_true: np.ndarray, y_pred: np.ndarray, pruned_mask: np.ndarray) -> dict:
    from argus.ml.features import LABEL_CRITICAL

    critical = y_true == LABEL_CRITICAL
    fn = int(np.sum(critical & pruned_mask))
    fp = int(np.sum((y_true == LABEL_JUNK) & ~pruned_mask))
    return {
        "false_negatives_critical_pruned": fn,
        "junk_kept": fp,
        "n_critical": int(np.sum(critical)),
        "n_pruned": int(np.sum(pruned_mask)),
    }
