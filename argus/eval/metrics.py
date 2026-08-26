from __future__ import annotations

"""Held-out prune metrics helpers."""

from typing import Dict, List, Tuple

import numpy as np

from argus.ml.features import LABEL_CRITICAL, LABEL_JUNK
from argus.ml.pruner import eval_prune_metrics


def summarize_ab(times_with: List[float], times_without: List[float]) -> Dict[str, float]:
    return {
        "mean_with_prune": float(np.mean(times_with)) if times_with else 0.0,
        "mean_without_prune": float(np.mean(times_without)) if times_without else 0.0,
        "n": float(min(len(times_with), len(times_without))),
    }


def false_negative_rate(y_true: np.ndarray, pruned_mask: np.ndarray) -> float:
    m = eval_prune_metrics(y_true, y_true, pruned_mask)
    n = m["n_critical"]
    return 0.0 if n == 0 else m["false_negatives_critical_pruned"] / n
