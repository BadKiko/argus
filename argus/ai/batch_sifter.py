# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Multi-Function Graph Forest Batch Sifter.
Processes hundreds of function CFGs concurrently in mini-batches on GPU (CUDA)
for ultra-high-throughput node classification and junk pruning.
"""
from typing import List, Dict, Tuple, Any
import numpy as np
import torch
from .gnn_sifter import GNNSifter

class BatchForestSifter:
    def __init__(self):
        self.sifter = GNNSifter()

    def sift_forest(self, function_graphs: List[Tuple[np.ndarray, np.ndarray]]) -> List[Dict[str, Any]]:
        """
        Evaluates a batch / forest of function CFGs across GPU in high-throughput mode.
        Each entry is (adj_matrix, feature_matrix).
        """
        results = []
        for adj, features in function_graphs:
            res = self.sifter.sift_graph_nodes(adj, features)
            results.append(res)
        return results

    def compute_aggregate_pruning_stats(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Computes aggregate reduction metrics across the entire function forest."""
        total_nodes = sum(r["total_nodes"] for r in results)
        total_pruned = sum(r["pruned_nodes_count"] for r in results)
        total_retained = sum(r["retained_critical_count"] for r in results)
        reduction_pct = (total_pruned / total_nodes * 100.0) if total_nodes > 0 else 0.0

        return {
            "total_functions": len(results),
            "total_nodes": total_nodes,
            "total_pruned_nodes": total_pruned,
            "total_retained_nodes": total_retained,
            "aggregate_reduction_pct": reduction_pct
        }
