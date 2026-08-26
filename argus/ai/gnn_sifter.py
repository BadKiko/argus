# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
In-Battle GNN Graph Sifter & Control Flow Pruner.
Uses the trained Graph Neural Network to classify all basic blocks in a binary's CFG,
pruning 90%+ of dead code and state dispatcher loops before invoking SMT solvers.
"""
import os
import numpy as np
from typing import List, Dict, Tuple, Any
from .gnn_model import TORCH_AVAILABLE

if TORCH_AVAILABLE:
    import torch
    from .gnn_model import PyTorchGCNClassifier

class GNNSifter:
    def __init__(self, weights_path: str = None):
        self.device = torch.device("cuda" if TORCH_AVAILABLE and torch.cuda.is_available() else "cpu") if TORCH_AVAILABLE else "numpy"
        self.model = None
        
        if TORCH_AVAILABLE:
            if weights_path is None:
                default_path = os.path.join(os.path.dirname(__file__), "models", "gnn_sifter.pt")
                if os.path.exists(default_path):
                    weights_path = default_path

            self.model = PyTorchGCNClassifier(in_dim=8, hidden_dim=64, num_classes=3).to(self.device)
            if weights_path and os.path.exists(weights_path):
                self.model.load_state_dict(torch.load(weights_path, map_location=self.device))
                self.model.eval()

    def sift_graph_nodes(self, adj_matrix: np.ndarray, node_features: np.ndarray) -> Dict[str, Any]:
        """
        Classifies all nodes in the given CFG.
        Returns:
            - node_predictions: array of class ids (0: JUNK, 1: DISPATCHER, 2: CRITICAL)
            - pruned_nodes_count: number of junk/dispatcher nodes to eliminate
            - retained_critical_indices: list of node indices to retain for SMT solving
        """
        num_nodes = adj_matrix.shape[0]

        if TORCH_AVAILABLE and self.model is not None:
            with torch.no_grad():
                adj_t = torch.tensor(adj_matrix, dtype=torch.float32, device=self.device)
                x_t = torch.tensor(node_features, dtype=torch.float32, device=self.device)
                out = self.model(x_t, adj_t)
                preds = torch.argmax(out, dim=1).cpu().numpy()
        else:
            # Fallback based on feature rules
            preds = np.zeros(num_nodes, dtype=np.int64)
            for i in range(num_nodes):
                if node_features[i, 3] > 0.5 and node_features[i, 5] > 0.7:
                    preds[i] = 2 # CRITICAL
                elif node_features[i, 2] > 0.6 or (node_features[i, 0] + node_features[i, 1]) > 0.3:
                    preds[i] = 1 # DISPATCHER
                else:
                    preds[i] = 0 # JUNK

        critical_indices = [i for i, p in enumerate(preds) if p == 2]
        # Safety fallback: if no critical node found, retain all
        if not critical_indices:
            critical_indices = list(range(num_nodes))

        pruned_count = num_nodes - len(critical_indices)

        return {
            "total_nodes": num_nodes,
            "node_predictions": preds,
            "pruned_nodes_count": pruned_count,
            "retained_critical_count": len(critical_indices),
            "retained_indices": critical_indices
        }
