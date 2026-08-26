# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Massive Synthetic Control Flow Graph (CFG) Dataset Generator.
Synthesizes 2,500+ diverse Control Flow Graphs (60,000+ basic block nodes) with 100% Ground Truth:
- Class 0: DEAD_JUNK (unobserved writes, dead stack cycles, synthetic noise)
- Class 1: VM_DISPATCHER (control flow flattening routers, state machine switches)
- Class 2: CRITICAL_COMPUTATION (arithmetic payload, cryptographic transformations, key validation)
"""
import random
import numpy as np
from typing import List, Tuple, Dict, Any

class GraphDatasetGenerator:
    def __init__(self, seed: int = 42):
        self.rng = random.Random(seed)
        np.random.seed(seed)

    def generate_single_graph(self, num_nodes: int = 25) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Synthesizes a single obfuscated Control Flow Graph.
        Returns:
            - adj_matrix: (N, N) binary adjacency matrix
            - node_features: (N, 8) feature matrix
            - node_labels: (N,) ground-truth class labels (0, 1, 2)
        """
        # Node classes: ~40% Junk, ~35% Dispatcher/Router, ~25% Critical
        node_labels = np.zeros(num_nodes, dtype=np.int64)
        node_features = np.zeros((num_nodes, 8), dtype=np.float32)
        adj_matrix = np.zeros((num_nodes, num_nodes), dtype=np.float32)

        # Allocate node types
        dispatcher_idx = 0
        node_labels[dispatcher_idx] = 1 # Master Dispatcher Block

        for i in range(1, num_nodes):
            rand_val = self.rng.random()
            if rand_val < 0.45:
                node_labels[i] = 0 # DEAD_JUNK
            elif rand_val < 0.70:
                node_labels[i] = 1 # VM_DISPATCHER
            else:
                node_labels[i] = 2 # CRITICAL_COMPUTATION

        # Construct realistic obfuscated edges (Flattened state machine + loops)
        for i in range(num_nodes):
            label = node_labels[i]
            if label == 1: # Dispatcher connects to multiple state blocks
                targets = self.rng.sample(range(num_nodes), min(3, num_nodes))
                for t in targets:
                    if t != i:
                        adj_matrix[i, t] = 1.0
            elif label == 0: # Junk block bounces or loops back
                target = self.rng.randint(0, num_nodes - 1)
                adj_matrix[i, target] = 1.0
            else: # Critical block computes and transitions to next or dispatcher
                target = 0 if self.rng.random() < 0.6 else self.rng.randint(0, num_nodes - 1)
                adj_matrix[i, target] = 1.0

        # Compute 8 node features:
        # [0]: in_degree, [1]: out_degree, [2]: loop_depth, [3]: crypto_ratio,
        # [4]: mov_ratio, [5]: taint_score, [6]: centrality, [7]: branch_entropy
        in_degrees = adj_matrix.sum(axis=0)
        out_degrees = adj_matrix.sum(axis=1)

        for i in range(num_nodes):
            lbl = node_labels[i]
            in_deg = in_degrees[i]
            out_deg = out_degrees[i]

            if lbl == 0: # JUNK
                crypto_ratio = self.rng.uniform(0.0, 0.1)
                mov_ratio = self.rng.uniform(0.6, 0.95)
                taint_score = self.rng.uniform(0.0, 0.15)
                loop_depth = self.rng.uniform(0.0, 0.3)
            elif lbl == 1: # DISPATCHER
                crypto_ratio = self.rng.uniform(0.1, 0.3)
                mov_ratio = self.rng.uniform(0.5, 0.8)
                taint_score = self.rng.uniform(0.2, 0.5)
                loop_depth = self.rng.uniform(0.7, 1.0)
            else: # CRITICAL
                crypto_ratio = self.rng.uniform(0.6, 1.0)
                mov_ratio = self.rng.uniform(0.1, 0.4)
                taint_score = self.rng.uniform(0.85, 1.0)
                loop_depth = self.rng.uniform(0.2, 0.6)

            centrality = (in_deg + out_deg) / (num_nodes + 1)
            branch_entropy = out_deg / (out_deg + 1.0)

            node_features[i] = [
                in_deg / num_nodes,
                out_deg / num_nodes,
                loop_depth,
                crypto_ratio,
                mov_ratio,
                taint_score,
                centrality,
                branch_entropy
            ]

        return adj_matrix, node_features, node_labels

    def generate_dataset(self, num_graphs: int = 2500) -> List[Tuple[np.ndarray, np.ndarray, np.ndarray]]:
        """
        Synthesizes a massive dataset of N obfuscated CFGs.
        """
        dataset = []
        for _ in range(num_graphs):
            num_nodes = self.rng.randint(15, 40)
            graph_data = self.generate_single_graph(num_nodes)
            dataset.append(graph_data)
        return dataset
