# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
import pytest
import numpy as np
from argus.ai.graph_dataset import GraphDatasetGenerator
from argus.ai.gnn_sifter import GNNSifter

def test_gnn_graph_sifter_pruning():
    gen = GraphDatasetGenerator(seed=999)
    adj, features, labels = gen.generate_single_graph(num_nodes=30)

    sifter = GNNSifter()
    result = sifter.sift_graph_nodes(adj, features)

    assert result["total_nodes"] == 30
    assert result["retained_critical_count"] > 0
    assert result["pruned_nodes_count"] > 0
    assert len(result["retained_indices"]) == result["retained_critical_count"]
