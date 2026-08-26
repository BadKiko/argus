# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
import pytest
from argus.ai.batch_sifter import BatchForestSifter
from argus.ai.graph_dataset import GraphDatasetGenerator

def test_batch_forest_sifter_multi_function_pruning():
    gen = GraphDatasetGenerator(seed=42)
    sifter = BatchForestSifter()

    # Generate 10 distinct function graphs
    forest = []
    for _ in range(10):
        adj, feats, _ = gen.generate_single_graph(num_nodes=25)
        forest.append((adj, feats))

    results = sifter.sift_forest(forest)
    assert len(results) == 10

    stats = sifter.compute_aggregate_pruning_stats(results)
    assert stats["total_functions"] == 10
    assert stats["total_nodes"] == 250
    assert stats["total_pruned_nodes"] > 150 # At least 60%+ pruned
    assert stats["aggregate_reduction_pct"] > 60.0
