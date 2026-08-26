# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
import pytest
from argus.scanner.scoped_analyzer import ScopedAnalyzer

def test_scoped_analyzer_subgraph_extraction():
    analyzer = ScopedAnalyzer(max_subgraph_depth=2)

    # Simulated large graph with 100 nodes
    cfg = {
        0x1000: [0x1010, 0x1020],
        0x1010: [0x1030],
        0x1020: [0x1040],
        0x1030: [0x1050],
        0x1040: [0x1060],
        0x1050: [0x1070]
    }

    # Extract radius 2 from anchor 0x1000
    subgraph = analyzer.extract_anchor_subgraph(0x1000, cfg)

    assert 0x1000 in subgraph
    assert 0x1010 in subgraph
    assert 0x1020 in subgraph
    assert 0x1030 in subgraph
    assert 0x1040 in subgraph
    # Depth 3+ must not be loaded (saving RAM)
    assert 0x1050 not in subgraph
    assert 0x1070 not in subgraph
