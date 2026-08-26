# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Multi-Megabyte Binary Scoped Slicer.
Performs scoped, on-demand sub-graph building around key anchors (Entry points, XRefs, API sinks)
without exhausting system RAM on 100-500 MB binaries.
"""
from typing import Dict, List, Set, Tuple, Any

class ScopedAnalyzer:
    def __init__(self, max_subgraph_depth: int = 4):
        self.max_depth = max_subgraph_depth

    def extract_anchor_subgraph(self, anchor_rva: int, full_cfg_adjacency: Dict[int, List[int]]) -> Set[int]:
        """
        Extracts a localized sub-graph of basic blocks within radius R around an anchor.
        """
        visited: Set[int] = {anchor_rva}
        queue: List[Tuple[int, int]] = [(anchor_rva, 0)]

        while queue:
            node, depth = queue.pop(0)
            if depth >= self.max_depth:
                continue

            neighbors = full_cfg_adjacency.get(node, [])
            for nxt in neighbors:
                if nxt not in visited:
                    visited.add(nxt)
                    queue.append((nxt, depth + 1))

        return visited
