# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
import pytest
import numpy as np
from argus.targets.mega_challenge import MegaChallengeTarget
from argus.ai.gnn_sifter import GNNSifter

def test_mega_challenge_end_to_end_solving():
    target = MegaChallengeTarget(key_lo=0xCAFE1337, key_hi=0xDEADBEEF)
    adj, features, labels = target.generate_full_graph(total_nodes=120)

    # 1. Run GNN Sifter
    sifter = GNNSifter()
    result = sifter.sift_graph_nodes(adj, features)

    # 2. Verify Zero False Negatives (all 16 critical Feistel blocks must be retained)
    retained_set = set(result["retained_indices"])
    ground_truth_critical = set(range(16))

    # All critical nodes are preserved
    assert ground_truth_critical.issubset(retained_set), "GNN pruned a critical block (False Negative)!"
    # Over 70% of junk and dispatchers pruned
    assert result["pruned_nodes_count"] >= 80

    # 3. Verify Ground-Truth Password Matching
    assert target.verify_password(0xCAFE1337, 0xDEADBEEF) is True
    assert target.verify_password(0x00000000, 0x11111111) is False
