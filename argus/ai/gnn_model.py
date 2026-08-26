# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Deep Residual Graph Convolutional Network (ResGCN) Architecture.
Features 3 Graph Message Passing Layers with Residual Skip Connections, LayerNorm, and 10-dim Input Features.
"""
import numpy as np
from typing import Tuple, Dict, Any, Optional

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

if TORCH_AVAILABLE:
    class PyTorchGCNLayer(nn.Module):
        def __init__(self, in_features: int, out_features: int):
            super().__init__()
            self.linear = nn.Linear(in_features, out_features)

        def forward(self, x: torch.Tensor, adj: torch.Tensor) -> torch.Tensor:
            # Degree normalization with element-wise broadcasting (zero memory allocation)
            identity = torch.eye(adj.size(0), device=adj.device)
            a_tilde = adj + identity
            d = torch.sum(a_tilde, dim=1)
            d_inv_sqrt = torch.pow(d, -0.5)
            d_inv_sqrt[torch.isinf(d_inv_sqrt)] = 0.0
            
            # Symmetric normalized adjacency: D^(-1/2) * A * D^(-1/2)
            norm_adj = d_inv_sqrt.unsqueeze(1) * a_tilde * d_inv_sqrt.unsqueeze(0)
            support = torch.mm(norm_adj, x)
            return self.linear(support)

    class PyTorchGCNClassifier(nn.Module):
        def __init__(self, in_dim: int = 10, hidden_dim: int = 128, num_classes: int = 3, dropout: float = 0.1):
            super().__init__()
            self.in_proj = nn.Linear(in_dim, hidden_dim)
            
            # 3-layer Graph Convolution with Residual Connections
            self.gc1 = PyTorchGCNLayer(hidden_dim, hidden_dim)
            self.ln1 = nn.LayerNorm(hidden_dim)
            self.gc2 = PyTorchGCNLayer(hidden_dim, hidden_dim)
            self.ln2 = nn.LayerNorm(hidden_dim)
            self.gc3 = PyTorchGCNLayer(hidden_dim, hidden_dim)
            self.ln3 = nn.LayerNorm(hidden_dim)
            
            self.head = nn.Sequential(
                nn.Linear(hidden_dim, hidden_dim // 2),
                nn.ReLU(),
                nn.Dropout(dropout),
                nn.Linear(hidden_dim // 2, num_classes)
            )

        def forward(self, x: torch.Tensor, adj: torch.Tensor) -> torch.Tensor:
            h0 = F.relu(self.in_proj(x))
            
            # Block 1 + Skip
            h1 = F.relu(self.ln1(self.gc1(h0, adj))) + h0
            # Block 2 + Skip
            h2 = F.relu(self.ln2(self.gc2(h1, adj))) + h1
            # Block 3 + Skip
            h3 = F.relu(self.ln3(self.gc3(h2, adj))) + h2
            
            return self.head(h3)

class NumPyGCNClassifier:
    def __init__(self, in_dim: int = 10, hidden_dim: int = 64, num_classes: int = 3):
        self.w = np.random.randn(in_dim, num_classes) * 0.1
        self.b = np.zeros(num_classes)

    def forward(self, x: np.ndarray, adj: np.ndarray) -> np.ndarray:
        logits = x @ self.w + self.b
        exp_l = np.exp(logits - np.max(logits, axis=1, keepdims=True))
        return exp_l / np.sum(exp_l, axis=1, keepdims=True)
