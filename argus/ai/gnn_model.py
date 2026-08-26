# Copyright (c) 2026 k.zhukov
# Licensed under the MIT License. See LICENSE in the project root for license information.
"""
Graph Convolutional Network (GCN) Architecture for CFG Node Classification.
Implements Graph Message Passing over control flow transitions:
H^(l+1) = ReLU( D_tilde^(-1/2) * A_tilde * D_tilde^(-1/2) * H^(l) * W^(l) )
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
            # Add self-loops: A_tilde = A + I
            identity = torch.eye(adj.size(0), device=adj.device)
            a_tilde = adj + identity
            
            # Degree normalization
            d = torch.sum(a_tilde, dim=1)
            d_inv_sqrt = torch.pow(d, -0.5)
            d_inv_sqrt[torch.isinf(d_inv_sqrt)] = 0.0
            d_mat = torch.diag(d_inv_sqrt)
            
            # Symmetric normalized adjacency: D^(-1/2) * A * D^(-1/2)
            norm_adj = torch.mm(torch.mm(d_mat, a_tilde), d_mat)
            
            # Message passing and linear transform
            support = torch.mm(norm_adj, x)
            return self.linear(support)

    class PyTorchGCNClassifier(nn.Module):
        def __init__(self, in_dim: int = 8, hidden_dim: int = 64, num_classes: int = 3, dropout: float = 0.1):
            super().__init__()
            self.gc1 = PyTorchGCNLayer(in_dim, hidden_dim)
            self.ln1 = nn.LayerNorm(hidden_dim)
            self.gc2 = PyTorchGCNLayer(hidden_dim, hidden_dim)
            self.ln2 = nn.LayerNorm(hidden_dim)
            self.fc = nn.Linear(hidden_dim, num_classes)
            self.dropout = nn.Dropout(dropout)

        def forward(self, x: torch.Tensor, adj: torch.Tensor) -> torch.Tensor:
            h = F.relu(self.ln1(self.gc1(x, adj)))
            h = self.dropout(h)
            h = F.relu(self.ln2(self.gc2(h, adj)))
            out = self.fc(h)
            return out

# Vectorized Pure-NumPy Fallback
class NumPyGCNClassifier:
    def __init__(self, in_dim: int = 8, hidden_dim: int = 32, num_classes: int = 3):
        self.w1 = np.random.randn(in_dim, hidden_dim) * 0.1
        self.b1 = np.zeros(hidden_dim)
        self.w2 = np.random.randn(hidden_dim, num_classes) * 0.1
        self.b2 = np.zeros(num_classes)

    def forward(self, x: np.ndarray, adj: np.ndarray) -> np.ndarray:
        # A_tilde = A + I
        n = adj.shape[0]
        a_tilde = adj + np.eye(n)
        d = np.sum(a_tilde, axis=1)
        d_inv_sqrt = np.power(d, -0.5)
        d_inv_sqrt[np.isinf(d_inv_sqrt)] = 0.0
        d_mat = np.diag(d_inv_sqrt)
        norm_adj = d_mat @ a_tilde @ d_mat

        # Layer 1
        h1 = np.maximum(0, (norm_adj @ x) @ self.w1 + self.b1)
        # Layer 2
        logits = (norm_adj @ h1) @ self.w2 + self.b2
        # Softmax
        exp_logits = np.exp(logits - np.max(logits, axis=1, keepdims=True))
        return exp_logits / np.sum(exp_logits, axis=1, keepdims=True)
