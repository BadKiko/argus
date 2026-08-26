from __future__ import annotations

"""ResGCN classifier — adapted from legacy Argus AI module."""

from typing import Optional

import numpy as np

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F

    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    torch = None  # type: ignore
    nn = None  # type: ignore
    F = None  # type: ignore

from argus.ml.features import FEATURE_DIM


if TORCH_AVAILABLE:

    class GCNLayer(nn.Module):
        def __init__(self, in_features: int, out_features: int):
            super().__init__()
            self.linear = nn.Linear(in_features, out_features)

        def forward(self, x: "torch.Tensor", adj: "torch.Tensor") -> "torch.Tensor":
            identity = torch.eye(adj.size(0), device=adj.device)
            a_tilde = adj + identity
            d = torch.sum(a_tilde, dim=1)
            d_inv_sqrt = torch.pow(d, -0.5)
            d_inv_sqrt[torch.isinf(d_inv_sqrt)] = 0.0
            norm_adj = d_inv_sqrt.unsqueeze(1) * a_tilde * d_inv_sqrt.unsqueeze(0)
            return self.linear(torch.mm(norm_adj, x))

    class ResGCNClassifier(nn.Module):
        def __init__(self, in_dim: int = FEATURE_DIM, hidden_dim: int = 128, num_classes: int = 3, dropout: float = 0.1):
            super().__init__()
            self.in_proj = nn.Linear(in_dim, hidden_dim)
            self.gc1 = GCNLayer(hidden_dim, hidden_dim)
            self.ln1 = nn.LayerNorm(hidden_dim)
            self.gc2 = GCNLayer(hidden_dim, hidden_dim)
            self.ln2 = nn.LayerNorm(hidden_dim)
            self.gc3 = GCNLayer(hidden_dim, hidden_dim)
            self.ln3 = nn.LayerNorm(hidden_dim)
            self.head = nn.Sequential(
                nn.Linear(hidden_dim, hidden_dim // 2),
                nn.ReLU(),
                nn.Dropout(dropout),
                nn.Linear(hidden_dim // 2, num_classes),
            )

        def forward(self, x: "torch.Tensor", adj: "torch.Tensor") -> "torch.Tensor":
            h0 = F.relu(self.in_proj(x))
            h1 = F.relu(self.ln1(self.gc1(h0, adj))) + h0
            h2 = F.relu(self.ln2(self.gc2(h1, adj))) + h1
            h3 = F.relu(self.ln3(self.gc3(h2, adj))) + h2
            return self.head(h3)


def train_res_gcn(
    graphs: list,
    epochs: int = 30,
    lr: float = 1e-3,
) -> Optional[object]:
    """graphs: list of (adj, feats, labels)."""
    if not TORCH_AVAILABLE:
        return None
    model = ResGCNClassifier()
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    loss_fn = nn.CrossEntropyLoss()
    model.train()
    for _ in range(epochs):
        total = 0.0
        for adj, feats, labels in graphs:
            x = torch.tensor(feats, dtype=torch.float32)
            a = torch.tensor(adj, dtype=torch.float32)
            y = torch.tensor(labels, dtype=torch.long)
            opt.zero_grad()
            logits = model(x, a)
            loss = loss_fn(logits, y)
            loss.backward()
            opt.step()
            total += float(loss.item())
    model.eval()
    return model


def predict(model, adj: np.ndarray, feats: np.ndarray):
    if not TORCH_AVAILABLE or model is None:
        return None, None
    with torch.no_grad():
        x = torch.tensor(feats, dtype=torch.float32)
        a = torch.tensor(adj, dtype=torch.float32)
        logits = model(x, a)
        probs = torch.softmax(logits, dim=1).cpu().numpy()
        preds = np.argmax(probs, axis=1)
        conf = probs.max(axis=1)
    return preds, conf
