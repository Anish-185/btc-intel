"""One GNN for edge classification: is this transaction part of illicit activity?

A simplified GINe, reimplemented from Multi-GNN's published design (vendor/,
read not imported): node and edge embeddings, GIN-style message passing that
*includes the edge features in the message* — which matters here because the
transaction is the edge — a residual update per layer, and a classifier head
over [source, destination, edge] embeddings.

Kept from Multi-GNN: edge-conditioned messages, the (x + relu(norm(conv)))/2
residual, and optional edge updates between layers.
Dropped: the GAT/PNA/RGCN variants, port numbering and reverse message passing.
Our graph is thousands of nodes, not millions of bank transfers; those
adaptations can be added later against a measured baseline.

Message passing is ~20 lines of index_add_ rather than a PyTorch Geometric
import — one fewer heavyweight, version-sensitive dependency for a model this
size. `data.to_pyg_data()` is there for when PyG's layer zoo is wanted.
"""

from __future__ import annotations

import torch
import torch.nn.functional as F
from torch import nn


class EdgeGINConv(nn.Module):
    """GIN aggregation where each message carries its edge's features."""

    def __init__(self, hidden: int):
        super().__init__()
        self.eps = nn.Parameter(torch.zeros(1))
        self.mlp = nn.Sequential(nn.Linear(hidden, hidden), nn.ReLU(), nn.Linear(hidden, hidden))

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor,
                edge_attr: torch.Tensor) -> torch.Tensor:
        src, dst = edge_index
        messages = F.relu(x[src] + edge_attr)
        aggregated = torch.zeros_like(x)
        aggregated.index_add_(0, dst, messages)
        return self.mlp((1 + self.eps) * x + aggregated)


class GINe(nn.Module):
    """Edge classifier. Returns one logit per edge."""

    def __init__(self, node_dim: int, edge_dim: int, hidden: int = 64, layers: int = 2,
                 dropout: float = 0.2, edge_updates: bool = True):
        super().__init__()
        self.node_emb = nn.Linear(node_dim, hidden)
        self.edge_emb = nn.Linear(edge_dim, hidden)
        self.convs = nn.ModuleList(EdgeGINConv(hidden) for _ in range(layers))
        self.norms = nn.ModuleList(nn.LayerNorm(hidden) for _ in range(layers))
        self.edge_mlps = nn.ModuleList(
            nn.Sequential(nn.Linear(3 * hidden, hidden), nn.ReLU(), nn.Linear(hidden, hidden))
            for _ in range(layers)) if edge_updates else None
        self.head = nn.Sequential(
            nn.Linear(3 * hidden, hidden), nn.ReLU(), nn.Dropout(dropout),
            nn.Linear(hidden, hidden // 2), nn.ReLU(), nn.Dropout(dropout),
            nn.Linear(hidden // 2, 1))

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor,
                edge_attr: torch.Tensor) -> torch.Tensor:
        src, dst = edge_index
        x = self.node_emb(x)
        e = self.edge_emb(edge_attr)
        for i, conv in enumerate(self.convs):
            x = (x + F.relu(self.norms[i](conv(x, edge_index, e)))) / 2
            if self.edge_mlps is not None:
                e = e + self.edge_mlps[i](torch.cat([x[src], x[dst], e], dim=-1)) / 2
        return self.head(torch.cat([x[src], x[dst], e], dim=-1)).squeeze(-1)

    @torch.no_grad()
    def predict_proba(self, x, edge_index, edge_attr) -> torch.Tensor:
        self.eval()
        return torch.sigmoid(self(x, edge_index, edge_attr))
