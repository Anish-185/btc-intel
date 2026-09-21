"""Our wallet/transaction graph as tensors for edge classification.

Layout follows Multi-GNN (vendor/, read not imported — see docs/vendor_notes.md):
**nodes are entities, edges are transactions**, and the label lives on the edge.
Two adaptations their bank-ledger model does not need:

  * a UTXO transaction is many-to-many, so one transaction becomes every
    (input entity -> output entity) pair, capped by `max_edges_per_tx`; the
    per-transaction score is pooled back over those edges at inference.
  * a transaction whose value never leaves one entity (pure change) would
    otherwise vanish, so it keeps one self-loop edge.

Tensors are plain torch. `to_pyg_data()` wraps them in a PyTorch Geometric
`Data` object when PyG is installed, which is the on-ramp to its GAT/PNA/RGCN
layers later; nothing here requires it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd
import torch

import config
from engines.rules.detectors import FeatureSet
from graph.builder import graph_transactions

UNKNOWN = -1

NODE_FEATURES = ["wallets", "txs", "txs_in", "txs_out", "counterparties_in",
                 "counterparties_out", "fan_in_ratio", "fan_out_ratio", "value_in",
                 "value_out", "round_amount_ratio", "velocity", "lifetime_days",
                 "dormant_then_active", "max_dormant_gap_days", "max_burst_transactions",
                 "unique_broadcast_ips", "unique_asns", "suspicious_merge"]

TX_FEATURES = ["input_count", "output_count", "equal_output_count", "equal_output_value",
               "peel_ratio", "value_in", "value_out", "fee",
               "time_since_prev_tx_same_wallet"]

EDGE_FEATURES = TX_FEATURES + ["edge_value", "edge_value_share"]


@dataclass
class GraphTensors:
    x: torch.Tensor              # [N, F_node]
    edge_index: torch.Tensor     # [2, E]
    edge_attr: torch.Tensor      # [E, F_edge]
    y: torch.Tensor              # [E] 1 illicit, 0 licit, -1 unknown
    edge_txid: list[str]         # txid behind each edge
    nodes: list[str]             # entity id per node index
    timestamps: torch.Tensor     # [E] epoch seconds, for the chronological split
    node_features: list[str] = field(default_factory=lambda: list(NODE_FEATURES))
    edge_features: list[str] = field(default_factory=lambda: list(EDGE_FEATURES))

    @property
    def num_nodes(self) -> int:
        return self.x.shape[0]

    @property
    def num_edges(self) -> int:
        return self.edge_index.shape[1]

    @property
    def labelled(self) -> torch.Tensor:
        return self.y >= 0

    def to_pyg_data(self):
        """A PyTorch Geometric Data object, if PyG is installed."""
        from torch_geometric.data import Data  # optional dependency
        return Data(x=self.x, edge_index=self.edge_index, edge_attr=self.edge_attr,
                    y=self.y, timestamps=self.timestamps)


def load_labels(ground_truth, cfg: dict | None = None) -> dict[str, int]:
    """txid -> 1 illicit / 0 licit, from the generator's hidden ground truth."""
    cfg = cfg or config.load()
    illicit = set(cfg["engines"]["gnn"]["illicit_typologies"])
    gt = (ground_truth if isinstance(ground_truth, dict)
          else json.loads(Path(ground_truth).read_text()))
    return {txid: int(meta["typology"] in illicit) for txid, meta in gt["transactions"].items()}


def _finite(value, fill: float = -1.0) -> float:
    v = float(value)
    return fill if (np.isnan(v) or np.isinf(v)) else v


def build_dataset(graph, features: FeatureSet | None = None,
                  labels: dict[str, int] | None = None,
                  cfg: dict | None = None) -> GraphTensors:
    cfg = cfg or config.load()
    g = cfg["engines"]["gnn"]
    features = features or FeatureSet.from_graph(graph, cfg)
    txs = list(graph_transactions(graph)) if hasattr(graph, "nodes") else list(graph)

    entities = features.entities.set_index("cluster_id")
    node_ids = list(entities.index)
    index = {eid: i for i, eid in enumerate(node_ids)}
    x = torch.tensor(entities[NODE_FEATURES].astype(float).to_numpy(), dtype=torch.float)

    tx_rows = features.transactions.set_index("txid")
    src, dst, attrs, ys, txids, times = [], [], [], [], [], []
    for tx in txs:
        if tx.txid not in tx_rows.index:
            continue
        row = tx_rows.loc[tx.txid]
        base = [_finite(row[f]) for f in TX_FEATURES]
        total_out = sum(tx.output_values) or 1.0
        senders: dict[str, float] = {}
        receivers: dict[str, float] = {}
        for addr, value in tx.inputs:
            senders[features.entity_of(addr)] = senders.get(features.entity_of(addr), 0.0) + value
        for addr, value in tx.outputs:
            receivers[features.entity_of(addr)] = receivers.get(features.entity_of(addr), 0.0) + value

        pairs = [(a, b, v) for a in senders for b, v in receivers.items() if a != b]
        if not pairs:  # everything stayed inside one entity — keep a self-loop
            only = next(iter(senders or receivers), None)
            pairs = [(only, only, total_out)] if only is not None else []
        pairs.sort(key=lambda p: (-p[2], p[0], p[1]))
        pairs = pairs[: g["max_edges_per_tx"]]

        label = UNKNOWN if labels is None else labels.get(tx.txid, UNKNOWN)
        ts = pd.Timestamp(tx.timestamp).timestamp() if tx.timestamp is not None else 0.0
        for a, b, value in pairs:
            if a not in index or b not in index:
                continue
            src.append(index[a])
            dst.append(index[b])
            attrs.append(base + [value, value / total_out])
            ys.append(label)
            txids.append(tx.txid)
            times.append(ts)

    edge_index = torch.tensor([src, dst], dtype=torch.long) if src else torch.zeros((2, 0), dtype=torch.long)
    edge_attr = torch.tensor(attrs, dtype=torch.float) if attrs else torch.zeros((0, len(EDGE_FEATURES)))
    return GraphTensors(x=x, edge_index=edge_index, edge_attr=edge_attr,
                        y=torch.tensor(ys, dtype=torch.long) if ys else torch.zeros(0, dtype=torch.long),
                        edge_txid=txids, nodes=node_ids,
                        timestamps=torch.tensor(times, dtype=torch.double))


def z_norm(tensor: torch.Tensor, stats: tuple | None = None):
    """Standardise columns. Reuses the training statistics at inference."""
    if stats is None:
        mean = tensor.mean(dim=0)
        std = tensor.std(dim=0)
        std[std == 0] = 1.0
        stats = (mean, std)
    mean, std = stats
    return (tensor - mean) / std, stats


def temporal_split(data: GraphTensors, cfg: dict | None = None):
    """Chronological, never random: a model that has seen the future scores
    beautifully and means nothing. Same discipline as the Elliptic pipeline in
    vendor/ (see docs/vendor_notes.md)."""
    cfg = cfg or config.load()
    train_frac, val_frac, _ = cfg["engines"]["gnn"]["split"]
    order = torch.argsort(data.timestamps)
    n = len(order)
    n_train, n_val = int(n * train_frac), int(n * (train_frac + val_frac))
    masks = []
    for chunk in (order[:n_train], order[n_train:n_val], order[n_val:]):
        mask = torch.zeros(n, dtype=torch.bool)
        mask[chunk] = True
        masks.append(mask & data.labelled)
    return tuple(masks)
