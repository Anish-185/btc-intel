"""Score transactions and entities with the trained GNN.

    python -m engines.gnn.infer --input data/processed/transactions.parquet \
        --output data/processed/gnn_scores.parquet

Edge probabilities are pooled back to one score per transaction (mean over the
edges that transaction produced) and one per entity (max, or mean, per config).
Every score carries the synthetic-label caveat from train.py — see its docstring.
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

import pandas as pd
import torch

import config
from engines.rules.detectors import FeatureSet
from graph.builder import from_parquet

from .data import build_dataset, z_norm
from .model import GINe
from .train import SYNTHETIC_LABELS_WARNING

SCORE_COLUMNS = ["id", "level", "gnn_score"]


def load_model(path=None, cfg: dict | None = None):
    cfg = cfg or config.load()
    artefacts = torch.load(path or cfg["models"]["gnn"], weights_only=False)
    model = GINe(artefacts["node_dim"], artefacts["edge_dim"],
                 hidden=artefacts["config"]["hidden"], layers=artefacts["config"]["layers"],
                 dropout=artefacts["config"]["dropout"])
    model.load_state_dict(artefacts["state_dict"])
    model.eval()
    return model, artefacts


def score(data, model, artefacts, cfg: dict | None = None) -> pd.DataFrame:
    cfg = cfg or config.load()
    how = cfg["engines"]["gnn"]["entity_aggregation"]
    if data.num_edges == 0:
        return pd.DataFrame(columns=SCORE_COLUMNS)
    x, _ = z_norm(data.x, artefacts["x_stats"])
    edge_attr, _ = z_norm(data.edge_attr, artefacts["edge_stats"])
    probs = model.predict_proba(x, data.edge_index, edge_attr).tolist()

    per_tx: dict[str, list[float]] = defaultdict(list)
    per_entity: dict[str, list[float]] = defaultdict(list)
    src, dst = data.edge_index.tolist()
    for i, p in enumerate(probs):
        per_tx[data.edge_txid[i]].append(p)
        per_entity[data.nodes[src[i]]].append(p)
        per_entity[data.nodes[dst[i]]].append(p)

    pool = max if how == "max" else (lambda v: sum(v) / len(v))
    rows = [{"id": txid, "level": "transaction", "gnn_score": sum(v) / len(v)}
            for txid, v in per_tx.items()]
    rows += [{"id": eid, "level": "entity", "gnn_score": pool(v)}
             for eid, v in per_entity.items()]
    df = pd.DataFrame(rows, columns=SCORE_COLUMNS)
    return df.sort_values(["level", "gnn_score"], ascending=[True, False], ignore_index=True)


def run(input_path=None, output=None, model_path=None, cfg: dict | None = None) -> dict:
    cfg = cfg or config.load()
    graph = from_parquet(input_path, cfg)
    features = FeatureSet.from_graph(graph, cfg)
    data = build_dataset(graph, features, cfg=cfg)
    model, artefacts = load_model(model_path, cfg)
    df = score(data, model, artefacts, cfg)
    output = Path(output or cfg["engines"]["gnn"]["scores_path"])
    output.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(output, index=False)
    counts = df["level"].value_counts().to_dict()
    return {"scored": counts, "output": str(output),
            "mean_score": round(float(df["gnn_score"].mean()), 4) if len(df) else 0.0,
            "warning": SYNTHETIC_LABELS_WARNING}


def main(argv=None) -> None:
    cfg = config.load()
    ap = argparse.ArgumentParser(prog="engines.gnn.infer", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", default=cfg["ingest"]["output_path"])
    ap.add_argument("--output", default=cfg["engines"]["gnn"]["scores_path"])
    ap.add_argument("--model", default=cfg["models"]["gnn"])
    args = ap.parse_args(argv)
    print(json.dumps(run(args.input, args.output, args.model), indent=2))


if __name__ == "__main__":
    main()
