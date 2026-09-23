"""Supervised training on SYNTHETIC labels.

    python -m engines.gnn.train --input data/processed/transactions.parquet \
        --ground-truth data/raw/ground_truth.json

⚠️  READ THIS BEFORE TRUSTING ANY NUMBER THIS PRODUCES.

The only labels this model has ever seen come from `generator/` — patterns we
invented and then asked the model to find. That makes every accuracy figure
here a statement about our own simulator, not about Bitcoin. Specifically:

  * NTRO's real data will arrive with NO labels, so this model cannot be
    retrained on it — it can only be applied, and its errors there are unknown.
  * Our typologies are cleaner than reality: real ransomware collectors mix
    with exchange deposits, real layering hides inside ordinary commerce.
  * A real illicit/licit split is far more imbalanced than ours.
  * Nothing here has been validated against a real labelled corpus such as
    Elliptic; doing so is the honest next step before this score carries weight.

So: this is ONE signal among several in `fusion/`, deliberately weighted
alongside rules and anomaly detection which need no labels at all. The rules
engine, not this, is what an investigator should be shown first.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import torch
from torch import nn

import config
from graph.builder import from_parquet

from .data import build_dataset, load_labels, temporal_split, z_norm
from .model import GINe

SYNTHETIC_LABELS_WARNING = (
    "trained on synthetic labels from generator/; real-world generalisation is unproven"
)


def metrics(probs: torch.Tensor, y: torch.Tensor, threshold: float = 0.5) -> dict:
    pred = (probs >= threshold).long()
    tp = int(((pred == 1) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": round(precision, 4), "recall": round(recall, 4),
            "f1": round(f1, 4), "positives": int((y == 1).sum()), "n": int(len(y))}


def train(data, cfg: dict | None = None, epochs: int | None = None, verbose: bool = False):
    """Returns (model, artefacts, history). Raises if nothing is labelled."""
    cfg = cfg or config.load()
    g = cfg["engines"]["gnn"]
    torch.manual_seed(g["seed"])

    if not bool(data.labelled.any()):
        raise ValueError("no labelled edges — GNN training needs ground_truth.json; "
                         "unlabelled data is what the rules and anomaly engines are for")

    x, x_stats = z_norm(data.x)
    edge_attr, e_stats = z_norm(data.edge_attr)
    train_mask, val_mask, test_mask = temporal_split(data, cfg)
    if not bool(train_mask.any()):
        train_mask = data.labelled  # tiny graphs: train on whatever is labelled

    model = GINe(data.x.shape[1], data.edge_attr.shape[1], hidden=g["hidden"],
                 layers=g["layers"], dropout=g["dropout"])
    optimiser = torch.optim.Adam(model.parameters(), lr=g["lr"], weight_decay=g["weight_decay"])

    y = data.y.clamp(min=0).float()
    positives = float(y[train_mask].sum())
    negatives = float(train_mask.sum()) - positives
    # illicit is the rare class; without this the model learns to say "licit"
    pos_weight = torch.tensor([negatives / positives if positives else 1.0])
    loss_fn = nn.BCEWithLogitsLoss(pos_weight=pos_weight)

    history = []
    for epoch in range(epochs if epochs is not None else g["epochs"]):
        model.train()
        optimiser.zero_grad()
        logits = model(x, data.edge_index, edge_attr)
        loss = loss_fn(logits[train_mask], y[train_mask])
        loss.backward()
        optimiser.step()

        entry = {"epoch": epoch, "loss": round(loss.detach().item(), 5)}
        if bool(val_mask.any()):
            probs = model.predict_proba(x, data.edge_index, edge_attr)
            entry["val"] = metrics(probs[val_mask], data.y[val_mask])
        history.append(entry)
        if verbose:
            print(json.dumps(entry))

    probs = model.predict_proba(x, data.edge_index, edge_attr)
    artefacts = {
        "state_dict": model.state_dict(),
        "node_dim": data.x.shape[1], "edge_dim": data.edge_attr.shape[1],
        "node_features": data.node_features, "edge_features": data.edge_features,
        "x_stats": x_stats, "edge_stats": e_stats,
        "config": {k: g[k] for k in ("hidden", "layers", "dropout", "illicit_typologies")},
        "warning": SYNTHETIC_LABELS_WARNING,
        "val": metrics(probs[val_mask], data.y[val_mask]) if bool(val_mask.any()) else None,
        "test": metrics(probs[test_mask], data.y[test_mask]) if bool(test_mask.any()) else None,
    }
    return model, artefacts, history


def _source_seed(ground_truth: Path) -> int | None:
    """The generator seed of the dataset this model is about to learn."""
    try:
        return json.loads(Path(ground_truth).read_text()).get("seed")
    except Exception:                       # no ground truth, or not ours
        return None


def save(artefacts: dict, path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    torch.save(artefacts, path)
    return path


def run(input_path=None, ground_truth=None, model_path=None, epochs=None,
        cfg: dict | None = None, verbose: bool = True) -> dict:
    cfg = cfg or config.load()
    graph = from_parquet(input_path, cfg)
    labels = load_labels(ground_truth or Path(cfg["ingest"]["input_dir"]) / "ground_truth.json", cfg)
    data = build_dataset(graph, labels=labels, cfg=cfg)
    _, artefacts, _ = train(data, cfg, epochs, verbose=verbose)
    # Provenance, so an evaluation can refuse to score this model against the
    # data it learned. Without it, training on the demo dataset and evaluating
    # on the canonical eval set — which share a seed — looks like a good result.
    source = Path(ground_truth or Path(cfg["ingest"]["input_dir"]) / "ground_truth.json")
    artefacts["trained_on"] = {
        "ground_truth": str(source),
        "seed": _source_seed(source),
        "input": str(input_path or cfg["ingest"]["output_path"]),
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    path = save(artefacts, model_path or cfg["models"]["gnn"])
    return {"edges": data.num_edges, "nodes": data.num_nodes,
            "labelled": int(data.labelled.sum()),
            "illicit_edges": int((data.y == 1).sum()),
            "val": artefacts["val"], "test": artefacts["test"],
            "model": str(path), "warning": SYNTHETIC_LABELS_WARNING}


def main(argv=None) -> None:
    cfg = config.load()
    ap = argparse.ArgumentParser(prog="engines.gnn.train", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", default=cfg["ingest"]["output_path"])
    ap.add_argument("--ground-truth",
                    default=str(Path(cfg["ingest"]["input_dir"]) / "ground_truth.json"))
    ap.add_argument("--model", default=cfg["models"]["gnn"])
    ap.add_argument("--epochs", type=int, default=cfg["engines"]["gnn"]["epochs"])
    args = ap.parse_args(argv)
    print(json.dumps(run(args.input, args.ground_truth, args.model, args.epochs), indent=2))


if __name__ == "__main__":
    main()
