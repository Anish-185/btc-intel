"""Unsupervised outlier detection over entity features.

IsolationForest, deliberately: it needs no labels, so unlike engines/gnn it
still works on NTRO's real data. It finds entities that are unusual, which is
not the same as illicit — an exchange is wildly unusual and entirely legitimate.
Its score is one input to fusion, never an alert on its own.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd
from sklearn.ensemble import IsolationForest

import config

SCORE_COLUMNS = ["entity_id", "anomaly_score", "is_outlier"]


def feature_matrix(entities: pd.DataFrame, cfg: dict | None = None) -> pd.DataFrame:
    cols = (cfg or config.load())["engines"]["anomaly"]["features"]
    present = [c for c in cols if c in entities.columns]
    return entities[present].astype(float).fillna(0.0)


def fit_score(entities: pd.DataFrame, cfg: dict | None = None) -> pd.DataFrame:
    """Fit and score in one pass — there is no held-out set to protect here."""
    cfg = cfg or config.load()
    a = cfg["engines"]["anomaly"]
    if entities.empty:
        return pd.DataFrame(columns=SCORE_COLUMNS)
    X = feature_matrix(entities, cfg)
    model = IsolationForest(n_estimators=a["n_estimators"], contamination=a["contamination"],
                            random_state=a["seed"]).fit(X)
    # decision_function: higher is more normal. Flip and squash to [0, 1].
    raw = -model.decision_function(X)
    spread = raw.max() - raw.min()
    scaled = (raw - raw.min()) / spread if spread else raw * 0.0
    return pd.DataFrame({"entity_id": entities["cluster_id"].values,
                         "anomaly_score": scaled,
                         "is_outlier": model.predict(X) == -1},
                        columns=SCORE_COLUMNS)


def run(features_path=None, output=None, cfg: dict | None = None) -> dict:
    cfg = cfg or config.load()
    entities = pd.read_parquet(features_path or cfg["features"]["entity_path"])
    scores = fit_score(entities, cfg)
    output = Path(output or cfg["engines"]["anomaly"]["scores_path"])
    output.parent.mkdir(parents=True, exist_ok=True)
    scores.to_parquet(output, index=False)
    return {"entities": len(scores), "outliers": int(scores["is_outlier"].sum()),
            "mean_score": round(float(scores["anomaly_score"].mean()), 4) if len(scores) else 0.0,
            "output": str(output)}


def main(argv=None) -> None:
    cfg = config.load()
    ap = argparse.ArgumentParser(prog="engines.anomaly.detector", description=__doc__)
    ap.add_argument("--features", default=cfg["features"]["entity_path"])
    ap.add_argument("--output", default=cfg["engines"]["anomaly"]["scores_path"])
    args = ap.parse_args(argv)
    print(json.dumps(run(args.features, args.output), indent=2))


if __name__ == "__main__":
    main()
