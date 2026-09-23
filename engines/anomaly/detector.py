"""Unsupervised outlier detection over entity features, within peer groups.

IsolationForest, deliberately: it needs no labels, so unlike engines/gnn it
still works on NTRO's real data.

Scored against the whole population the signal *inverts*: measured on generated
data it reached AUC 0.16 alone, well below chance, because the biggest outliers
are exchanges and high-volume legitimate businesses, not criminals. The fix is
to compare like with like — entities are bucketed by transaction count and
outbound volume, and each is scored against its own peer group, so the question
becomes "is this unusual *for an entity of this size*".

It still finds entities that are unusual, which is not the same as illicit. Its
score is one input to fusion, never an alert on its own.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd
from sklearn.ensemble import IsolationForest

import config

SCORE_COLUMNS = ["entity_id", "anomaly_score", "is_outlier", "peer_group"]
GLOBAL_GROUP = "all"


def feature_matrix(entities: pd.DataFrame, cfg: dict | None = None) -> pd.DataFrame:
    cols = (cfg or config.load())["engines"]["anomaly"]["features"]
    present = [c for c in cols if c in entities.columns]
    return entities[present].astype(float).fillna(0.0)


def peer_groups(entities: pd.DataFrame, cfg: dict | None = None) -> pd.Series:
    """Bucket entities by size, so an exchange is compared with exchanges."""
    cfg = cfg or config.load()
    p = cfg["engines"]["anomaly"]["peer_groups"]
    labels = pd.Series(["" for _ in range(len(entities))], index=entities.index)
    for column in p["by"]:
        if column not in entities.columns:
            continue
        values = entities[column].astype(float)
        edges = sorted({values.quantile(q) for q in p["quantiles"]})
        bucket = pd.Series(0, index=entities.index)
        for edge in edges:
            bucket += (values > edge).astype(int)
        labels = labels + column[:3] + bucket.astype(str) + "|"
    return labels.replace("", GLOBAL_GROUP)


def _score_block(X: pd.DataFrame, a: dict) -> tuple[pd.Series, pd.Series]:
    # n_jobs only changes how many cores build the trees; with random_state
    # fixed the forest, and therefore every score, is identical. It is measured
    # rather than assumed: on our peer groups more cores is slower, so the
    # configured default is 1 (docs/redteam_performance.md).
    model = IsolationForest(n_estimators=a["n_estimators"], contamination=a["contamination"],
                            random_state=a["seed"], n_jobs=a.get("n_jobs", -1)).fit(X)
    # decision_function: higher is more normal. Flip and squash to [0, 1].
    raw = -model.decision_function(X)
    spread = raw.max() - raw.min()
    scaled = (raw - raw.min()) / spread if spread else raw * 0.0
    return pd.Series(scaled, index=X.index), pd.Series(model.predict(X) == -1, index=X.index)


def fit_score(entities: pd.DataFrame, cfg: dict | None = None) -> pd.DataFrame:
    """Fit and score within each peer group; small groups fall back to global."""
    cfg = cfg or config.load()
    a = cfg["engines"]["anomaly"]
    if entities.empty:
        return pd.DataFrame(columns=SCORE_COLUMNS)

    X = feature_matrix(entities, cfg)
    groups = peer_groups(entities, cfg)
    sizes = groups.value_counts()
    small = set(sizes[sizes < a["peer_groups"]["min_group"]].index)
    groups = groups.where(~groups.isin(small), GLOBAL_GROUP)

    scores = pd.Series(0.0, index=entities.index)
    outliers = pd.Series(False, index=entities.index)
    for label, index in groups.groupby(groups).groups.items():
        block = X.loc[index]
        if len(block) < 2:                       # nothing to compare against
            continue
        scores.loc[index], outliers.loc[index] = _score_block(block, a)

    return pd.DataFrame({"entity_id": entities["cluster_id"].values,
                         "anomaly_score": scores.values, "is_outlier": outliers.values,
                         "peer_group": groups.values}, columns=SCORE_COLUMNS)


def run(features_path=None, output=None, cfg: dict | None = None) -> dict:
    cfg = cfg or config.load()
    entities = pd.read_parquet(features_path or cfg["features"]["entity_path"])
    scores = fit_score(entities, cfg)
    output = Path(output or cfg["engines"]["anomaly"]["scores_path"])
    output.parent.mkdir(parents=True, exist_ok=True)
    scores.to_parquet(output, index=False)
    return {"entities": len(scores), "outliers": int(scores["is_outlier"].sum()),
            "peer_groups": int(scores["peer_group"].nunique()),
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
