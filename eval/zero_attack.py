"""What the system does when there is nothing to find.

Every other number here is recall-shaped: given crime, did we catch it. This is
the opposite question, and the one an operator actually lives with. A dataset
with no injected criminal pattern at all should produce no alerts. Whatever it
does produce is the false-positive rate, and it is reported whether or not it
flatters us — a detector that alerts on ordinary traffic wastes the analyst's
day regardless of how good its recall is.

The dataset is the canonical one with `generator.pattern_mix` set to `normal`
only: same seed, same size, same relay observation rate, same everything else.
Exchanges, ordinary wallets and CoinJoin-free traffic, and nothing planted.
"""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from fusion.pipeline import build_alerts, collect_signals

from .datasets import Dataset, build


def dataset(cfg: dict, seed: int | None = None, rebuild: bool = False) -> Dataset:
    """The canonical setup with every criminal typology turned off."""
    e = cfg["eval"]
    quiet = json.loads(json.dumps(cfg))
    # `normal` alone. Not a smaller mix — zero, so a pattern cannot appear by
    # rounding when the transaction budget is divided up.
    quiet["generator"]["pattern_mix"] = {"normal": 1.0}
    return build(e["default_rate"], False, seed if seed is not None else e["seed"],
                 quiet, rebuild=rebuild, name_prefix="zero-attack")


def evaluate(cfg: dict, stacker, seed: int | None = None, rebuild: bool = False) -> dict:
    """Run the whole stack on clean traffic and count what fires.

    `stacker` is the model fitted on the canonical standard set — the same one
    whose AUC the report quotes. There is nothing to fit here (no positives at
    all), and fitting a second model somewhere else would measure a detector
    the report does not otherwise describe.
    """
    ds = dataset(cfg, seed, rebuild)
    gt = ds.ground_truth()
    planted = {cid: c["pattern_type"] for cid, c in gt["clusters"].items()
               if c["pattern_type"] not in ("normal", "exchange")}

    bundle = collect_signals(ds.frame(), cfg, ds.raw)
    signals = bundle["signals"]
    scored = pd.Series(stacker.score(signals), index=signals.index)
    threshold = cfg["fusion"]["alert_threshold"]
    alerts = build_alerts({**bundle, "stacker": stacker}, stacker, cfg)

    firing = signals.assign(risk_score=scored)
    over = firing[firing["risk_score"] >= threshold]
    return {
        "dataset": ds.describe(),
        "seed": ds.seed,
        "entities": len(signals),
        "transactions": int(ds.frame()["txid"].nunique()),
        # If this is not empty the dataset is not what it claims to be, and
        # every number below means something different.
        "planted_patterns": sorted(set(planted.values())),
        "rule_alerts": int(len(bundle["alerts"])),
        "watchlist_seeds": len(bundle["seed_entities"]),
        "alerts": int(len(over)),
        "false_positive_rate": round(len(over) / len(signals), 4) if len(signals) else 0.0,
        "threshold": threshold,
        "scores": score_distribution(firing, threshold),
        "top": top_offenders(alerts, over),
        "by_signal": which_signal_fired(over, threshold),
    }


def score_distribution(firing: pd.DataFrame, threshold: float) -> pd.DataFrame:
    """Where the scores sit. The shape matters as much as the count: a hundred
    entities just over the line is a different problem from three at 0.99."""
    edges = [0.0, 0.1, 0.25, 0.5, 0.75, 0.9, 1.01]
    labels = ["0.00–0.10", "0.10–0.25", "0.25–0.50", "0.50–0.75", "0.75–0.90", "0.90–1.00"]
    buckets = pd.cut(firing["risk_score"], edges, labels=labels, right=False,
                     include_lowest=True)
    counts = buckets.value_counts().reindex(labels, fill_value=0)
    return pd.DataFrame({
        "risk bucket": labels,
        "entities": counts.values,
        "above threshold": [lo >= threshold for lo in (0.0, 0.1, 0.25, 0.5, 0.75, 0.9)],
    })


def which_signal_fired(over: pd.DataFrame, threshold: float) -> pd.DataFrame:
    """For the entities that alerted, which engine put them there."""
    if over.empty:
        return pd.DataFrame(columns=["signal", "alerts with it non-zero", "share"])
    rows = []
    for signal in ("rule_score", "anomaly_score", "gnn_score", "taint_score"):
        if signal not in over:
            continue
        n = int((over[signal] > 0).sum())
        rows.append({"signal": signal, "alerts with it non-zero": n,
                     "share": round(n / len(over), 3)})
    return pd.DataFrame(rows)


def top_offenders(alerts: pd.DataFrame, over: pd.DataFrame, limit: int = 5) -> pd.DataFrame:
    """The worst false positives, with the reason the system gave for them."""
    if over.empty:
        return pd.DataFrame(columns=["entity_id", "risk_score", "reason"])
    reasons = ({r.entity_id: r.reason for r in alerts.itertuples()}
               if alerts is not None and len(alerts) else {})
    top = over.sort_values("risk_score", ascending=False).head(limit)
    return pd.DataFrame([{"entity_id": r.entity_id[:18] + "…",
                          "risk_score": round(float(r.risk_score), 3),
                          "reason": reasons.get(r.entity_id, "—")[:110]}
                         for r in top.itertuples()])
