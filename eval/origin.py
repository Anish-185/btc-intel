"""Origin-estimator evaluation, per docs/origin_eval_protocol.md."""

from __future__ import annotations

import pandas as pd

import config
from engines.propagation.estimators import ESTIMATORS, estimate_all
from engines.propagation.tree import build_trees
from ingest.ip_intel import load_intel

from .datasets import Dataset


def truth_of(dataset: Dataset) -> dict[str, str]:
    gt = dataset.ground_truth()
    return {txid: meta["observed_origin_ip"] for txid, meta in gt["transactions"].items()}


def ceiling(dataset: Dataset) -> tuple[float, int]:
    """Fraction of multi-hop transactions whose true origin appears at all.

    No estimator can exceed this — it is the share of cases where the answer is
    present in the evidence.
    """
    truth = truth_of(dataset)
    trees = {k: v for k, v in build_trees(dataset.frame()).items()
             if not v.is_single_observation}
    if not trees:
        return 0.0, 0
    hits = sum(truth.get(txid) in tree.ips for txid, tree in trees.items())
    return hits / len(trees), len(trees)


def score_estimator(dataset: Dataset, name: str, cfg: dict,
                    class_weights: bool = True) -> dict:
    truth = truth_of(dataset)
    intel = load_intel(None, dataset.raw, cfg)
    origins, _ = estimate_all(dataset.frame(), intel, cfg, name, class_weights)
    origins = origins[~origins["degraded"]]
    if origins.empty:
        return {"estimator": name, "n": 0}

    trees = build_trees(dataset.frame())
    observed = {txid: truth.get(txid) in trees[txid].ips for txid in origins["txid"]}
    correct = [r.estimated_origin_ip == truth.get(r.txid) for r in origins.itertuples()]
    top3 = [truth.get(r.txid) in [r.estimated_origin_ip] + list(r.runner_up_ips)
            for r in origins.itertuples()]
    observable = [observed[r.txid] for r in origins.itertuples()]

    conditional = [c for c, o in zip(correct, observable) if o]
    return {
        "estimator": name, "n": len(origins),
        "top1": sum(correct) / len(correct),
        "top3": sum(top3) / len(top3),
        "conditional_top1": (sum(conditional) / len(conditional)) if conditional else 0.0,
        "brier": brier(origins["confidence"], correct),
        "frame": origins.assign(correct=correct, origin_observed=observable),
    }


def brier(confidence, correct) -> float:
    """Mean squared error between stated confidence and being right."""
    confidence = list(confidence)
    if not confidence:
        return 0.0
    return round(sum((c - int(k)) ** 2 for c, k in zip(confidence, correct)) / len(confidence), 4)


def reliability(frame: pd.DataFrame, bins: int) -> pd.DataFrame:
    """Confidence vs. observed accuracy, bucketed."""
    if frame.empty:
        return pd.DataFrame(columns=["bucket", "n", "mean_confidence", "accuracy"])
    edges = [i / bins for i in range(bins + 1)]
    buckets = pd.cut(frame["confidence"], edges, include_lowest=True)
    grouped = frame.groupby(buckets, observed=True)
    return pd.DataFrame({
        "bucket": [str(i) for i in grouped.groups],
        "n": grouped.size().values,
        "mean_confidence": grouped["confidence"].mean().round(3).values,
        "accuracy": grouped["correct"].mean().round(3).values,
    })


def flag_quality(frame: pd.DataFrame) -> dict:
    """How often origin_likely_unobserved is right.

    "Right" means: the flag is set and the true origin really was absent from
    the observed tree, or the flag is clear and it really was present.
    """
    if frame.empty:
        return {}
    flagged = frame["origin_likely_unobserved"]
    unobserved = ~frame["origin_observed"]
    tp = int((flagged & unobserved).sum())
    fp = int((flagged & ~unobserved).sum())
    fn = int((~flagged & unobserved).sum())
    tn = int((~flagged & ~unobserved).sum())
    return {"flagged": int(flagged.sum()), "of": len(frame),
            "precision": round(tp / (tp + fp), 3) if tp + fp else 0.0,
            "recall": round(tp / (tp + fn), 3) if tp + fn else 0.0,
            "accuracy": round((tp + tn) / len(frame), 3),
            "accuracy_when_flag_clear": round(frame[~flagged]["correct"].mean(), 3)
            if (~flagged).any() else 0.0,
            "accuracy_when_flagged": round(frame[flagged]["correct"].mean(), 3)
            if flagged.any() else 0.0}


def evaluate(datasets: dict[float, Dataset], cfg: dict) -> dict:
    """The full origin table: every estimator at every observation rate."""
    rows, extras = [], {}
    for rate, dataset in sorted(datasets.items()):
        cap, n_trees = ceiling(dataset)
        for name in ESTIMATORS:
            result = score_estimator(dataset, name, cfg)
            rows.append({"rate": rate, "estimator": name, "ceiling": cap,
                         "multi_hop_txs": n_trees, **{k: v for k, v in result.items()
                                                      if k != "frame"}})
            if rate == cfg["eval"]["default_rate"]:
                extras[name] = result["frame"]
    return {"table": pd.DataFrame(rows), "frames": extras}


def class_weight_ablation(dataset: Dataset, cfg: dict) -> pd.DataFrame:
    """What the relay / Tor / hosting down-weighting is actually worth."""
    rows = []
    for name in ESTIMATORS:
        for label, weights in (("with filter", True), ("without filter", False)):
            result = score_estimator(dataset, name, cfg, class_weights=weights)
            rows.append({"estimator": name, "class_weights": label,
                         "top1": result["top1"], "conditional_top1": result["conditional_top1"]})
    return pd.DataFrame(rows)
