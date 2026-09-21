"""Fusion evaluation: stacker AUC, taint's independent value, per-typology recall."""

from __future__ import annotations

import pandas as pd
from sklearn.metrics import roc_auc_score

import config
from engines.rules.detectors import FeatureSet
from fusion.pipeline import collect_signals
from fusion.stacker import SIGNALS, ablation, train

from .datasets import Dataset

# Two ways to say "illicit", reported side by side because they measure very
# different things. ACTORS is who ran the scheme; ASSOCIATED includes every
# pass-through wallet the money touched, most of which have one transaction and
# are, by construction, indistinguishable from ordinary small wallets.
ACTOR_PATTERNS = {"ransomware_collector"}
ASSOCIATED_PATTERNS = {"ransomware_collector", "layering", "cashout"}


def label_entities(dataset: Dataset, features: FeatureSet, patterns: set[str]) -> set[str]:
    gt = dataset.ground_truth()
    out = set()
    for cluster in gt["clusters"].values():
        if cluster["pattern_type"] in patterns:
            for wallet in cluster["wallets"]:
                out.add(features.entity_of(wallet))
    return out


def evaluate(dataset: Dataset, cfg: dict) -> dict:
    bundle = collect_signals(dataset.frame(), cfg, dataset.raw)
    signals = bundle["signals"]
    features = bundle["features"]

    actors = label_entities(dataset, features, ACTOR_PATTERNS)
    associated = label_entities(dataset, features, ASSOCIATED_PATTERNS)

    out = {"dataset": dataset.name, "entities": len(signals),
           "watchlist_seeds": len(bundle["seed_entities"]),
           "rule_alerts": len(bundle["alerts"])}

    for label_name, ids in (("associated", associated), ("actors", actors)):
        y = signals["entity_id"].isin(ids).astype(int)
        if y.sum() == 0 or y.sum() == len(y):
            continue
        stacker = train(signals, y, cfg)
        out[label_name] = {
            "positives": int(y.sum()),
            "auc": stacker.metrics.get("auc"),
            "auc_in_sample": stacker.metrics.get("auc_in_sample", False),
            "coefficients": stacker.metrics.get("coefficients", {}),
            "ablation": ablation(signals, y, list(SIGNALS), cfg),
            "signal_auc": {s: round(float(roc_auc_score(y, signals[s])), 4)
                           if signals[s].std() else None for s in SIGNALS},
        }

    out["taint"] = taint_value(signals, bundle, associated, cfg)
    out["per_typology"] = per_typology_recall(dataset, bundle, cfg)
    return out


def taint_value(signals: pd.DataFrame, bundle: dict, illicit: set[str], cfg: dict) -> dict:
    """What taint finds that the rules did not.

    Scored only on entities that are neither watchlist seeds nor rule-flagged —
    taint gets no credit for re-reporting what was already known.
    """
    seeds = bundle["seed_entities"]
    flagged = set(bundle["alerts"]["entity_id"]) if len(bundle["alerts"]) else set()
    known = seeds | flagged
    unknown = signals[~signals["entity_id"].isin(known)]
    if unknown.empty:
        return {}

    tainted = unknown[unknown["taint_score"] > 0]
    found = tainted[tainted["entity_id"].isin(illicit)]
    missed_illicit = unknown[unknown["entity_id"].isin(illicit)]
    y = unknown["entity_id"].isin(illicit).astype(int)
    return {
        "scored_on": len(unknown),
        "excluded_as_already_known": len(known),
        "tainted": len(tainted),
        "accomplices_found_that_rules_missed": len(found),
        "illicit_not_already_known": len(missed_illicit),
        "recall_of_the_remainder": round(len(found) / len(missed_illicit), 3)
        if len(missed_illicit) else 0.0,
        "precision": round(len(found) / len(tainted), 3) if len(tainted) else 0.0,
        "auc_on_unknown_entities": round(float(roc_auc_score(y, unknown["taint_score"])), 4)
        if y.sum() and unknown["taint_score"].std() else None,
    }


def per_typology_recall(dataset: Dataset, bundle: dict, cfg: dict) -> pd.DataFrame:
    """Which typologies the stack actually catches, one row each."""
    gt = dataset.ground_truth()
    features = bundle["features"]
    signals = bundle["signals"]
    flagged = set(bundle["alerts"]["entity_id"]) if len(bundle["alerts"]) else set()
    tainted = set(signals[signals["taint_score"] > 0]["entity_id"])
    seeds = bundle["seed_entities"]

    rows = []
    for pattern in ("ransomware_collector", "layering", "same_actor_cluster",
                    "cashout", "exchange", "normal"):
        entities = label_entities(dataset, features, {pattern})
        if not entities:
            continue
        rows.append({
            "typology": pattern, "entities": len(entities),
            "rule_flagged": round(len(entities & flagged) / len(entities), 3),
            "tainted": round(len(entities & tainted) / len(entities), 3),
            "either": round(len(entities & (flagged | tainted)) / len(entities), 3),
            "watchlist_seeded": round(len(entities & seeds) / len(entities), 3),
        })
    return pd.DataFrame(rows)
