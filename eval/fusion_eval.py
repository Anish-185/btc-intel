"""Fusion evaluation, scored on the actor (see docs/detection_unit_protocol.md).

The stacker is trained on the actor-level label — an entity is illicit iff it
holds a wallet of a ground-truth illicit operation — and the headline numbers
are per case: did we find the operation, was the alert a real case, and can we
trace out to the rest of it. The old broad wallet label is still fitted and
reported beside it, as the secondary comparison the previous pass quoted.
"""

from __future__ import annotations

import pandas as pd
from sklearn.metrics import roc_auc_score

from engines.rules.detectors import FeatureSet
from fusion.pipeline import collect_signals
from fusion.stacker import SIGNALS, ablation, train

from .actors import (BROAD_PATTERNS, actors_of, broad_label_wallets, case_metrics,
                     illicit_entities, per_typology_cases)
from .datasets import Dataset


def label_entities(dataset: Dataset, features: FeatureSet, patterns: set[str]) -> set[str]:
    """Entities holding any wallet of a cluster with one of these patterns."""
    gt = dataset.ground_truth()
    out = set()
    for cluster in gt["clusters"].values():
        if cluster["pattern_type"] in patterns:
            for wallet in cluster["wallets"]:
                out.add(features.entity_of(wallet))
    return out


def fit_block(signals: pd.DataFrame, ids: set[str], cfg: dict) -> dict | None:
    """Fit the stacker on one label definition and report it with its ablation."""
    y = signals["entity_id"].isin(ids).astype(int)
    if y.sum() == 0 or y.sum() == len(y):
        return None
    stacker = train(signals, y, cfg)
    return {
        "positives": int(y.sum()),
        "auc": stacker.metrics.get("auc"),
        "auc_in_sample": stacker.metrics.get("auc_in_sample", False),
        "coefficients": stacker.metrics.get("coefficients", {}),
        "ablation": ablation(signals, y, list(SIGNALS), cfg),
        "signal_auc": {s: round(float(roc_auc_score(y, signals[s])), 4)
                       if signals[s].std() else None for s in SIGNALS},
        "stacker": stacker,
    }


def evaluate(dataset: Dataset, cfg: dict) -> dict:
    bundle = collect_signals(dataset.frame(), cfg, dataset.raw)
    signals = bundle["signals"]
    features = bundle["features"]
    actors = actors_of(dataset)

    actor_entities = illicit_entities(actors, features.entity_of)
    broad_entities = label_entities(dataset, features, BROAD_PATTERNS)

    out = {"dataset": dataset.name, "seed": dataset.seed, "shifted": dataset.shifted,
           "entities": len(signals), "watchlist_seeds": len(bundle["seed_entities"]),
           "rule_alerts": len(bundle["alerts"]), "actors": len(actors)}

    out["actor"] = fit_block(signals, actor_entities, cfg)
    out["broad"] = fit_block(signals, broad_entities, cfg)

    # Alerts as the product would raise them: the actor-trained stacker at the
    # configured threshold. Every case metric below is scored on this set.
    block = out["actor"]
    if block:
        scored = block["stacker"].score(signals)
        alerted = set(signals.loc[scored >= cfg["fusion"]["alert_threshold"], "entity_id"])
        entity_wallets = {cid: set(members)
                          for cid, members in features.clustering.clusters.items()}
        out["cases"] = case_metrics(dataset, alerted, features.entity_of, entity_wallets,
                                    bundle["entity_graph"], cfg)
        out["per_typology_cases"] = per_typology_cases(dataset, alerted, features.entity_of,
                                                       bundle["entity_graph"], cfg)
        out["alerted_entities"] = len(alerted)
        block.pop("stacker", None)
    if out["broad"]:
        out["broad"].pop("stacker", None)

    out["taint"] = taint_value(signals, bundle, actor_entities, cfg)
    out["per_typology_wallets"] = per_typology_recall(dataset, bundle, cfg)
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
    """Wallet-level coverage per typology — secondary, kept for comparability."""
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


def broad_wallet_count(dataset: Dataset) -> int:
    return len(broad_label_wallets(dataset))
