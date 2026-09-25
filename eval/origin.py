"""Origin-estimator evaluation.

Protocols: docs/origin_eval_protocol.md (which estimator is the default) and
docs/detection_unit_protocol.md (the origin outcome costs, the three filter
configurations, and how `low_confidence_origin`'s cutoff is chosen on seed A
and reported on seed B).
"""

from __future__ import annotations

import pandas as pd

from analysis import validity
from engines.propagation.estimators import ESTIMATORS, estimate_all
from engines.propagation.tree import build_trees
from ingest.ip_intel import load_intel

from .datasets import Dataset

FILTER_MODES = ("off", "combined", "split")
OUTCOMES = ("correct_actionable", "correct_infrastructure",
            "wrong_uninvolved_third_party", "abstained",
            # the metric revision, pre-registered in docs/VALIDITY.md
            "qualified_correct", "qualified_wrong", "coinjoin_input_misattribution")
#: `metric="p6"` is the outcome vocabulary before the revision: the first four.
METRICS = ("revised", "p6")


def truth_of(dataset: Dataset) -> dict[str, str]:
    gt = dataset.ground_truth()
    return {txid: meta["observed_origin_ip"] for txid, meta in gt["transactions"].items()}


def ceiling(dataset: Dataset) -> tuple[float, int]:
    """Fraction of multi-hop transactions whose true origin appears at all.

    No estimator can exceed this — it is the share of cases where the answer is
    present in the evidence. Multi-hop only, because that is the population the
    estimators are scored on; `ceiling_both` gives the unconditional figure too.
    """
    conditional, _, trees, _ = ceiling_both(dataset)
    return conditional, trees


def ceiling_both(dataset: Dataset) -> tuple[float, float, int, int]:
    """Both denominators, because they answer different questions.

    * **Multi-hop-conditional** — of the transactions an estimator is actually
      asked about (those observed at more than one relay), how often is the
      true origin among the observed addresses. This bounds accuracy.
    * **Unconditional** — of *every* transaction in the dataset, how often is
      the true origin observed. Lower, because a transaction seen at a single
      relay is usually seen somewhere that is not its source. This is the one
      that describes the evidence an operator actually has.

    Quoting one as the other is how this repo ended up with two different
    ceiling figures in circulation, so both are returned together and the
    report prints both.
    """
    truth = truth_of(dataset)
    everything = build_trees(dataset.frame())
    multi = {k: v for k, v in everything.items() if not v.is_single_observation}
    if not everything:
        return 0.0, 0.0, 0, 0
    hit_all = sum(truth.get(txid) in tree.ips for txid, tree in everything.items())
    hit_multi = sum(truth.get(txid) in tree.ips for txid, tree in multi.items())
    return ((hit_multi / len(multi)) if multi else 0.0,
            hit_all / len(everything), len(multi), len(everything))


def score_estimator(dataset: Dataset, name: str, cfg: dict,
                    mode: str | None = None) -> dict:
    """One estimator under one origin-filter configuration."""
    truth = truth_of(dataset)
    intel = load_intel(None, dataset.raw, cfg)
    origins, _ = estimate_all(dataset.frame(), intel, cfg, name, mode)
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
    mixes = {txid for txid, meta in dataset.ground_truth()["transactions"].items()
             if meta.get("pattern") == "coinjoin"}
    frame = origins.assign(correct=correct, origin_observed=observable,
                           coinjoin_truth=origins["txid"].isin(mixes))
    return {
        "estimator": name, "n": len(origins), "filter": mode or cfg["engines"]["propagation"]["origin_filter"]["mode"],
        "top1": sum(correct) / len(correct),
        "top3": sum(top3) / len(top3),
        "conditional_top1": (sum(conditional) / len(conditional)) if conditional else 0.0,
        "brier": brier(origins["confidence"], correct),
        "frame": frame,
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


# --- the flag and the cost-weighted outcome metric ------------------------
def flagged_at(frame: pd.DataFrame, cfg: dict, cutoff: float | None = None) -> pd.Series:
    """`low_confidence_origin` recomputed at an arbitrary cutoff.

    Same rule as engines.propagation.low_confidence_origin: a public relay at
    the top, confidence below the cutoff, or — when the frame carries a verdict
    — a validity tier the configured policy withholds (analysis.validity: the
    ABSTAIN tier, or every non-PASS tier in P6's binary mode).
    """
    p = cfg["engines"]["propagation"]
    cut = p["low_confidence_cutoff"] if cutoff is None else cutoff
    flagged = frame["ip_class"].isin(p["low_confidence_classes"]) | (frame["confidence"] < cut)
    if "validity_tier" in frame:
        flagged |= frame["validity_tier"].map(lambda t: validity.withholds(t, cfg))
    return flagged


def outcomes(frame: pd.DataFrame, cfg: dict, cutoff: float | None = None,
             metric: str = "revised") -> pd.Series:
    """One outcome per estimate, per docs/detection_unit_protocol.md and the
    metric revision in docs/VALIDITY.md, decided in this order:

      abstained                      the policy withholds it; free
      coinjoin_input_misattribution  (revised) a true CoinJoin answered without
                                     the COINJOIN qualification: it claims
                                     ownership of other people's inputs
      qualified_correct / _wrong     (revised) a QUALIFIED answer, right or wrong
      correct_actionable / correct_infrastructure / wrong_uninvolved_third_party

    `metric="p6"` skips the two revised steps. A frame without verdicts or
    CoinJoin labels scores exactly as before the revision.
    """
    anonymized = frame["ip_class"] != "residential_or_unknown"
    flagged = flagged_at(frame, cfg, cutoff)
    revised = metric == "revised"
    qualifies = revised and validity.tiered(cfg) and "validity_tier" in frame
    n = len(frame)
    tiers = frame["validity_tier"] if "validity_tier" in frame else [validity.PASS] * n
    reasons = frame["validity_reasons"] if "validity_reasons" in frame else [()] * n
    mixes = frame["coinjoin_truth"] if "coinjoin_truth" in frame else [False] * n
    labels = []
    for f, c, a, tier, why, mix in zip(flagged, frame["correct"], anonymized, tiers,
                                       reasons, mixes):
        qualified = qualifies and tier == validity.QUALIFIED
        if f:
            labels.append("abstained")
        elif revised and mix and not (qualified and validity.COINJOIN in list(why)):
            labels.append("coinjoin_input_misattribution")
        elif qualified:
            labels.append("qualified_correct" if c else "qualified_wrong")
        else:
            labels.append("correct_infrastructure" if (c and a) else
                          "correct_actionable" if c else "wrong_uninvolved_third_party")
    return pd.Series(labels, index=frame.index)


def cost_score(frame: pd.DataFrame, cfg: dict, cutoff: float | None = None,
               metric: str = "revised") -> dict:
    """Accuracy, the outcome mix, and the cost-weighted score."""
    if frame.empty:
        return {}
    weights = cfg["engines"]["propagation"]["origin_filter"]["cost_weights"]
    labels = outcomes(frame, cfg, cutoff, metric)
    counts = labels.value_counts()
    out = {"n": len(frame), "accuracy": round(float(frame["correct"].mean()), 3)}
    out.update({name: int(counts.get(name, 0)) for name in OUTCOMES})
    out["cost_weighted_score"] = round(
        float(sum(counts.get(name, 0) * weights[name] for name in OUTCOMES) / len(frame)), 3)
    return out


def filter_comparison(dataset: Dataset, cfg: dict, estimator: str | None = None) -> pd.DataFrame:
    """The filter off, the old combined filter, and the new split filter."""
    name = estimator or cfg["engines"]["propagation"]["estimator"]
    rows = []
    for mode in FILTER_MODES:
        result = score_estimator(dataset, name, cfg, mode)
        if not result.get("n"):
            continue
        frame = result["frame"]
        row = {"filter": mode, "top1": round(result["top1"], 3),
               "conditional_top1": round(result["conditional_top1"], 3)}
        row.update({k: v for k, v in cost_score(frame, cfg).items() if k != "accuracy"})
        row["anonymized_entry_points"] = int(frame["anonymized_entry_point"].sum())
        rows.append(row)
    return pd.DataFrame(rows)


def choose_cutoff(dataset: Dataset, cfg: dict, estimator: str | None = None,
                  mode: str = "split") -> tuple[float, pd.DataFrame]:
    """Pick `low_confidence_cutoff` on seed A, by the pre-registered rule.

    The value in {0.10, 0.15, ... 0.90} maximising the cost-weighted score;
    ties go to the lower cutoff, which abstains less.
    """
    name = estimator or cfg["engines"]["propagation"]["estimator"]
    return choose_cutoff_for(score_estimator(dataset, name, cfg, mode)["frame"], cfg)


def choose_cutoff_for(frame: pd.DataFrame, cfg: dict,
                      metric: str = "revised") -> tuple[float, pd.DataFrame]:
    """The same rule on any frame of estimates, whatever produced them.

    Split out so the supervised origination model's cutoff is chosen by this
    rule and these weights rather than by a copy of them.
    """
    rows = []
    for step in range(2, 19):
        cutoff = round(step * 0.05, 2)
        scored = cost_score(frame, cfg, cutoff, metric)
        rows.append({"cutoff": cutoff, "flagged": int(flagged_at(frame, cfg, cutoff).sum()),
                     **{k: scored[k] for k in ("abstained", "correct_actionable",
                                               "correct_infrastructure",
                                               "wrong_uninvolved_third_party",
                                               "cost_weighted_score")}})
    table = pd.DataFrame(rows)
    best = table["cost_weighted_score"].max()
    chosen = float(table[table["cost_weighted_score"] == best]["cutoff"].min())
    return chosen, table


def flag_quality(frame: pd.DataFrame, cfg: dict, cutoff: float | None = None) -> dict:
    """How well `low_confidence_origin` separates weak estimates from strong.

    `precision`/`recall` are against the event "the true origin was not in the
    observed tree at all" — the thing the flag's old name claimed. They are low
    because that event is rare; the accuracy split underneath is what the flag
    is actually for.
    """
    if frame.empty:
        return {}
    flagged = flagged_at(frame, cfg, cutoff)
    unobserved = ~frame["origin_observed"]
    tp = int((flagged & unobserved).sum())
    fp = int((flagged & ~unobserved).sum())
    fn = int((~flagged & unobserved).sum())
    tn = int((~flagged & ~unobserved).sum())
    return {"cutoff": cfg["engines"]["propagation"]["low_confidence_cutoff"]
            if cutoff is None else cutoff,
            "flagged": int(flagged.sum()), "of": len(frame),
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
        cap, unconditional, n_trees, n_all = ceiling_both(dataset)
        for name in ESTIMATORS:
            result = score_estimator(dataset, name, cfg)
            rows.append({"rate": rate, "estimator": name, "ceiling": cap,
                         "ceiling_unconditional": unconditional,
                         "multi_hop_txs": n_trees, "all_txs": n_all,
                         **{k: v for k, v in result.items() if k != "frame"}})
            if rate == cfg["eval"]["default_rate"]:
                extras[name] = result["frame"]
    return {"table": pd.DataFrame(rows), "frames": extras}


def rate_filter_cross(datasets: dict[float, Dataset], cfg: dict) -> pd.DataFrame:
    """Every estimator, at every observation rate, with the filter on and off.

    The main table fixes the filter at whatever is configured and varies the
    rate; `class_weight_ablation` fixes the rate and varies the filter. Neither
    answers whether the filter's value holds as observation gets sparser — which
    is the regime a real deployment is in — so this is the full cross, with
    top-3 alongside top-1 and the ceiling that bounds both.
    """
    rows = []
    for rate, dataset in sorted(datasets.items()):
        cap, _ = ceiling(dataset)
        for name in ESTIMATORS:
            for mode in FILTER_MODES:
                result = score_estimator(dataset, name, cfg, mode)
                if not result.get("n"):
                    continue
                rows.append({
                    "rate": rate, "estimator": name, "filter": mode,
                    "n": result["n"],
                    "top-1": round(result["top1"], 3),
                    "top-3": round(result["top3"], 3),
                    "top-1 given observed": round(result["conditional_top1"], 3),
                    "ceiling": round(cap, 3),
                    "share of ceiling": round(result["top1"] / cap, 3) if cap else None,
                })
    return pd.DataFrame(rows)


def class_weight_ablation(dataset: Dataset, cfg: dict) -> pd.DataFrame:
    """Every estimator under every filter configuration."""
    rows = []
    for name in ESTIMATORS:
        for mode in FILTER_MODES:
            result = score_estimator(dataset, name, cfg, mode)
            rows.append({"estimator": name, "filter": mode,
                         "top1": result.get("top1", 0.0),
                         "conditional_top1": result.get("conditional_top1", 0.0),
                         "cost_weighted_score": cost_score(result["frame"], cfg)
                         .get("cost_weighted_score") if result.get("n") else None})
    return pd.DataFrame(rows)
