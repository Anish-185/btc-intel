"""Origin accuracy against known truth, per topology condition.

Reuses rather than reimplements. The three estimators come from
`engines.propagation.estimators` unchanged; the trees come from
`engines.propagation.tree.build_trees`; the abstention rule, the outcome classes
and the pre-registered cost weights come from `eval.origin`, which already
implements `docs/detection_unit_protocol.md`. What is new here is only what real
data forces: a first-spy floor to compare against, Wilson intervals because the
sample is a few dozen transactions rather than a thousand, the relay-delay noise
floor, and the fact that a single observer sees a star rather than a tree.

THE STAR PROBLEM, STATED BEFORE ANY NUMBER
One observer's capture yields one edge per announcement — peer to observer — so
the "propagation tree" is a star centred on us. Rumor centrality maximises over
tree position, and in a star every leaf is identical, so once the observer is
excluded as a candidate (it cannot be the origin of its own observations) that
estimator has nothing to rank on and falls back to breaking ties by address.
That is not a defect in Shah & Zaman: it is what their estimator does when the
observed topology carries no positional information. Only timing does, here,
which is exactly why the noise floor below is the number that bounds this
condition. A multi-observer capture would restore the topology; a simulated run
already has it, and that difference is why the simulated row is **not** a
substitute for the signet rows.
"""

from __future__ import annotations

import math

import pandas as pd

import config
from engines.propagation.estimators import (ESTIMATORS, apply_class_weights,
                                            attribution_confidence_of, confidence_of,
                                            is_anonymized_entry, low_confidence_origin)
from engines.propagation.tree import build_trees, degraded_mode
# The capture -> relay-record conversion is a feature-stage concern and lives
# there; importing it keeps one definition rather than two that can drift.
from features.relay import ANNOUNCEMENTS, relay_frame
from ingest.ip_intel import load_intel

from .. import origin

#: The baseline row, then the three estimators, then the row P5 will fill.
FIRST_SPY = "first_spy_baseline"
PENDING_MODEL = "supervised_origination (P5)"

# --- statistics -----------------------------------------------------------
def wilson(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval for a proportion.

    Not the normal approximation: at n = 50 and p near 1 the normal interval
    runs past 1.0 and reports an impossible bound, which on a table of
    fifty-transaction runs would be most of the rows.
    """
    if n <= 0:
        return (0.0, 0.0)
    p = successes / n
    denominator = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denominator
    half = (z / denominator) * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4))


def _ci(successes: int, n: int, cfg: dict) -> str:
    lo, hi = wilson(successes, n, cfg["eval"]["ground_truth"]["wilson_z"])
    return f"{lo:.3f}–{hi:.3f}"


# --- the capture, as the relay records the estimators already read --------
def rank(tree, intel, cfg: dict, estimator: str, exclude: set[str]) -> list[tuple[str, float]]:
    """Ranked candidates for one transaction, with `exclude` removed.

    Uses the estimator and the class weighting `estimate_all` uses; the only
    difference is that the observer is struck from the candidate list, which
    `estimate_all` has no reason to do on a dump whose observer is not a node.
    """
    if estimator == FIRST_SPY:
        ordered = sorted(((ip, -tree.first_seen[ip]) for ip in tree.first_seen
                          if ip not in exclude), key=lambda kv: (-kv[1], kv[0]))
        # The floor: earliest sighting wins, no class weighting, no abstention.
        return [(ip, 1.0 - i / max(len(ordered), 1)) for i, (ip, _) in enumerate(ordered)]
    scores = ESTIMATORS[estimator](tree, cfg)
    weighted, _ = apply_class_weights(scores, tree, intel, cfg)
    return sorted(((ip, s) for ip, s in weighted.items() if ip not in exclude),
                  key=lambda kv: (-kv[1], kv[0]))


def score_estimator(frame: pd.DataFrame, truth: dict[str, str], estimator: str,
                    cfg: dict, exclude: set[str], intel=None) -> dict:
    """One estimator over one condition's capture.

    Produces the same columns `eval.origin`'s cost and flag machinery reads, so
    abstention, the outcome classes and the cost weights are the existing ones
    rather than a second implementation that could drift from them.
    """
    cfg = cfg or config.load()
    intel = intel if intel is not None else load_intel(None, None, cfg)
    trees = build_trees(frame)
    runner_ups = cfg["engines"]["propagation"]["runner_ups"]
    rows = []
    for txid, tree in trees.items():
        if txid not in truth:
            continue                      # observed, but not one of ours
        ranked = rank(tree, intel, cfg, estimator, exclude)
        if not ranked:
            continue
        best = ranked[0][0]
        ip_class = intel.classify(best, None).ip_class
        confidence = confidence_of(ranked, tree.n_observations)
        anonymized = is_anonymized_entry(ip_class, cfg)
        rows.append({
            "txid": txid, "estimated_origin_ip": best, "ip_class": ip_class,
            "confidence": confidence,
            "attribution_confidence": attribution_confidence_of(confidence, anonymized, cfg),
            "anonymized_entry_point": anonymized,
            "low_confidence_origin": low_confidence_origin(ip_class, confidence, cfg),
            "n_observations": tree.n_observations,
            "n_candidates": len(ranked),
            "correct": best == truth[txid],
            "top3": truth[txid] in [ip for ip, _ in ranked[:1 + runner_ups]],
            "origin_observed": truth[txid] in tree.ips,
        })
    return {"estimator": estimator, "frame": pd.DataFrame(rows)}


def without_abstention(cfg: dict) -> dict:
    """The same config with the abstention rule switched off.

    Used for the floor row only, and done by overriding the two config values
    `eval.origin`'s existing machinery reads rather than by writing a second
    outcome classifier that could drift from it.
    """
    propagation = dict(cfg["engines"]["propagation"],
                       low_confidence_classes=[], low_confidence_cutoff=0.0)
    return {**cfg, "engines": {**cfg["engines"], "propagation": propagation}}


def summarise(estimator: str, frame: pd.DataFrame, cfg: dict,
              abstains: bool = True) -> dict:
    """One table row: accuracy with its interval, abstention, and the cost score.

    The floor does not abstain. Scored under the shared rule it would post a
    100% abstention rate and a cost-weighted score of zero — an artifact of
    confidence being the winner's share of an unweighted score vector, not a
    property of first-spy, and reporting it as the baseline's behaviour would
    make the floor look cautious when it is the opposite.
    """
    n = len(frame)
    if n == 0:
        return {"estimator": estimator, "n": 0}
    scoring_cfg = cfg if abstains else without_abstention(cfg)
    correct = int(frame["correct"].sum())
    top3 = int(frame["top3"].sum())
    flagged = origin.flagged_at(frame, scoring_cfg)
    kept = frame[~flagged]
    kept_correct = int(kept["correct"].sum())
    cost = origin.cost_score(frame, scoring_cfg)
    observed = int(frame["origin_observed"].sum())
    return {
        "estimator": estimator, "n": str(n),
        "top1": round(correct / n, 3), "top1 95% CI": _ci(correct, n, cfg),
        "top3": round(top3 / n, 3), "top3 95% CI": _ci(top3, n, cfg),
        "abstention rate": round(int(flagged.sum()) / n, 3) if abstains else None,
        "acc if answered": round(kept_correct / len(kept), 3) if len(kept) else None,
        "acc if answered 95% CI": (
            _ci(kept_correct, len(kept), cfg) if abstains and len(kept)
            else "n/a — the floor never abstains" if not abstains else "n/a"),
        "ceiling (origin observed)": round(observed / n, 3),
        "cost_weighted_score": cost.get("cost_weighted_score"),
        "wrong_uninvolved_third_party": cost.get("wrong_uninvolved_third_party"),
    }


def pending_row(reason: str = "not yet implemented — see docs/REFRAME_PLAN.md step 3") -> dict:
    """The reserved row for the supervised model, held open and marked."""
    return {"estimator": PENDING_MODEL, "n": "n/a", "top1": None, "top1 95% CI": "PENDING",
            "top3": None, "top3 95% CI": "PENDING", "abstention rate": None,
            "acc if answered": None, "acc if answered 95% CI": reason,
            "ceiling (origin observed)": None, "cost_weighted_score": None,
            "wrong_uninvolved_third_party": None}


def corpus_row() -> dict:
    """Row 5 of the canonical simulated table, which the model cannot fill.

    That dataset is NTRO-shaped hop records sampled at many relays, not one
    observer's capture, so there is no relay matrix to score. The model is
    measured on `origination`'s capture corpus instead, beside these same four
    baselines on the same split, and this row says where.
    """
    note = "see the capture-corpus tables below"
    return {"estimator": PENDING_MODEL, "n": "n/a", "top1": None, "top1 95% CI": note,
            "top3": None, "top3 95% CI": note, "abstention rate": None,
            "acc if answered": None,
            "acc if answered 95% CI": ("not applicable: hop records seen at many relays "
                                       "are not a single-vantage capture, so this dataset "
                                       "has no relay matrix to score"),
            "ceiling (origin observed)": None, "cost_weighted_score": None,
            "wrong_uninvolved_third_party": None}


# --- the relay-delay noise floor -----------------------------------------
def noise_floor(frame: pd.DataFrame, truth: dict[str, str], cfg: dict) -> dict:
    """How far apart announcements of the same transaction actually arrive.

    A timing estimator can only separate two peers if their announcements are
    further apart than the capture can resolve. So this measures the observed
    distribution of inter-peer deltas per transaction, and then the share of
    transactions where the true origin announced *first and by more than the
    clock resolution* — which is the ceiling any purely timing-based estimator
    is bounded by on this topology, independent of how clever it is.
    """
    g = cfg["eval"]["ground_truth"]
    resolution = float(g["clock_resolution_seconds"])
    deltas: list[float] = []
    separable = first = multi = 0
    for txid, group in frame.groupby("txid", sort=False):
        times = group.groupby("src_ip")["timestamp"].min().sort_values()
        if len(times) < 2:
            continue
        multi += 1
        seconds = [t.timestamp() for t in times]
        deltas.extend(b - a for a, b in zip(seconds, seconds[1:]))
        if txid in truth:
            earliest_ip = times.index[0]
            if earliest_ip == truth[txid]:
                first += 1
                if seconds[1] - seconds[0] > resolution:
                    separable += 1
    series = pd.Series(deltas, dtype=float)
    out = {
        "transactions with 2+ announcing peers": multi,
        "inter-peer deltas measured": len(deltas),
        "mean delta (s)": round(float(series.mean()), 6) if len(series) else None,
        "clock resolution (s)": resolution,
        "origin announced first": first,
        "origin first and separable": separable,
        "timing ceiling": round(separable / multi, 3) if multi else None,
    }
    for percentile in g["delta_percentiles"]:
        out[f"p{percentile} delta (s)"] = (round(float(series.quantile(percentile / 100)), 6)
                                           if len(series) else None)
    return out


# --- a whole condition ---------------------------------------------------
def score_condition(frame: pd.DataFrame, truth: dict[str, str], condition: str,
                    cfg: dict, exclude: set[str] | None = None,
                    intel=None, model_row: dict | None = None) -> dict:
    """Every row of one condition's table, plus its noise floor."""
    cfg = cfg or config.load()
    exclude = exclude or set()
    rows, frames = [], {}
    for estimator in (FIRST_SPY, *ESTIMATORS):
        result = score_estimator(frame, truth, estimator, cfg, exclude, intel)
        frames[estimator] = result["frame"]
        rows.append(summarise(estimator, result["frame"], cfg,
                              abstains=estimator != FIRST_SPY))
    rows.append(model_row or pending_row())
    return {
        "condition": condition,
        "table": pd.DataFrame(rows),
        "noise_floor": noise_floor(frame, truth, cfg),
        "degraded": degraded_mode(frame),
        "transactions_scored": int(len(frames[FIRST_SPY])),
        "frames": frames,
    }


# --- the simulated condition ---------------------------------------------
def simulated(cfg: dict, rebuild: bool = False) -> dict:
    """The same measurement over generator/'s 500-node gossip simulation.

    Deterministic (seed and sizes from `config.yaml`'s `eval:` block), always
    available, and labelled `simulated` so it can never be read as a signet
    result. It is not a stand-in for one either: the simulation is observed at
    many relays, so its trees have the positional structure a single-observer
    signet capture does not.
    """
    from ..datasets import build

    dataset = build(cfg=cfg, rebuild=rebuild)
    frame = dataset.frame()
    truth = origin.truth_of(dataset)
    intel = load_intel(None, dataset.raw, cfg)
    result = score_condition(frame, truth, "simulated", cfg, set(), intel, corpus_row())
    result["source"] = "simulated"
    result["describes"] = dataset.describe()
    return result


# --- signet conditions, read from sealed fixtures ------------------------
def signet_conditions(cfg: dict) -> dict:
    """Score whatever sealed signet captures are present; PENDING when none.

    A bundle is a directory holding capture files, `manifest.json` and one
    `*.labels.json`. The manifest is verified before anything is read — an
    unverified capture is not evidence — and preflight runs before anything is
    scored.
    """
    from pathlib import Path

    from p2p.capture_reader import read_directory
    from p2p.manifest import verify_capture

    from .broadcast import load_labels, resolve_from_labels, truth_of
    from .preflight import PreflightError, check

    root = Path(cfg["eval"]["ground_truth"]["fixtures_dir"])
    out: dict[str, dict] = {}
    if not root.is_dir():
        return out
    for bundle in sorted(p for p in root.iterdir() if p.is_dir()):
        labels_files = sorted(bundle.glob("*.labels.json"))
        if not labels_files:
            continue
        labels = load_labels(labels_files[0])
        if labels.get("source") != "signet":
            # The test fixtures live here too, and they are not signet captures.
            # A bundle only becomes a signet row by saying so in its label file,
            # so a fixture can never be published as a measurement of Bitcoin.
            out.setdefault("_skipped", {"bundles": []})["bundles"].append(
                {"bundle": bundle.name, "source": labels.get("source")})
            continue
        condition = labels.get("topology_condition", "unlabelled")
        entry: dict = {"bundle": bundle.name, "source": labels.get("source"),
                       "condition": condition}
        entry["manifest"] = verify_capture(bundle, cfg=cfg, record=False)
        if not entry["manifest"]["ok"]:
            entry["status"] = "REJECTED — manifest did not verify"
            out[condition] = entry
            continue
        events = read_directory(bundle, cfg=cfg,
                                local_ips=labels.get("observer_local_ips") or None)
        entry["wtxid_resolution"] = resolve_from_labels(events, labels)
        local = set(labels.get("observer_local_ips") or [])
        try:
            entry["preflight"] = check(events, labels, local, cfg, entry["wtxid_resolution"])
        except PreflightError as exc:
            entry["status"] = "REJECTED by preflight"
            entry["failures"] = exc.failures
            out[condition] = entry
            continue
        observer = sorted(local)[0]
        frame = relay_frame(events, observer)
        entry.update(score_condition(frame, truth_of(labels), condition, cfg, local))
        entry["status"] = "scored"
        out[condition] = entry
    return out


def relay_features(cfg: dict) -> pd.DataFrame:
    """The relay feature matrix's size and its three proportions, per bundle.

    Reported beside the origin table because it is the same evidence counted a
    different way: `degenerate` and `scope_out` are the rows a supervised model
    must abstain on rather than learn from, and the quarantine share is how much
    of the capture could not be keyed to a txid at all. The source column is
    carried so a fixture-derived row can never be read as a signet one.
    """
    from pathlib import Path

    from features.relay import build, summarise

    from .broadcast import load_labels

    root = Path(cfg["eval"]["ground_truth"]["fixtures_dir"])
    rows = []
    if not root.is_dir():
        return pd.DataFrame()
    for bundle in sorted(p for p in root.iterdir() if p.is_dir()):
        found = sorted(bundle.glob("*.labels.json"))
        if not found:
            continue
        labels = load_labels(found[0])
        try:
            features, quarantine, _ = build(bundle, cfg=cfg)
        except Exception as exc:                  # a bundle that cannot be featurised
            rows.append({"capture_id": bundle.name, "source": labels.get("source"),
                         "condition": labels.get("topology_condition"),
                         "rows": None, "note": f"{type(exc).__name__}: {exc}"})
            continue
        rows.append({"capture_id": bundle.name, "source": labels.get("source"),
                     "condition": labels.get("topology_condition"),
                     **summarise(features, quarantine)})
    return pd.DataFrame(rows)


def evaluate(cfg: dict, rebuild: bool = False) -> dict:
    """Everything section 9 of the report needs."""
    conditions = signet_conditions(cfg)
    skipped = conditions.pop("_skipped", {"bundles": []})
    return {
        "signet": conditions,
        "skipped_bundles": skipped["bundles"],
        "relay_features": relay_features(cfg),
        "simulated": simulated(cfg, rebuild),
        # The first line of the section says this outright: a run with no signet
        # bundle is a simulated run, and must never be read as anything else.
        "data_source": ("signet + simulated" if conditions else "simulated only"),
        "pending": [c for c in ("adjacent", "non_adjacent") if c not in conditions],
    }
