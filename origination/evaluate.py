"""Split, fit, and score against the floor and the three estimators — on one split.

Every captured number here is `condition="simulated"` and is quoted beside
`corpus.OMISSIONS`. The scoring is not new: each method's per-transaction frame
goes through `eval.ground_truth.score.summarise`, so top-1, top-3, Wilson
intervals, abstention and the cost score come out of the same functions that
produce the rest of section 9.

THE SPLIT, AND WHICH NUMBER IS THE HONEST ONE
Captures are the unit: a transaction's rows never straddle two sets, and
neither do a capture's transactions (their peer histories are shared). Whole
topology configurations named in the manifest's `cross_topology_test` are held
out entirely — no graph drawn from them is seen in training or calibration. The
remaining captures are divided by a hash of their id into train, calibration
and a within-topology test set.

  within-topology   unseen captures, on topology configurations (and graphs)
                    the model trained on. Optimistic by construction.
  cross-topology    configurations the model never saw. The honest number.

Calibration and every abstention cutoff — the model's and each estimator's —
are chosen on the calibration captures by `eval.origin.choose_cutoff_for`.
Nothing is chosen on a test capture.
"""

from __future__ import annotations

import json
import os
from concurrent.futures import ProcessPoolExecutor

import pandas as pd

import config
from engines.propagation.estimators import ESTIMATORS
from eval import origin as origin_eval
from eval.ground_truth import score

from . import corpus
from .model import KEY, OriginationModel, abstains_by_construction, ece

MODEL = score.PENDING_MODEL       # the row it fills
ROLES = ("train", "calibration", "within_test", "cross_test")
TEST_SETS = {"within_test": "within-topology", "cross_test": "cross-topology"}


# --- the split ------------------------------------------------------------
def assign(captures: pd.DataFrame, manifest: dict) -> pd.Series:
    """capture_id -> role. Deterministic: a hash of the id, not a shuffle."""
    s = manifest["split"]
    roles = {}
    for row in captures.itertuples():
        if row.topology_split == "cross_test":
            roles[row.capture_id] = "cross_test"
            continue
        u = corpus._seed(manifest["seed"], "split", row.capture_id) / 16 ** 12
        roles[row.capture_id] = ("within_test" if u < s["within_test_share"] else
                                 "calibration" if u < s["within_test_share"]
                                 + s["calibration_share"] else "train")
    return pd.Series(roles, name="role")


def check_split(roles: pd.Series, captures: pd.DataFrame) -> dict:
    """The two leakage constraints, as a result rather than a hope.

    No capture in two roles (the index makes that structural; asserted anyway),
    and no topology configuration shared between what the model learnt from
    (train + calibration) and the cross-topology test set.
    """
    if roles.index.has_duplicates:
        raise AssertionError("a capture_id was assigned two roles")
    topo = captures.set_index("capture_id")["topology_id"]
    seen = set(topo[roles[roles.isin(["train", "calibration"])].index])
    cross = set(topo[roles[roles == "cross_test"].index])
    shared = seen & cross
    if shared:
        raise AssertionError(f"topology configurations in both training and the "
                             f"cross-topology test: {sorted(shared)}")
    return {"captures": roles.value_counts().reindex(ROLES, fill_value=0).to_dict(),
            "topologies_trained_on": len(seen), "topologies_held_out": len(cross),
            "shared_capture_ids": 0, "shared_topologies_train_vs_cross": 0}


# --- the baselines, on the same captures ----------------------------------
def _baseline_job(args) -> dict[str, pd.DataFrame]:
    """The floor and the three estimators on one capture, through
    `eval.ground_truth.score.score_estimator` unchanged, with the intel the
    capture was featurised with rebuilt from its spec."""
    spec, relay, truth, observers, cfg, coinjoins = args
    intel = corpus._intel(corpus.build_graph(spec, cfg), cfg)
    out = {}
    for name in (score.FIRST_SPY, *ESTIMATORS):
        frame = score.score_estimator(relay, truth, name, cfg, observers, intel,
                                      coinjoins)["frame"]
        out[name] = frame.assign(capture_id=spec["capture_id"])
    return out


def baselines(data: dict, capture_ids: list[str], cfg: dict,
              workers: int | None = None) -> dict[str, pd.DataFrame]:
    specs = data["captures"].set_index("capture_id")
    relay = dict(tuple(data["relay"].groupby("capture_id")))
    truth = {cid: dict(zip(g["txid"], g["origin_ip"]))
             for cid, g in data["truth"].groupby("capture_id")}
    mixes = coinjoins_of(data)
    jobs = [({**_plain(specs.loc[cid].to_dict()), "capture_id": cid}, relay[cid], truth[cid],
             set(specs.at[cid, "observers"].split(",")), cfg,
             {txid for c, txid in mixes if c == cid})
            for cid in capture_ids if cid in relay]
    workers = workers or min(len(jobs), os.cpu_count() or 1) or 1
    if workers > 1:
        with ProcessPoolExecutor(workers) as pool:
            results = list(pool.map(_baseline_job, jobs, chunksize=4))
    else:
        results = [_baseline_job(job) for job in jobs]
    return {name: pd.concat([r[name] for r in results], ignore_index=True)
            for name in (score.FIRST_SPY, *ESTIMATORS)}


def _plain(spec: dict) -> dict:
    """numpy scalars from parquet -> Python ones; `random.Random` refuses numpy ints."""
    return {k: v.item() if hasattr(v, "item") else v for k, v in spec.items()}


def with_cutoff(cfg: dict, cutoff: float) -> dict:
    """The config with `low_confidence_cutoff` replaced — how a cutoff chosen on
    the calibration captures reaches `eval.origin`'s unchanged machinery."""
    propagation = dict(cfg["engines"]["propagation"], low_confidence_cutoff=cutoff)
    return {**cfg, "engines": {**cfg["engines"], "propagation": propagation}}


# --- everything -----------------------------------------------------------
def run(cfg: dict | None = None, rebuild: bool = False, workers: int | None = None,
        manifest: dict | None = None) -> dict:
    cfg = cfg or config.load()
    manifest = manifest or corpus.load_manifest()
    directory = corpus.build(cfg, manifest, rebuild=rebuild, workers=workers)
    data = corpus.load(directory)
    captures, matrix = data["captures"], data["matrix"]
    roles = assign(captures, manifest)
    split = check_split(roles, captures)
    matrix_role = matrix["capture_id"].map(roles)
    part = {role: matrix[matrix_role == role] for role in ROLES}
    truth = data["truth"].set_index(KEY)["origin_ip"]
    shapes = shapes_of(data)

    model = OriginationModel.fit(part["train"], cfg)
    model.meta.update(corpus=directory.name, split=split)
    mixes = coinjoins_of(data)
    model.calibrate(part["calibration"], cfg, shapes, mixes)

    # Every estimator's cutoff is chosen the way the model's is: on the
    # calibration captures, by the same rule. The configured cutoff was chosen
    # on a different dataset, and using it here would hand the model an
    # in-distribution cutoff its competitors did not get.
    ids = {role: sorted(roles[roles == role].index) for role in ROLES}
    calibration = baselines(data, ids["calibration"], cfg, workers)
    cutoffs = {name: origin_eval.choose_cutoff_for(frame, cfg)[0]
               for name, frame in calibration.items() if name != score.FIRST_SPY}
    cutoffs[MODEL] = model.cutoff

    tables, reliability, frames = {}, {}, {}
    for role, label in TEST_SETS.items():
        rows = []
        tested = baselines(data, ids[role], cfg, workers)
        decided = label_coinjoins(model.decide(part[role], truth, cfg, shapes), mixes)
        n = len(decided)
        for name, frame in tested.items():
            if len(frame) != n:
                raise AssertionError(f"{name} scored {len(frame)} transactions on the "
                                     f"{label} set, the model {n}: not the same split")
            rows.append(_row(name, frame, cfg, cutoffs.get(name), label))
        rows.append(_row(MODEL, decided, cfg, model.cutoff, label))
        tables[role] = pd.DataFrame(rows)
        frames[role] = decided
        reliability[role] = _reliability(model, part[role], decided, cfg)

    best = _verdict(tables["cross_test"])
    return {"corpus": directory.name,
            "summary": _read_summary(directory),
            # for analysis.evaluate's with/without-validity comparison
            "decided": frames, "parts": part, "truth": truth, "shapes": shapes,
            "truth_frame": data["truth"],
            "baselines_cfg": cfg,
            "split": split, "cutoffs": cutoffs, "tables": tables,
            "reliability": reliability, "verdict": best,
            "examples": examples(model, part["cross_test"], frames["cross_test"]),
            "model": model, "omissions": corpus.OMISSIONS,
            "training": {"rows": model.meta["rows"], "positives": model.meta["positives"],
                         "features": len(model.meta["features"])}}


def _row(name: str, frame: pd.DataFrame, cfg: dict, cutoff: float | None,
         label: str) -> dict:
    abstains = name != score.FIRST_SPY
    scoring = with_cutoff(cfg, cutoff) if abstains else cfg
    row = score.summarise(name, frame, scoring, abstains=abstains)
    return {"condition": "simulated", "test set": label, **row,
            "cutoff (chosen on calibration)": cutoff if abstains else None}


def _reliability(model: OriginationModel, matrix: pd.DataFrame, decided: pd.DataFrame,
                 cfg: dict) -> dict:
    bins = cfg["origination"]["ece_bins"]
    scored = model.score(matrix)
    live = ~abstains_by_construction(matrix)
    y = matrix.loc[live, "originated"]
    answered = decided[decided["abstain_reason"].isna()]
    return {"condition": "simulated",
            "rows scored": int(live.sum()),
            "ECE per candidate, raw": ece(scored.loc[live, "p_raw"], y, bins),
            "ECE per candidate, calibrated": ece(scored.loc[live, "p_calibrated"], y, bins),
            "transactions scored": len(answered),
            "ECE top candidate, calibrated": ece(answered["confidence"],
                                                 answered["correct"], bins),
            "bins": bins}


def _verdict(table: pd.DataFrame) -> dict:
    """Does the fusion earn its place on the cross-topology set? Stated either way."""
    estimators = table[table["estimator"].isin(list(ESTIMATORS))]
    best = estimators.sort_values("cost_weighted_score", ascending=False).iloc[0]
    mine = table[table["estimator"] == MODEL].iloc[0]
    return {"best_estimator": best["estimator"],
            "best_estimator_cost": best["cost_weighted_score"],
            "best_estimator_acc_if_answered": best["acc if answered"],
            "model_cost": mine["cost_weighted_score"],
            "model_acc_if_answered": mine["acc if answered"],
            "earns_its_place": bool(mine["cost_weighted_score"] > best["cost_weighted_score"])}


def examples(model: OriginationModel, matrix: pd.DataFrame, decided: pd.DataFrame,
             per_kind: int = 2) -> pd.DataFrame:
    """A few top-candidate explanations from the cross-topology set: answered
    and right, answered and wrong, and each way of abstaining by construction. Chosen by
    sorted key, not by how good the sentence reads."""
    kinds = {
        "answered, correct": decided[decided["abstain_reason"].isna()
                                     & (decided["confidence"] >= model.cutoff)
                                     & decided["correct"]],
        "answered, wrong": decided[decided["abstain_reason"].isna()
                                   & (decided["confidence"] >= model.cutoff)
                                   & ~decided["correct"]],
        "abstained: degenerate": decided[decided["abstain_reason"] == "degenerate"],
        "abstained: scope_out": decided[decided["abstain_reason"] == "scope_out"],
    }
    rows = []
    indexed = matrix.set_index(KEY + ["peer_ip"], drop=False)
    for kind, frame in kinds.items():
        for r in frame.sort_values(KEY).head(per_kind).itertuples():
            row = indexed.loc[[(r.capture_id, r.txid, r.estimated_origin_ip)]]
            text = model.explain(row.reset_index(drop=True))["explanation"].iloc[0]
            rows.append({"condition": "simulated", "case": kind, "capture_id": r.capture_id,
                         "txid": r.txid[:12],
                         "explanation": text})
    return pd.DataFrame(rows)


def coinjoins_of(data: dict) -> set[tuple[str, str]]:
    """(capture_id, txid) of every true CoinJoin — ground truth, read only to
    score `coinjoin_input_misattribution`, never by a detector or the model."""
    truth = data["truth"]
    if "shape" not in truth:
        return set()
    mixes = truth[truth["shape"] == "coinjoin"]
    return set(zip(mixes["capture_id"], mixes["txid"]))


def label_coinjoins(frame: pd.DataFrame, mixes: set) -> pd.DataFrame:
    return frame.assign(coinjoin_truth=[k in mixes for k in
                                        zip(frame["capture_id"], frame["txid"])])


def shapes_of(data: dict) -> pd.DataFrame | None:
    """Transaction structure, where the corpus has it (the validity variant)."""
    truth = data["truth"]
    return truth if "in_addrs" in truth else None


def _read_summary(directory) -> dict:
    return json.loads((directory / "summary.json").read_text())
