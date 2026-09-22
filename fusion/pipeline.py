"""End-to-end: every engine, then fusion, then one ranked explained alert list.

    python -m fusion.pipeline

Reads the processed transactions, runs rules / anomaly / GNN / correlation /
taint, stacks the five signals into one composite score per entity, explains
everything above the threshold, and writes final_alerts.parquet (+ .json, which
is what the API serves).

The GNN is optional: without torch installed, or without a trained model, its
signal is simply absent and the other four still stack. That is deliberate —
the labelled engine is the one least likely to survive contact with real data.
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

import pandas as pd

import config
from engines.anomaly.detector import fit_score
from engines.correlation.scorer import correlate
from engines.propagation.estimators import estimate_all, is_anonymized_entry
from engines.propagation.tree import degraded_mode
from engines.rules.detectors import FeatureSet, run_all
from engines.rules.schema import alerts_to_frame
from graph.builder import build_graph, load
from graph.entity_graph import build_entity_graph
from ingest.ip_intel import load_intel

from .explain import explain_entity
from .stacker import SIGNALS, Stacker, default_weights, save, train
from .taint import compute_taint, load_watchlist

log = logging.getLogger(__name__)

# One alert per entity, so the entity id IS the alert id — the API takes either.
ALERT_COLUMNS = ["alert_id", "entity_id", "entity_type", "pattern_types", "risk_score",
                 "reason", "evidence", "top_signal", "rule_score", "anomaly_score",
                 "gnn_score", "taint_score", "taint_path", "leads", "contributions",
                 "wallets", "suspicious_merge"]


def gnn_scores(df: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    """Best-effort: torch is an optional extra and the model may not be trained."""
    try:
        from engines.gnn.data import build_dataset
        from engines.gnn.infer import load_model, score
    except ImportError:
        log.info("torch not installed — GNN signal omitted")
        return pd.DataFrame(columns=["entity_id", "gnn_score"])
    model_path = Path(cfg["models"]["gnn"])
    if not model_path.exists():
        log.info("no trained GNN at %s — GNN signal omitted", model_path)
        return pd.DataFrame(columns=["entity_id", "gnn_score"])
    try:
        model, artefacts = load_model(model_path, cfg)
        scored = score(build_dataset(build_graph(df, cfg), cfg=cfg), model, artefacts, cfg)
    except Exception as exc:                       # a stale model must not kill the run
        log.warning("GNN scoring failed (%s) — signal omitted", exc)
        return pd.DataFrame(columns=["entity_id", "gnn_score"])
    entities = scored[scored["level"] == "entity"]
    return entities.rename(columns={"id": "entity_id"})[["entity_id", "gnn_score"]]


def collect_signals(df: pd.DataFrame, cfg: dict, watchlist_path=None) -> dict:
    """Run every engine and assemble one row per entity."""
    graph = build_graph(df, cfg)
    features = FeatureSet.from_graph(graph, cfg)
    intel = load_intel(None, cfg["ingest"]["input_dir"], cfg)
    origins, propagation_status = estimate_all(df, intel, cfg)

    alerts = alerts_to_frame(run_all(graph, features, cfg))
    rule_score = (alerts.groupby("entity_id")["score"].max().rename("rule_score")
                  if len(alerts) else pd.Series(dtype=float, name="rule_score"))

    anomaly = fit_score(features.entities, cfg).rename(columns={"entity_id": "entity_id"})
    # Attribution leads, kept OUT of the risk score: an IP correlation says
    # something about who, not about whether the entity is risky.
    links = correlate(df, features, cfg, origins, intel)

    entity_graph = build_entity_graph(graph, features.clustering, cfg)
    watchlist = load_watchlist(watchlist_path, cfg)
    taint = compute_taint(entity_graph, watchlist, features.entity_of, cfg=cfg)
    seed_entities = set(taint[taint["taint_hops"] == 0]["entity_id"]) if len(taint) else set()

    signals = features.entities.rename(columns={"cluster_id": "entity_id"}).copy()
    signals = signals.merge(rule_score, on="entity_id", how="left")
    signals = signals.merge(anomaly[["entity_id", "anomaly_score"]], on="entity_id", how="left")
    signals = signals.merge(gnn_scores(df, cfg), on="entity_id", how="left")
    signals = signals.merge(taint[["entity_id", "taint_score", "taint_path"]],
                            on="entity_id", how="left")
    for column in SIGNALS:
        if column not in signals:
            signals[column] = 0.0
        signals[column] = signals[column].fillna(0.0)
    signals["taint_path"] = signals["taint_path"].apply(lambda v: v if isinstance(v, list) else [])
    return {"signals": signals, "alerts": alerts, "links": links, "features": features,
            "graph": graph, "entity_graph": entity_graph, "origins": origins,
            "propagation": propagation_status, "watchlist": watchlist,
            "taint": taint, "seed_entities": seed_entities}


def labels_for(signals: pd.DataFrame, ground_truth: dict, features: FeatureSet,
               cfg: dict) -> pd.Series:
    """1 if any wallet in the entity belongs to an illicit cluster."""
    illicit_patterns = {"ransomware_collector", "layering", "cashout"}
    bad_entities = set()
    for cluster in ground_truth.get("clusters", {}).values():
        if cluster["pattern_type"] in illicit_patterns:
            for wallet in cluster["wallets"]:
                bad_entities.add(features.entity_of(wallet))
    return signals["entity_id"].isin(bad_entities).astype(int)


def attribution_leads(links: pd.DataFrame, cfg: dict) -> dict[str, list[dict]]:
    """Top-k IP leads per entity — shown beside an alert, never inside its score.

    Ranked and cut at k rather than filtered by a score floor: the old floor was
    calibrated against a scale that no longer exists once each observation is
    weighted by its origin-estimate confidence.
    """
    if links is None or links.empty:
        return {}
    k = cfg["fusion"]["leads_per_entity"]
    ranked = links.sort_values("final_score", ascending=False)
    out: dict[str, list[dict]] = {}
    for row in ranked.itertuples():
        bucket = out.setdefault(row.entity_id, [])
        if len(bucket) < k:
            anonymized = is_anonymized_entry(str(row.ip_class), cfg)
            bucket.append({"ip": str(row.ip), "ip_class": str(row.ip_class),
                           "confidence": round(float(row.final_score), 4),
                           "observations": int(row.observation_count),
                           # A Tor exit or hosting address is where the
                           # broadcast entered the network, not who sent it —
                           # said in the lead itself so nobody reads it as an
                           # attribution.
                           "anonymized_entry_point": anonymized,
                           "label": ("anonymized entry point" if anonymized
                                     else "candidate origin"),
                           "evidence": str(row.reason)})
    return out


def build_alerts(bundle: dict, stacker: Stacker, cfg: dict) -> pd.DataFrame:
    signals = bundle["signals"].copy()
    signals["risk_score"] = stacker.score(signals)
    threshold = cfg["fusion"]["alert_threshold"]
    flagged = signals[signals["risk_score"] >= threshold]
    baseline = signals[stacker.signals].astype(float).mean()

    reasons_by_entity: dict[str, list[str]] = {}
    evidence_by_entity: dict[str, list[str]] = {}
    patterns_by_entity: dict[str, list[str]] = {}
    for row in bundle["alerts"].itertuples():
        reasons_by_entity.setdefault(row.entity_id, []).append(row.reason)
        evidence_by_entity.setdefault(row.entity_id, []).extend(list(row.evidence)[:8])
        patterns_by_entity.setdefault(row.entity_id, []).append(row.rule_name)
    leads_by_entity = attribution_leads(bundle["links"], cfg)

    clusters = bundle["features"].clustering.clusters
    rows = []
    for _, row in flagged.iterrows():
        entity = str(row["entity_id"])
        leads = leads_by_entity.get(entity, [])
        evidence = list(evidence_by_entity.get(entity, []))
        evidence += sorted(clusters.get(entity, {entity}))[:5]
        evidence += [lead["ip"] for lead in leads]
        explanation = explain_entity(row, stacker, baseline,
                                     reasons_by_entity.get(entity, []), evidence,
                                     None, list(row.get("taint_path") or []), cfg)
        members = clusters.get(entity, {entity})
        rows.append({
            "alert_id": entity, "entity_id": entity,
            # A coarse type, because that is all an offline pipeline can honestly
            # say: several wallets provably co-owned, or a lone address. Service
            # labels (exchange, mixer) need attribution data we do not have.
            "entity_type": "cluster" if len(members) > 1 else "wallet",
            "pattern_types": sorted(set(patterns_by_entity.get(entity, []))),
            "taint_path": list(row.get("taint_path") or []),
            "risk_score": explanation.score,
            "reason": explanation.reason, "evidence": explanation.evidence,
            "top_signal": explanation.top_signal,
            **{s: float(row.get(s, 0.0) or 0.0) for s in SIGNALS},
            "leads": json.dumps(leads),
            "contributions": json.dumps(explanation.contributions),
            "wallets": len(members),
            "suspicious_merge": bool(row.get("suspicious_merge", False)),
        })
    df = pd.DataFrame(rows, columns=ALERT_COLUMNS)
    return df.sort_values("risk_score", ascending=False, ignore_index=True)


def run(input_path=None, ground_truth=None, out_parquet=None, out_json=None,
        cfg: dict | None = None, watchlist_path=None) -> dict:
    cfg = cfg or config.load()
    f = cfg["fusion"]
    df = load(input_path, cfg)
    bundle = collect_signals(df, cfg, watchlist_path)

    gt_path = Path(ground_truth) if ground_truth else Path(cfg["ingest"]["input_dir"]) / "ground_truth.json"
    if gt_path.exists():
        gt = json.loads(gt_path.read_text())
        labels = labels_for(bundle["signals"], gt, bundle["features"], cfg)
        stacker = train(bundle["signals"], labels, cfg)
        save(stacker, f["model_path"])
    else:
        log.warning("no ground truth at %s — stacking with config risk_weights instead "
                    "of a fitted model", gt_path)
        stacker = Stacker(fallback_weights=default_weights(cfg),
                          metrics={"fitted": False, "reason": "no labels available"})

    alerts = build_alerts(bundle, stacker, cfg)
    parquet = Path(out_parquet or f["alerts_parquet"])
    js = Path(out_json or f["alerts_json"])
    parquet.parent.mkdir(parents=True, exist_ok=True)
    alerts.to_parquet(parquet, index=False)
    payload = {
        "generated_from": str(input_path or cfg["ingest"]["output_path"]),
        "alert_threshold": f["alert_threshold"],
        "stacker": stacker.metrics,
        "degraded_mode": bundle["propagation"],
        "alerts": json.loads(alerts.to_json(orient="records")),
    }
    js.write_text(json.dumps(payload, indent=2))
    return {"entities": len(bundle["signals"]), "alerts": len(alerts),
            "rule_alerts": len(bundle["alerts"]),
            "watchlist_seeds": len(bundle["seed_entities"]),
            "tainted": int((bundle["signals"]["taint_score"] > 0).sum()),
            "stacker": stacker.metrics, "degraded_mode": bundle["propagation"]["degraded"],
            "parquet": str(parquet), "json": str(js)}


def main(argv=None) -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    cfg = config.load()
    ap = argparse.ArgumentParser(prog="fusion.pipeline", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", default=cfg["ingest"]["output_path"])
    ap.add_argument("--ground-truth",
                    default=str(Path(cfg["ingest"]["input_dir"]) / "ground_truth.json"))
    ap.add_argument("--parquet", default=cfg["fusion"]["alerts_parquet"])
    ap.add_argument("--json", dest="js", default=cfg["fusion"]["alerts_json"])
    ap.add_argument("--watchlist", default=None,
                    help="analyst known-bad list; defaults to the dataset's, then data/intel/")
    args = ap.parse_args(argv)
    print(json.dumps(run(args.input, args.ground_truth, args.parquet, args.js,
                         watchlist_path=args.watchlist), indent=2))


if __name__ == "__main__":
    main()
