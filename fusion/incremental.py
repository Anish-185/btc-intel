"""Re-run the stack over newly arrived transactions only.

Red-team mode plants a pattern into a dataset the detectors have already been
run over, and the question is whether they catch it. Re-running everything from
the parquet would answer that in a few seconds on the demo dataset and in
minutes on a real one, with a judge watching — so the stages that scale with
the size of the dataset run over the new transactions alone, and the state the
API already holds in memory is extended rather than rebuilt.

**What is skipped, and what is not.** Two stages read only the new
transactions, because they are per-transaction and they are the two that
dominate as a dataset grows:

  * *graph construction* — the new transactions are appended to the graph the
    API already holds, instead of rebuilding it from the parquet.
  * *origin estimation* — a propagation tree belongs to one transaction, so
    estimating the new ones changes nothing about the old ones.

Everything else is recomputed over the whole dataset, on purpose:

  * *clustering and features* — the change-address heuristics read the whole
    transaction history, so clustering a few new transactions in isolation can
    reach a different answer from clustering them in context. It did, and
    `test_incremental_matches_a_full_rerun` caught it. Both stages cost
    milliseconds; being wrong quickly is not a trade worth making.
  * *rules* — cheap, and a detector that only ever looks at new subgraphs
    would miss a pattern that only completes when new transactions join old
    ones.
  * *anomaly* — IsolationForest is fitted per peer group and min-max scaled
    inside it, so every score in a group moves when the group gains a member.
  * *correlation* — an IP's weight depends on how many entities share it,
    which is a global count.

**What is never retrained.** The GNN and the stacker are loaded and used for
inference. A red-team run measures the detector that exists, not one refitted
around the attack it is being asked to find.

The injected structure is disjoint from the existing graph by construction —
`generator.inject.inject_pattern` mints fresh wallets and fresh counterparties
— so extending the clustering and the feature table is a merge, not a
recomputation. `tests/test_redteam.py` checks the result against a full re-run
rather than taking that on trust.
"""

from __future__ import annotations

import logging
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

import networkx as nx
import pandas as pd

import config
from engines.anomaly.detector import fit_score
from engines.correlation.scorer import correlate
from engines.propagation.estimators import estimate_all
from engines.rules.detectors import FeatureSet, run_all
from engines.rules.schema import alerts_to_frame
from features.engineer import compute_all
from graph.builder import build_graph, graph_transactions
from graph.clustering import cluster_wallets
from graph.entity_graph import build_entity_graph
from ingest.ip_intel import load_intel

from .pipeline import build_alerts, gnn_scores
from .stacker import SIGNALS, Stacker, default_weights
from .taint import compute_taint, load_watchlist

log = logging.getLogger(__name__)


@dataclass
class Timing:
    """How long each stage took — the thing the performance doc is made of."""

    stages: list[tuple[str, float]] = field(default_factory=list)
    on_stage: Callable[[str, float], None] | None = None

    @contextmanager
    def stage(self, name: str):
        start = time.perf_counter()
        yield
        seconds = time.perf_counter() - start
        self.stages.append((name, seconds))
        if self.on_stage:
            self.on_stage(name, seconds)

    @property
    def total(self) -> float:
        return sum(seconds for _, seconds in self.stages)

    def as_dict(self) -> dict:
        return {"stages": [{"name": n, "seconds": round(s, 3)} for n, s in self.stages],
                "total_seconds": round(self.total, 3)}


def load_stacker(cfg: dict) -> Stacker:
    """The fitted model from the last full pipeline run, or config weights.

    Never trained here: a detector that refits itself around the attack it is
    being asked to find is not being tested.
    """
    path = Path(cfg["fusion"]["model_path"])
    if path.exists():
        from .stacker import load as load_model
        try:
            return load_model(path)
        except Exception as exc:                      # a stale artefact must not stop a run
            log.warning("could not load %s (%s) — falling back to config weights", path, exc)
    return Stacker(fallback_weights=default_weights(cfg),
                   metrics={"fitted": False, "reason": "no saved stacker — config weights"})


def signals_frame(entities: pd.DataFrame, rule_scores: pd.Series, anomaly: pd.DataFrame,
                  gnn: pd.DataFrame, taint: pd.DataFrame) -> pd.DataFrame:
    """One row per entity, the four signals filled in. Same shape as the full
    pipeline's, because the same alert builder reads it."""
    signals = entities.rename(columns={"cluster_id": "entity_id"}).copy()
    signals = signals.merge(rule_scores, on="entity_id", how="left")
    signals = signals.merge(anomaly[["entity_id", "anomaly_score"]], on="entity_id", how="left")
    signals = signals.merge(gnn, on="entity_id", how="left")
    if len(taint):
        signals = signals.merge(taint[["entity_id", "taint_score", "taint_path"]],
                                on="entity_id", how="left")
    else:
        signals["taint_score"] = 0.0
        signals["taint_path"] = None
    for column in SIGNALS:
        if column not in signals:
            signals[column] = 0.0
        signals[column] = signals[column].fillna(0.0)
    signals["taint_path"] = signals["taint_path"].apply(lambda v: v if isinstance(v, list) else [])
    return signals


def update(state: dict, new_rows: pd.DataFrame, cfg: dict | None = None,
           watchlist_path=None, timing: Timing | None = None) -> dict:
    """Fold `new_rows` into a bundle produced by `fusion.pipeline.collect_signals`.

    Returns a bundle of the same shape, plus `alerts_frame` — the ranked,
    explained alert list — and the timing.
    """
    cfg = cfg or config.load()
    timing = timing or Timing()
    df = state["df"]
    graph: nx.MultiDiGraph = state["graph"]
    features: FeatureSet = state["features"]

    with timing.stage("graph: add new transactions"):
        new_graph = build_graph(new_rows, cfg)
        new_txs = list(graph_transactions(new_graph))
        # An injection mints its transactions from its seed. Seeing one that is
        # already here means the same seed has been injected before, and going
        # on would double every amount in it.
        repeated = [tx.txid for tx in new_txs if tx.txid in graph]
        if repeated:
            raise ValueError(
                f"{len(repeated)} of these transactions are already in the dataset "
                f"(for example {repeated[0]}). The same seed has been injected before — "
                "use a different seed, or reset the dataset."
            )
        graph.add_nodes_from(new_graph.nodes(data=True))
        graph.add_edges_from(new_graph.edges(keys=True, data=True))

    with timing.stage("cluster + features: whole dataset"):
        # Deliberately not incremental. The change-address heuristics read the
        # transaction history, so clustering the new transactions alone can
        # reach a different answer from clustering them in context — which is
        # a wrong answer arrived at quickly. Both stages are milliseconds.
        all_txs = list(graph_transactions(graph))
        clustering = cluster_wallets(all_txs, cfg)
        entities, tx_features = compute_all(all_txs, clustering, cfg)
        features = FeatureSet(entities, tx_features, clustering)
        df = pd.concat([df, new_rows], ignore_index=True)

    with timing.stage("rules: whole graph"):
        alerts = alerts_to_frame(run_all(graph, features, cfg))
        rule_score = (alerts.groupby("entity_id")["score"].max().rename("rule_score")
                      if len(alerts) else pd.Series(dtype=float, name="rule_score"))

    with timing.stage("anomaly: refit over the population"):
        anomaly = fit_score(features.entities, cfg)

    with timing.stage("gnn: inference, never training"):
        gnn = gnn_scores(df, cfg)
        if not len(gnn):                      # torch absent, or no trained model
            gnn = pd.DataFrame(columns=["entity_id", "gnn_score"])

    with timing.stage("origins: new transactions only"):
        intel = state.get("intel") or load_intel(None, cfg["ingest"]["input_dir"], cfg)
        new_origins, propagation = estimate_all(new_rows, intel, cfg)
        origins = pd.concat([state["origins"], new_origins], ignore_index=True)

    with timing.stage("correlation: recomputed globally"):
        links = correlate(df, features, cfg, origins, intel)

    with timing.stage("taint: from the watchlist"):
        entity_graph = build_entity_graph(graph, features.clustering, cfg)
        watchlist = state.get("watchlist") or load_watchlist(watchlist_path, cfg)
        taint = compute_taint(entity_graph, watchlist, features.entity_of, cfg=cfg)

    with timing.stage("fuse: score with the saved model"):
        signals = signals_frame(features.entities, rule_score, anomaly, gnn, taint)
        stacker = state.get("stacker") or load_stacker(cfg)
        bundle = {
            "df": df, "graph": graph, "features": features, "signals": signals,
            "alerts": alerts, "links": links, "origins": origins,
            "propagation": propagation, "entity_graph": entity_graph,
            "watchlist": watchlist, "taint": taint, "intel": intel, "stacker": stacker,
            "seed_entities": set(taint[taint["taint_hops"] == 0]["entity_id"])
            if len(taint) else set(),
        }
        bundle["alerts_frame"] = build_alerts(bundle, stacker, cfg)

    bundle["timing"] = timing
    bundle["new_txids"] = [tx.txid for tx in new_txs]
    return bundle


def entity_scores(bundle: dict, entity_ids: Iterable[str]) -> pd.DataFrame:
    """Every engine's score for a set of entities, plus the fused score.

    This is what a red-team run shows when nothing was detected: the numbers
    that did not clear the bar, rather than a shrug.
    """
    wanted = set(entity_ids)
    signals = bundle["signals"]
    rows = signals[signals["entity_id"].isin(wanted)].copy()
    if rows.empty:
        return rows
    stacker: Stacker = bundle["stacker"]
    rows["risk_score"] = stacker.score(rows)
    columns = ["entity_id", *SIGNALS, "risk_score"]
    return rows[columns].sort_values("risk_score", ascending=False, ignore_index=True)
