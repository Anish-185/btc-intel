"""Local read-only API over the processed artefacts.

    uvicorn api.app:app --host 127.0.0.1 --port 8000

Serves what the pipeline already wrote to data/processed/. No analysis happens
here beyond shaping a propagation tree for the dashboard, and nothing reaches
the network — the whole system stays air-gapped.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

import pandas as pd
from fastapi import FastAPI, HTTPException

import config
from engines.propagation.estimators import estimate_origin
from engines.propagation.tree import build_trees, degraded_mode
from graph.builder import load
from ingest.ip_intel import load_intel

app = FastAPI(title="btc-intel", version="0.1.0",
              description="Offline Bitcoin transaction forensics (SIH26146)")

CLASS_BADGE = {"known_bitcoin_relay": "relay", "tor_exit": "tor",
               "hosting_vpn": "hosting", "residential_or_unknown": "residential"}


# Where the API reads from. Defaults come from config.yaml; configure() points
# the app at another set of artefacts (a second case, or a test fixture).
STATE: dict = {"transactions": None, "intel_dir": None, "alerts_json": None}


def configure(transactions=None, node_intel=None, alerts_json=None) -> None:
    STATE.update({"transactions": transactions, "intel_dir": node_intel,
                  "alerts_json": alerts_json})
    _transactions.cache_clear()
    _intel.cache_clear()


@lru_cache(maxsize=1)
def _transactions() -> pd.DataFrame:
    return load(STATE["transactions"])


@lru_cache(maxsize=1)
def _intel():
    cfg = config.load()
    return load_intel(None, STATE["intel_dir"] or cfg["ingest"]["input_dir"], cfg)


def _alerts() -> dict:
    path = Path(STATE["alerts_json"] or config.get("fusion.alerts_json"))
    return json.loads(path.read_text()) if path.exists() else {"alerts": []}


@app.get("/stats")
def stats() -> dict:
    """Pipeline status, including whether origin estimation is degraded."""
    cfg = config.load()
    try:
        df = _transactions()
    except FileNotFoundError:
        raise HTTPException(404, "no processed transactions — run the pipeline first")
    propagation = degraded_mode(df)
    alerts = _alerts()
    return {
        "rows": int(len(df)),
        "transactions": propagation["transactions"],
        "features": {
            "origin_estimation": {
                "status": "degraded" if propagation["degraded"] else "ok",
                "reason": propagation["reason"],
                "multi_hop_transactions": propagation["multi_row_transactions"],
                "mean_observations_per_transaction": propagation["mean_observations"],
                "estimator": cfg["engines"]["propagation"]["estimator"],
            },
        },
        "alerts": len(alerts.get("alerts", [])),
        "stacker": alerts.get("stacker", {}),
        "intel": _intel().manifest().get("loaded", {}),
    }


@app.get("/alerts")
def alerts(limit: int = 50) -> dict:
    payload = _alerts()
    return {"alert_threshold": payload.get("alert_threshold"),
            "stacker": payload.get("stacker", {}),
            "alerts": payload.get("alerts", [])[:limit]}


@app.get("/transactions/{txid}/propagation")
def propagation(txid: str) -> dict:
    """The observed propagation tree, in Cytoscape elements format.

    The estimated origin is marked `origin`, the runner-ups `runner_up`, and
    every node carries an IP-class badge so the dashboard can show at a glance
    that a candidate is a public relay rather than somebody's home connection.
    """
    try:
        df = _transactions()
    except FileNotFoundError:
        raise HTTPException(404, "no processed transactions — run the pipeline first")
    rows = df[df["txid"] == txid]
    if rows.empty:
        raise HTTPException(404, f"unknown transaction {txid}")

    tree = build_trees(rows)[txid]
    estimate = estimate_origin(tree, _intel(), config.load())
    runner_ups = {ip: score for ip, score in estimate.runner_ups[:3]}
    ranked = dict(estimate.ranked)

    nodes = []
    for ip in tree.ips:
        classification = _intel().classify(ip, tree.graph.nodes.get(ip, {}).get("asn"))
        role = ("origin" if ip == estimate.ip
                else "runner_up" if ip in runner_ups else "relay")
        nodes.append({"data": {
            "id": ip, "label": ip, "role": role,
            "ip_class": classification.ip_class,
            "badge": CLASS_BADGE.get(classification.ip_class, classification.ip_class),
            "asn": classification.asn,
            "score": round(float(ranked.get(ip, 0.0)), 6),
            "first_seen": tree.first_seen.get(ip),
            "evidence": classification.evidence,
        }})
    edges = [{"data": {"id": f"{u}->{v}", "source": u, "target": v,
                       "timestamp": data["timestamp"]}}
             for u, v, data in tree.graph.edges(data=True)]

    return {
        "txid": txid,
        "estimated_origin": estimate.ip,
        "ip_class": estimate.ip_class,
        "confidence": estimate.confidence,
        "estimator": estimate.estimator,
        "degraded": estimate.degraded,
        "n_observations": estimate.n_observations,
        "runner_ups": [{"ip": ip, "score": round(float(s), 6)} for ip, s in runner_ups.items()],
        "caveat": ("estimated origin is a probabilistic lead, not an attribution — "
                   "the true origin is often absent from the observed hops"),
        "layout": {"name": "dagre", "roots": [estimate.ip] if estimate.ip else []},
        "elements": {"nodes": nodes, "edges": edges},
    }
