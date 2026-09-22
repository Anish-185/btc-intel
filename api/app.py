"""Local read-only API over the processed artefacts.

    uvicorn api.app:app --host 127.0.0.1 --port 8000

Serves what the pipeline already wrote to data/processed/. No analysis happens
here beyond shaping subgraphs and a propagation tree for the dashboard, and
nothing reaches the network — the whole system stays air-gapped.

NO AUTHENTICATION. Deliberate, for the hackathon demo: this binds to localhost
and serves synthetic data. A real deployment carries case data for live
investigations and would need, at minimum, authentication with per-case
authorisation on every endpoint below, an audit log of who read which entity
(which is itself evidence), TLS termination, and a CORS list that is not a
convenience for a dev server. The feedback endpoint would additionally need the
analyst's identity recorded with the verdict.
"""

from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

import pandas as pd
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel

import config
from engines.propagation.estimators import estimate_origin
from engines.propagation.tree import build_trees, degraded_mode
from engines.rules.detectors import FeatureSet
from graph.builder import IP, TRANSACTION, WALLET, build_graph, load
from ingest.ip_intel import load_intel

from . import graph as graph_api
from .case_report import render_pdf

app = FastAPI(title="btc-intel", version="0.1.0",
              description="Offline Bitcoin transaction forensics (SIH26146)")

# Local frontend dev. See the module docstring: not what a deployment does.
app.add_middleware(CORSMiddleware, allow_origins=config.get("api.cors_origins"),
                   allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

CLASS_BADGE = {"known_bitcoin_relay": "relay", "tor_exit": "tor",
               "hosting_vpn": "hosting", "residential_or_unknown": "residential"}

STARTED_AT = datetime.now(timezone.utc).isoformat(timespec="seconds")


@lru_cache(maxsize=1)
def _commit() -> str:
    """Which build this process is. Read once, at start.

    A demo is lost when the browser talks to a server started before the fix
    it is demonstrating — the page looks right and the data is old. The commit
    is stamped into both halves so they can be compared instead of trusted.
    BTC_INTEL_COMMIT wins, for a container built without a .git directory.
    """
    stamped = os.environ.get("BTC_INTEL_COMMIT")
    if stamped:
        return stamped.strip()[:7]
    try:
        out = subprocess.run(["git", "rev-parse", "--short=7", "HEAD"],
                             cwd=Path(__file__).resolve().parent.parent,
                             capture_output=True, text=True, timeout=2, check=True)
        return out.stdout.strip()
    except Exception:                      # no git, no repo, no problem
        return "unknown"

# Where the API reads from. Defaults come from config.yaml; configure() points
# the app at another set of artefacts (a second case, or a test fixture).
STATE: dict = {"transactions": None, "intel_dir": None, "alerts_json": None,
               "feedback": None}


def configure(transactions=None, node_intel=None, alerts_json=None,
              feedback=None) -> None:
    STATE.update({"transactions": transactions, "intel_dir": node_intel,
                  "alerts_json": alerts_json, "feedback": feedback})
    for cached in (_transactions, _intel, _features):
        cached.cache_clear()


@lru_cache(maxsize=1)
def _transactions() -> pd.DataFrame:
    return load(STATE["transactions"])


@lru_cache(maxsize=1)
def _intel():
    cfg = config.load()
    return load_intel(None, STATE["intel_dir"] or cfg["ingest"]["input_dir"], cfg)


@lru_cache(maxsize=1)
def _features() -> tuple:
    """The wallet graph and its clustering — needed for entity detail and subgraphs.

    ponytail: rebuilt once per process from the parquet, not incrementally
    maintained. Fine for a demo-sized case; a live deployment would serve this
    from the same store the pipeline writes.
    """
    cfg = config.load()
    graph = build_graph(_transactions(), cfg)
    return graph, FeatureSet.from_graph(graph, cfg)


def _frame() -> pd.DataFrame:
    try:
        return _transactions()
    except FileNotFoundError:
        raise HTTPException(404, "no processed transactions — run the pipeline first")


def _alerts() -> dict:
    path = Path(STATE["alerts_json"] or config.get("fusion.alerts_json"))
    return json.loads(path.read_text()) if path.exists() else {"alerts": []}


def _alert_rows() -> list[dict]:
    return list(_alerts().get("alerts", []))


def _alert_for(entity_id: str) -> dict | None:
    for alert in _alert_rows():
        if entity_id in (alert.get("alert_id"), alert.get("entity_id")):
            return alert
    return None


@app.get("/version")
def version() -> dict:
    """What is actually running here.

    The console fetches this on load and compares `commit` with the one
    compiled into its own bundle; a mismatch means one half is stale and the
    page says so rather than showing yesterday's answers.
    """
    return {
        "commit": _commit(),
        "started_at": STARTED_AT,
        # From the schema, not from app.routes: routes mounted through a
        # router are wrapped and would not be counted. A missing endpoint is
        # exactly the kind of staleness this is here to catch.
        "routes": len(app.openapi().get("paths", {})),
    }


# --- dashboard ------------------------------------------------------------
@app.get("/stats")
def stats() -> dict:
    """Header counts for the dashboard, plus whether origin estimation is degraded."""
    cfg = config.load()
    df = _frame()
    propagation = degraded_mode(df)
    payload = _alerts()
    alerts = payload.get("alerts", [])
    _, features = _features()

    by_pattern: dict[str, int] = {}
    for alert in alerts:
        for pattern in alert.get("pattern_types") or ["(no rule fired)"]:
            by_pattern[pattern] = by_pattern.get(pattern, 0) + 1
    confidences = [float(a["risk_score"]) for a in alerts if a.get("risk_score") is not None]

    return {
        "rows": int(len(df)),
        "transactions": propagation["transactions"],
        "total_entities": len(features.clustering.clusters),
        "total_alerts": len(alerts),
        "alerts_by_pattern_type": dict(sorted(by_pattern.items())),
        "avg_confidence": round(sum(confidences) / len(confidences), 4) if confidences else 0.0,
        "features": {
            "origin_estimation": {
                "status": "degraded" if propagation["degraded"] else "ok",
                "reason": propagation["reason"],
                "multi_hop_transactions": propagation["multi_row_transactions"],
                "mean_observations_per_transaction": propagation["mean_observations"],
                "estimator": cfg["engines"]["propagation"]["estimator"],
            },
        },
        "alerts": len(alerts),          # kept: the dashboard header reads this
        "stacker": payload.get("stacker", {}),
        "intel": _intel().manifest().get("loaded", {}),
    }


@app.get("/alerts")
def alerts(limit: int | None = None, offset: int = Query(0, ge=0),
           min_score: float | None = Query(None, ge=0.0, le=1.0),
           entity_type: str | None = None,
           pattern_type: str | None = None) -> dict:
    """Ranked alerts, highest risk first, paginated and filtered."""
    cfg = config.load()
    size = min(limit or cfg["api"]["page_size"], cfg["api"]["max_page_size"])
    rows = _alert_rows()
    if min_score is not None:
        rows = [r for r in rows if float(r.get("risk_score") or 0.0) >= min_score]
    if entity_type:
        rows = [r for r in rows if r.get("entity_type") == entity_type]
    if pattern_type:
        rows = [r for r in rows if pattern_type in (r.get("pattern_types") or [])]
    rows.sort(key=lambda r: float(r.get("risk_score") or 0.0), reverse=True)
    payload = _alerts()
    return {
        "alert_threshold": payload.get("alert_threshold"),
        "stacker": payload.get("stacker", {}),
        "total": len(rows),
        "limit": size, "offset": offset,
        "filters": {"min_score": min_score, "entity_type": entity_type,
                    "pattern_type": pattern_type},
        "alerts": rows[offset:offset + size],
    }


# --- one entity -----------------------------------------------------------
@app.get("/entities/{entity_id}")
def entity(entity_id: str) -> dict:
    """Everything known about one entity: features, engine scores, explanation."""
    _, features = _features()
    table = features.entities
    row = table[table["cluster_id"] == entity_id]
    if row.empty:
        raise HTTPException(404, f"unknown entity {entity_id}")
    record = json.loads(row.iloc[0].to_json())
    alert = _alert_for(entity_id) or {}
    wallets = sorted(features.clustering.clusters.get(entity_id, {entity_id}))

    return {
        "entity_id": entity_id,
        "entity_type": alert.get("entity_type",
                                 "cluster" if len(wallets) > 1 else "wallet"),
        "wallets": wallets,
        "flag": features.clustering.flags.get(entity_id),
        "features": {k: v for k, v in record.items() if k != "cluster_id"},
        "scores": {
            "risk_score": alert.get("risk_score"),
            "rule_score": alert.get("rule_score"),
            "anomaly_score": alert.get("anomaly_score"),
            "gnn_score": alert.get("gnn_score"),
            "taint_score": alert.get("taint_score"),
            "top_signal": alert.get("top_signal"),
            "contributions": json.loads(alert["contributions"])
            if alert.get("contributions") else {},
        },
        "alerted": bool(alert),
        "pattern_types": alert.get("pattern_types", []),
        "reason": alert.get("reason"),
        "evidence": alert.get("evidence", []),
        "taint_path": alert.get("taint_path", []),
        "leads": json.loads(alert["leads"]) if alert.get("leads") else [],
        "caveat": ("scores rank leads for a human; an entity without an alert is not "
                   "cleared, only unremarkable"),
    }


def subgraph(entity_id: str, hops: int) -> dict:
    """Wallets, transactions and IPs within `hops` of this entity's wallets.

    Cytoscape.js elements format. Hops are counted on the wallet/transaction
    graph, so one hop out of a wallet reaches its transactions and two reaches
    the counterparty wallets.
    """
    cfg = config.load()
    graph, features = _features()
    wallets = features.clustering.clusters.get(entity_id)
    if not wallets:
        if entity_id not in graph:
            raise HTTPException(404, f"unknown entity {entity_id}")
        wallets = {entity_id}

    limit = cfg["api"]["max_graph_nodes"]
    seen: dict[str, int] = {w: 0 for w in wallets if w in graph}
    frontier = list(seen)
    for depth in range(1, hops + 1):
        nxt = []
        for node in frontier:
            for neighbour in set(graph.successors(node)) | set(graph.predecessors(node)):
                if neighbour not in seen and len(seen) < limit:
                    seen[neighbour] = depth
                    nxt.append(neighbour)
        frontier = nxt

    def entity_of(addr: str) -> str | None:
        return features.clustering.cluster_of(addr)

    nodes = []
    for node, depth in seen.items():
        data = graph.nodes[node]
        kind = data.get("node_type", WALLET)
        owner = entity_of(node) if kind == WALLET else None
        nodes.append({"data": {
            "id": node, "type": kind, "hop": depth,
            "label": node[:10] + "…" if kind != IP and len(node) > 12 else node,
            "full_id": node,
            "entity_id": owner,
            "is_focus": owner == entity_id or node in wallets,
            **({"asn": data.get("asn"), "country": data.get("geo_country")}
               if kind == IP else {}),
            **({"fee": data.get("fee"), "script_type": data.get("script_type")}
               if kind == TRANSACTION else {}),
        }})

    edges = []
    for u, v, key, data in graph.edges(keys=True, data=True):
        if u in seen and v in seen:
            edges.append({"data": {
                "id": f"{u}|{key}|{v}", "source": u, "target": v,
                "type": data.get("kind"), "label": data.get("kind"),
                "amount": data.get("amount"),
            }})

    return {
        "entity_id": entity_id, "hops": hops,
        "truncated": len(seen) >= limit,
        "counts": {"wallets": sum(1 for n in nodes if n["data"]["type"] == WALLET),
                   "transactions": sum(1 for n in nodes if n["data"]["type"] == TRANSACTION),
                   "ips": sum(1 for n in nodes if n["data"]["type"] == IP)},
        "layout": {"name": "cose"},
        "elements": {"nodes": nodes, "edges": edges},
    }


@app.get("/entities/{entity_id}/graph")
def entity_graph(entity_id: str, hops: int | None = Query(None, ge=1, le=4)) -> dict:
    return subgraph(entity_id, hops or config.get("api.graph_hops"))


@app.get("/entities/{entity_id}/report")
def entity_report(entity_id: str, hops: int | None = Query(None, ge=1, le=4),
                  investigation: str | None = None) -> Response:
    """A one-page PDF case report, ready to attach to a file.

    With `?investigation=<id>` the figure is the analyst's own saved view —
    the same nodes in the same arrangement they were looking at — rather than
    a freshly computed neighbourhood. A case report should show what the
    investigator saw.
    """
    detail = entity(entity_id)
    graph = (_investigation_figure(investigation)
             if investigation else subgraph(entity_id, hops or config.get("api.graph_hops")))
    pdf = render_pdf(detail, graph, datetime.now(timezone.utc))
    return Response(pdf, media_type="application/pdf", headers={
        "Content-Disposition": f'attachment; filename="btc-intel-{entity_id}.pdf"'})


def _investigation_figure(investigation_id: str) -> dict:
    """A saved investigation, in the shape the report's figure draws."""
    record = graph_api.load_investigation(investigation_id)
    state = record.get("state", {})
    elements = state.get("elements", [])
    nodes = [e for e in elements if "source" not in e.get("data", {})]
    edges = [e for e in elements if "source" in e.get("data", {})]
    counts = {kind: sum(1 for n in nodes if n["data"].get("type") == kind)
              for kind in ("wallet", "transaction", "ip")}
    return {
        "elements": {"nodes": nodes, "edges": edges},
        "positions": state.get("positions", {}),
        "counts": {"wallets": counts["wallet"], "transactions": counts["transaction"],
                   "ips": counts["ip"]},
        "hops": state.get("hops", 0),
        "truncated": False,
        "source_label": f"saved investigation {record.get('name') or record['id']}",
    }


# --- analyst feedback -----------------------------------------------------
class Feedback(BaseModel):
    status: str      # "confirmed" | "false_positive"


@app.post("/alerts/{alert_id}/feedback")
def alert_feedback(alert_id: str, body: Feedback) -> dict:
    """Record an analyst's verdict, for recalibrating the stacker later.

    Appended, never updated: a changed mind is a second row with a later
    timestamp, because the sequence of verdicts is itself evidence about the
    alert. Nothing here re-fits anything; fusion/stacker.py reads this file when
    it is next trained.
    """
    if body.status not in ("confirmed", "false_positive"):
        raise HTTPException(422, "status must be 'confirmed' or 'false_positive'")
    alert = _alert_for(alert_id)
    if alert is None:
        raise HTTPException(404, f"unknown alert {alert_id}")

    path = Path(STATE["feedback"] or config.get("fusion.feedback_parquet"))
    path.parent.mkdir(parents=True, exist_ok=True)
    row = pd.DataFrame([{
        "alert_id": alert_id,
        "entity_id": alert.get("entity_id", alert_id),
        "status": body.status,
        "risk_score": float(alert.get("risk_score") or 0.0),
        "top_signal": alert.get("top_signal"),
        "recorded_at": pd.Timestamp.now(tz="UTC"),
    }])
    # ponytail: read-concat-write. One analyst clicking a button at human speed;
    # if this ever needs concurrency, it wants a real append (or a database).
    if path.exists():
        row = pd.concat([pd.read_parquet(path), row], ignore_index=True)
    row.to_parquet(path, index=False)
    return {"alert_id": alert_id, "status": body.status, "recorded": len(row),
            "path": str(path)}


# --- propagation ----------------------------------------------------------
@app.get("/transactions/{txid}/propagation")
def propagation(txid: str) -> dict:
    """The observed propagation tree, in Cytoscape elements format.

    The estimated origin is marked `origin`, the runner-ups `runner_up`, and
    every node carries an IP-class badge so the dashboard can show at a glance
    that a candidate is a public relay rather than somebody's home connection.
    """
    df = _frame()
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
        "attribution_confidence": estimate.attribution_confidence,
        "estimator": estimate.estimator,
        "degraded": estimate.degraded,
        "low_confidence_origin": estimate.low_confidence,
        "anonymized_entry_point": estimate.anonymized_entry_point,
        "n_observations": estimate.n_observations,
        "runner_ups": [{"ip": ip, "score": round(float(s), 6)} for ip, s in runner_ups.items()],
        "caveat": ("estimated origin is a probabilistic lead, not an attribution — "
                   "the true origin is often absent from the observed hops"
                   + ("; this candidate is an anonymized entry point (Tor exit or "
                      "hosting), which is where the broadcast entered the network, "
                      "not who sent it" if estimate.anonymized_entry_point else "")),
        "layout": {"name": "dagre", "roots": [estimate.ip] if estimate.ip else []},
        "elements": {"nodes": nodes, "edges": edges},
    }


# The investigation graph endpoints, sharing this module's cached graph and
# alert list rather than rebuilding either.
graph_api.register(app, _features, _alerts)
