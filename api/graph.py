"""Graph endpoints for the investigation view.

Everything here serves one picture: wallets connected *through* transactions,
never directly. A Bitcoin transaction is many-in and many-out, so a
wallet→wallet edge would invent a relationship that does not exist — if a
transaction has three inputs and four outputs, twelve implied wallet pairs
would each be a claim nobody can support. The transaction stays in the graph as
a connector node and the edges say exactly what the chain says.

Shapes are Cytoscape-ready and identical everywhere:

    {"nodes": [{"data": {"id", "type", "label", "risk", "parent"?}}],
     "edges": [{"data": {"id", "source", "target", "amount", "ts", "type"}}]}

Risk on a wallet is its entity's fused score, because risk is computed per
entity; a wallet with no alert carries 0.0 and `alerted: false`, which means
"unremarkable", not "clean".
"""

from __future__ import annotations

import json
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Literal

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

import config
from graph.builder import IP, TRANSACTION, WALLET

router = APIRouter(prefix="/graph", tags=["graph"])
investigations = APIRouter(prefix="/investigations", tags=["investigations"])

# How many counterparty wallets one transaction contributes when a wallet is
# expanded. A CoinJoin with 40 participants must not arrive as 40 nodes.
COUNTERPARTY_CAP = 12


# --- shaping --------------------------------------------------------------
def node_payload(graph, node: str, meta: "GraphMeta", depth: int | None = None) -> dict:
    kind = graph.nodes[node].get("node_type", WALLET)
    data: dict[str, Any] = {"id": node, "type": kind, "label": label_for(kind, node, graph)}
    if kind == WALLET:
        entity = meta.entity_of(node)
        data["risk"] = meta.risk_of(entity)
        data["alerted"] = entity in meta.alerted
        data["entity_id"] = entity
        if entity and entity != node:
            data["parent"] = entity
    elif kind == TRANSACTION:
        data["fee"] = graph.nodes[node].get("fee")
        data["script_type"] = graph.nodes[node].get("script_type")
    elif kind == IP:
        data["asn"] = graph.nodes[node].get("asn")
        data["country"] = graph.nodes[node].get("geo_country")
    if depth is not None:
        data["depth"] = depth
    return {"data": data}


def label_for(kind: str, node: str, graph) -> str:
    if kind == IP:
        country = graph.nodes[node].get("geo_country")
        return f"{node} {country}" if country else node
    return node


def edge_payload(source: str, target: str, key: str, attrs: dict) -> dict:
    ts = attrs.get("timestamp")
    return {
        "data": {
            "id": f"{source}|{key}|{target}",
            "source": source,
            "target": target,
            "amount": float(attrs.get("amount") or 0.0),
            "ts": ts.isoformat() if hasattr(ts, "isoformat") else ts,
            "type": attrs.get("kind", "flow"),
        }
    }


class GraphMeta:
    """Risk and cluster membership, looked up once per request."""

    def __init__(self, clustering, alerts: list[dict]):
        self.clustering = clustering
        self.by_entity = {a["entity_id"]: a for a in alerts}
        self.alerted = set(self.by_entity)

    def entity_of(self, wallet: str) -> str:
        return self.clustering.cluster_of(wallet) or wallet

    def risk_of(self, entity: str | None) -> float:
        alert = self.by_entity.get(entity or "")
        return round(float(alert["risk_score"]), 6) if alert else 0.0


def collect(graph, meta: GraphMeta, nodes: Iterable[str], edges: Iterable[tuple]) -> dict:
    """One place where a response is assembled, so every endpoint agrees."""
    seen: dict[str, dict] = {}
    for node in nodes:
        if node not in seen and node in graph:
            seen[node] = node_payload(graph, node, meta)
    payload_edges = []
    for source, target, key, attrs in edges:
        if source in seen and target in seen:
            payload_edges.append(edge_payload(source, target, key, attrs))
    return {"nodes": list(seen.values()), "edges": payload_edges}


# --- traversal ------------------------------------------------------------
def wallet_steps(graph, wallet: str, forward: bool, min_amount: float):
    """One money-flow step: wallet -> tx -> wallet (or the reverse).

    Yields (transaction, next_wallet, in_edge, out_edge) so the connector node
    and both halves of the hop stay in the result.
    """
    first = graph.out_edges if forward else graph.in_edges
    second = graph.out_edges if forward else graph.in_edges
    for a, b, key, attrs in first(wallet, keys=True, data=True):
        tx = b if forward else a
        if graph.nodes[tx].get("node_type") != TRANSACTION:
            continue
        for c, d, key2, attrs2 in second(tx, keys=True, data=True):
            other = d if forward else c
            if graph.nodes.get(other, {}).get("node_type") != WALLET or other == wallet:
                continue
            amount = float(attrs2.get("amount") or 0.0)
            if amount < min_amount:
                continue
            yield tx, other, (a, b, key, attrs), (c, d, key2, attrs2)


def register(app, state_features, state_alerts) -> None:
    """Wire the routers onto the app, reusing its cached graph and alerts.

    The API keeps one built graph per process (api.app._features); passing the
    accessors in keeps this module free of import cycles and lets the tests
    point it at a fixture.
    """
    router.state_features = state_features  # type: ignore[attr-defined]
    router.state_alerts = state_alerts  # type: ignore[attr-defined]
    app.include_router(router)
    app.include_router(investigations)


def _context():
    graph, features = router.state_features()  # type: ignore[attr-defined]
    alerts = router.state_alerts()  # type: ignore[attr-defined]
    return graph, GraphMeta(features.clustering, alerts.get("alerts", []))


def _require(graph, node_id: str):
    if node_id not in graph:
        raise HTTPException(404, f"unknown node {node_id}")


# --- endpoints ------------------------------------------------------------
@router.get("/nodes/{node_id}/neighbors")
def neighbors(
    node_id: str,
    direction: Literal["in", "out", "both"] = "both",
    limit: int = Query(20, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> dict:
    """One expansion step, ranked by amount and paginated.

    Expanding a wallet returns the transactions it took part in *and* the
    wallets on the other side of them — a lone connector node answers nothing.
    Ranking by amount is what makes an exchange with 4,000 counterparties
    usable: the twenty that matter arrive first and the rest stay one page
    away.
    """
    graph, meta = _context()
    _require(graph, node_id)
    kind = graph.nodes[node_id].get("node_type", WALLET)

    if kind == WALLET:
        groups = _wallet_neighbor_groups(graph, node_id, direction)
    else:
        groups = _generic_neighbor_groups(graph, node_id, direction)

    groups.sort(key=lambda g: -g["amount"])
    total = len(groups)
    page = groups[offset : offset + limit]

    nodes: list[str] = [node_id]
    edges: list[tuple] = []
    for group in page:
        nodes.extend(group["nodes"])
        edges.extend(group["edges"])

    payload = collect(graph, meta, nodes, edges)
    payload.update(
        {
            "node_id": node_id,
            "direction": direction,
            "limit": limit,
            "offset": offset,
            "total": total,
            "returned": len(page),
            "has_more": offset + len(page) < total,
            "remaining": max(total - offset - len(page), 0),
        }
    )
    return payload


def _wallet_neighbor_groups(graph, wallet: str, direction: str) -> list[dict]:
    """Each group is one transaction plus the wallets on its far side."""
    groups: dict[str, dict] = {}
    for forward in (True, False):
        if direction == "out" and not forward:
            continue
        if direction == "in" and forward:
            continue
        edge_iter = graph.out_edges if forward else graph.in_edges
        for a, b, key, attrs in edge_iter(wallet, keys=True, data=True):
            tx = b if forward else a
            if graph.nodes[tx].get("node_type") != TRANSACTION:
                continue
            group = groups.setdefault(
                tx, {"nodes": [tx], "edges": [], "amount": 0.0}
            )
            group["edges"].append((a, b, key, attrs))
            group["amount"] += float(attrs.get("amount") or 0.0)

            far = graph.out_edges if forward else graph.in_edges
            counterparties = sorted(
                (
                    (float(attrs2.get("amount") or 0.0), c, d, key2, attrs2)
                    for c, d, key2, attrs2 in far(tx, keys=True, data=True)
                    if (d if forward else c) != wallet
                    and graph.nodes.get(d if forward else c, {}).get("node_type") == WALLET
                ),
                key=lambda row: -row[0],
            )[:COUNTERPARTY_CAP]
            for _, c, d, key2, attrs2 in counterparties:
                group["nodes"].append(d if forward else c)
                group["edges"].append((c, d, key2, attrs2))
    return list(groups.values())


def _generic_neighbor_groups(graph, node_id: str, direction: str) -> list[dict]:
    """Transactions and IPs expand to their immediate neighbours."""
    groups: list[dict] = []
    for forward in (True, False):
        if direction == "out" and not forward:
            continue
        if direction == "in" and forward:
            continue
        edge_iter = graph.out_edges if forward else graph.in_edges
        for a, b, key, attrs in edge_iter(node_id, keys=True, data=True):
            other = b if forward else a
            groups.append(
                {
                    "nodes": [other],
                    "edges": [(a, b, key, attrs)],
                    "amount": float(attrs.get("amount") or 0.0),
                }
            )
    return groups


@router.get("/trace")
def trace(
    from_: str = Query(..., alias="from"),
    direction: Literal["forward", "backward"] = "forward",
    max_hops: int = Query(4, ge=1, le=6),
    min_amount: float = Query(0.0, ge=0.0),
) -> dict:
    """Follow the money, breadth-first, and say what was pruned.

    `depth` on every node is hops from the start wallet, which is what the
    dagre tree ranks on. Branches under `min_amount` are counted rather than
    dropped silently — an investigator needs to know the view is partial.
    """
    graph, meta = _context()
    _require(graph, from_)
    if graph.nodes[from_].get("node_type") != WALLET:
        raise HTTPException(400, "trace starts from a wallet")

    forward = direction == "forward"
    depth = {from_: 0}
    order = [from_]
    edges: list[tuple] = []
    pruned = 0
    queue: deque[tuple[str, int]] = deque([(from_, 0)])

    while queue:
        wallet, hop = queue.popleft()
        if hop >= max_hops:
            continue
        for tx, other, in_edge, out_edge in wallet_steps(graph, wallet, forward, 0.0):
            amount = float(out_edge[3].get("amount") or 0.0)
            if amount < min_amount:
                pruned += 1
                continue
            if tx not in depth:
                depth[tx] = hop + 1
                order.append(tx)
            edges.append(in_edge)
            edges.append(out_edge)
            if other not in depth:
                depth[other] = hop + 1
                order.append(other)
                queue.append((other, hop + 1))

    payload = collect(graph, meta, order, edges)
    for node in payload["nodes"]:
        node["data"]["depth"] = depth.get(node["data"]["id"], 0)
    payload.update(
        {
            "root": from_,
            "direction": direction,
            "max_hops": max_hops,
            "min_amount": min_amount,
            "pruned_edges": pruned,
            "wallets": sum(1 for n in payload["nodes"] if n["data"]["type"] == WALLET),
        }
    )
    return payload


@router.get("/path")
def path(
    from_: str = Query(..., alias="from"),
    to: str = Query(...),
    max_hops: int = Query(12, ge=1, le=30),
) -> dict:
    """The shortest directed money-flow path, or a clear 404.

    Shortest is counted in graph steps, so a path reads
    wallet → tx → wallet → tx → wallet. Direction is respected: money that
    never moved from A to B has no path, even if B paid A.
    """
    graph, meta = _context()
    _require(graph, from_)
    _require(graph, to)
    if from_ == to:
        raise HTTPException(400, "from and to are the same node")

    previous: dict[str, tuple] = {}
    seen = {from_}
    queue: deque[tuple[str, int]] = deque([(from_, 0)])
    found = False
    while queue and not found:
        node, hops = queue.popleft()
        if hops >= max_hops:
            continue
        for a, b, key, attrs in graph.out_edges(node, keys=True, data=True):
            if b in seen:
                continue
            seen.add(b)
            previous[b] = (a, b, key, attrs)
            if b == to:
                found = True
                break
            queue.append((b, hops + 1))

    if not found:
        raise HTTPException(
            404,
            f"no directed money-flow path from {from_} to {to} within {max_hops} steps — "
            "funds may have moved the other way, or through a transaction that is not "
            "in this dataset",
        )

    chain: list[tuple] = []
    cursor = to
    while cursor != from_:
        edge = previous[cursor]
        chain.append(edge)
        cursor = edge[0]
    chain.reverse()

    nodes = [from_] + [edge[1] for edge in chain]
    payload = collect(graph, meta, nodes, chain)
    for index, node in enumerate(payload["nodes"]):
        node["data"]["depth"] = index
    payload.update({"from": from_, "to": to, "hops": len(chain), "path": nodes})
    return payload


@router.get("/taint")
def taint_from_seed(
    seed: str = Query(..., description="wallet or entity id to seed from"),
    max_hops: int = Query(4, ge=1, le=6),
) -> dict:
    """Re-run taint as if this node were on the analyst's watchlist.

    The pipeline seeds taint only from the watchlist, deliberately — see
    fusion/taint.py. This endpoint answers the other question an investigator
    asks at the graph: *if I had known about this wallet, what would have lit
    up?* It computes, it does not persist: nothing here changes the alert list
    or the model, and the result is labelled as a hypothesis in the UI.
    """
    from fusion.taint import propagate
    from graph.entity_graph import build_entity_graph

    graph, meta = _context()
    _require(graph, seed)
    entity = meta.entity_of(seed) if graph.nodes[seed].get("node_type") == WALLET else seed

    cfg = config.load()
    entity_graph = build_entity_graph(graph, meta.clustering, cfg)
    if entity not in entity_graph:
        raise HTTPException(404, f"{seed} is not on the entity graph — nothing to spread from")

    cfg = json.loads(json.dumps(cfg))
    cfg["fusion"]["taint"]["max_hops"] = max_hops
    spread = propagate(entity_graph, {entity: 1.0}, cfg)

    rows = sorted(
        (
            {
                "entity_id": t.entity_id,
                "score": round(float(t.score), 6),
                "hops": t.hops,
                "path": list(t.path),
            }
            for t in spread.values()
            if t.entity_id != entity
        ),
        key=lambda row: -row["score"],
    )
    return {
        "seed": seed,
        "seed_entity": entity,
        "max_hops": max_hops,
        "tainted": rows[:500],
        "total": len(rows),
        "caveat": (
            "hypothetical: taint from this seed only, computed now and not stored. "
            "Inherited suspicion is not evidence of wrongdoing."
        ),
    }


@router.get("/clusters/{cluster_id}")
def cluster(cluster_id: str) -> dict:
    """The wallets one entity owns — what an expand-collapse parent holds."""
    graph, meta = _context()
    members = meta.clustering.clusters.get(cluster_id)
    if not members:
        raise HTTPException(404, f"unknown cluster {cluster_id}")
    nodes = [w for w in sorted(members) if w in graph]
    payload = collect(graph, meta, nodes, [])
    payload.update(
        {
            "cluster_id": cluster_id,
            "size": len(members),
            "risk": meta.risk_of(cluster_id),
            "flag": meta.clustering.flags.get(cluster_id),
        }
    )
    return payload


# --- saved investigations -------------------------------------------------
class Investigation(BaseModel):
    """Whatever the client needs to restore a view, plus a name to find it by.

    The state is stored as sent: the console owns its own view model, and a
    schema here would have to be revised every time the graph gains a control.
    """

    name: str = Field(default="Untitled investigation", max_length=200)
    state: dict[str, Any]


def _investigations_dir() -> Path:
    path = Path(config.get("fusion.investigations_dir"))
    path.mkdir(parents=True, exist_ok=True)
    return path


@investigations.post("")
def save_investigation(body: Investigation) -> dict:
    """Save a view. Append-only: each save is its own file with its own id, so
    an analyst can step back to what they had an hour ago."""
    identifier = uuid.uuid4().hex[:12]
    record = {
        "id": identifier,
        "name": body.name,
        "saved_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "state": body.state,
    }
    (_investigations_dir() / f"{identifier}.json").write_text(json.dumps(record, indent=2))
    return {"id": identifier, "name": record["name"], "saved_at": record["saved_at"]}


@investigations.get("/{investigation_id}")
def load_investigation(investigation_id: str) -> dict:
    path = _investigations_dir() / f"{Path(investigation_id).name}.json"
    if not path.exists():
        raise HTTPException(404, f"unknown investigation {investigation_id}")
    return json.loads(path.read_text())


@investigations.get("")
def list_investigations(limit: int = Query(50, ge=1, le=200)) -> dict:
    rows = []
    for path in sorted(_investigations_dir().glob("*.json"), reverse=True):
        record = json.loads(path.read_text())
        rows.append(
            {
                "id": record["id"],
                "name": record.get("name"),
                "saved_at": record.get("saved_at"),
                "nodes": len(record.get("state", {}).get("nodes", [])),
            }
        )
    rows.sort(key=lambda r: r.get("saved_at") or "", reverse=True)
    return {"investigations": rows[:limit], "total": len(rows)}
