"""Collapse the wallet graph into one node per entity (cluster).

This is the link-analysis view the dashboard draws: a few thousand entities
instead of a few hundred thousand addresses. Flags from the collapse guard ride
along, so an oversized, untrusted cluster is visibly untrusted on screen.
"""

from __future__ import annotations

from collections.abc import Iterable

import networkx as nx

import config

from .builder import Tx, graph_transactions
from .clustering import Clustering

ENTITY = "entity"


def _as_transactions(source) -> list[Tx]:
    if isinstance(source, nx.MultiDiGraph):
        return list(graph_transactions(source))
    return list(source)


def build_entity_graph(source, clustering: Clustering, cfg: dict | None = None) -> nx.DiGraph:
    """Entity -> entity value flow. Self-loops (change, internal moves) are
    counted on the node rather than drawn as edges."""
    cfg = cfg or config.load()
    txs = _as_transactions(source)
    g = nx.DiGraph()

    def entity(addr: str) -> str:
        return clustering.cluster_of(addr) or addr

    for cid, members in clustering.clusters.items():
        g.add_node(cid, node_type=ENTITY, wallets=len(members),
                   flag=clustering.flags.get(cid), ips=set(), txs=0, internal_txs=0,
                   value_in=0.0, value_out=0.0)

    for tx in txs:
        mix = int(tx.txid in clustering.coinjoins)
        senders: dict[str, float] = {}
        for addr, value in tx.inputs:
            senders[entity(addr)] = senders.get(entity(addr), 0.0) + value
        receivers: dict[str, float] = {}
        for addr, value in tx.outputs:
            receivers[entity(addr)] = receivers.get(entity(addr), 0.0) + value
        total_in = sum(senders.values()) or 1.0

        for eid in set(senders) | set(receivers):
            if eid not in g:
                g.add_node(eid, node_type=ENTITY, wallets=1, flag=None, ips=set(),
                           txs=0, internal_txs=0, value_in=0.0, value_out=0.0)
            g.nodes[eid]["txs"] += 1
            g.nodes[eid]["ips"].update(tx.ips)
        for eid, value in senders.items():
            g.nodes[eid]["value_out"] += value
        for eid, value in receivers.items():
            g.nodes[eid]["value_in"] += value

        for src, sent in senders.items():
            share = sent / total_in
            for dst, received in receivers.items():
                if src == dst:
                    g.nodes[src]["internal_txs"] += 1
                    continue
                value = received * share
                if g.has_edge(src, dst):
                    e = g.edges[src, dst]
                    e["value"] += value
                    e["count"] += 1
                    e["mix_count"] += mix
                    e["txids"].append(tx.txid)
                    e["last_seen"] = max(e["last_seen"], tx.timestamp) if tx.timestamp else e["last_seen"]
                else:
                    # ponytail: full txid list per edge — fine at case scale; swap
                    # for a count plus a sample if an edge ever holds millions.
                    # mix_count: how many of those transactions were CoinJoins
                    # (clustering.is_coinjoin). fusion.taint does not cross an
                    # edge made of nothing else.
                    g.add_edge(src, dst, value=value, count=1, mix_count=mix, txids=[tx.txid],
                               first_seen=tx.timestamp, last_seen=tx.timestamp)
    for _, d in g.nodes(data=True):
        d["ips"] = sorted(d["ips"])
        d["shared_ip_count"] = len(d["ips"])
    return g


def top_entities(g: nx.DiGraph, by: str = "value_out", limit: int = 10) -> list[tuple[str, float]]:
    return sorted(((n, d.get(by, 0)) for n, d in g.nodes(data=True)),
                  key=lambda x: -x[1])[:limit]


def summary(g: nx.DiGraph) -> dict:
    flagged = [n for n, d in g.nodes(data=True) if d.get("flag")]
    return {"entities": g.number_of_nodes(), "links": g.number_of_edges(),
            "flagged": len(flagged),
            "value": round(sum(d["value"] for *_, d in g.edges(data=True)), 8),
            "largest_entity": max((d["wallets"] for _, d in g.nodes(data=True)), default=0)}
