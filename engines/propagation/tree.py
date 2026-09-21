"""Propagation trees from relay records.

NTRO's data is src_ip -> dst_ip with a timestamp. When one txid appears in
several records, those records describe how that transaction spread across the
P2P network, and the shape of that spread carries information about where it
started — which is more than "whoever we happened to see first".

What we observe is a *sample* of the real diffusion: some hops are recorded,
most are not. Everything downstream must treat the tree as partial evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import networkx as nx
import pandas as pd


@dataclass
class PropagationTree:
    txid: str
    graph: nx.DiGraph                      # nodes = IPs, edges = observed hops
    first_seen: dict[str, float] = field(default_factory=dict)
    n_observations: int = 0

    @property
    def ips(self) -> list[str]:
        return list(self.graph.nodes)

    @property
    def size(self) -> int:
        return self.graph.number_of_nodes()

    @property
    def is_single_observation(self) -> bool:
        return self.n_observations <= 1

    def earliest(self) -> str | None:
        """The first-spy baseline: whichever IP we saw first."""
        return min(self.first_seen, key=self.first_seen.get) if self.first_seen else None

    def undirected_tree(self) -> nx.Graph:
        """A spanning tree of the observed graph, rooted at the earliest sighting.

        Rumor centrality is defined on a tree; real observations can contain
        cycles (two nodes each relaying to the other's neighbour), so we take a
        BFS spanning tree from the earliest-seen node, which is the best-known
        approximation of the diffusion order we actually have.
        """
        undirected = self.graph.to_undirected()
        if undirected.number_of_nodes() <= 1:
            return undirected
        components = list(nx.connected_components(undirected))
        if len(components) > 1:  # keep the component holding the earliest sighting
            root = self.earliest()
            component = next((c for c in components if root in c), max(components, key=len))
            undirected = undirected.subgraph(component).copy()
        if undirected.number_of_edges() == undirected.number_of_nodes() - 1:
            return undirected
        root = self.earliest()
        source = root if root in undirected else next(iter(undirected))
        return nx.bfs_tree(undirected, source).to_undirected()


def build_trees(df: pd.DataFrame, min_rows: int = 1) -> dict[str, PropagationTree]:
    """One tree per txid. Rows with the same txid are the observed hops."""
    trees: dict[str, PropagationTree] = {}
    for txid, rows in df.groupby("txid", sort=False):
        if len(rows) < min_rows:
            continue
        g = nx.DiGraph()
        first_seen: dict[str, float] = {}
        for row in rows.itertuples():
            src, dst = str(row.src_ip), str(row.dst_ip)
            ts = pd.Timestamp(row.timestamp).timestamp()
            asn = None if pd.isna(getattr(row, "asn", None)) else int(row.asn)
            g.add_node(src, asn=asn)
            g.add_node(dst, asn=g.nodes.get(dst, {}).get("asn"))
            if g.has_edge(src, dst):
                g.edges[src, dst]["timestamp"] = min(g.edges[src, dst]["timestamp"], ts)
            else:
                g.add_edge(src, dst, timestamp=ts)
            for ip in (src, dst):
                first_seen[ip] = min(first_seen.get(ip, ts), ts)
        trees[str(txid)] = PropagationTree(str(txid), g, first_seen, n_observations=len(rows))
    return trees


def degraded_mode(df: pd.DataFrame) -> dict:
    """Is there any multi-hop structure in this dataset at all?

    If every transaction appears exactly once there is nothing to estimate from
    and origin estimation falls back to the first-seen IP everywhere. The
    dashboard must say so rather than implying an estimate was made.
    """
    if df.empty:
        return {"degraded": True, "reason": "no relay records", "multi_row_transactions": 0,
                "transactions": 0, "mean_observations": 0.0}
    counts = df.groupby("txid").size()
    multi = int((counts > 1).sum())
    return {
        "degraded": multi == 0,
        "reason": ("every transaction appears in a single relay record: no propagation "
                   "structure to estimate from, origin falls back to first-seen IP"
                   if multi == 0 else None),
        "transactions": int(len(counts)),
        "multi_row_transactions": multi,
        "mean_observations": round(float(counts.mean()), 2),
    }
