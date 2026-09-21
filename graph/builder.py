"""Build the wallet / transaction / IP graph from processed transactions.

The parquet holds one row per *relay observation*, so a txid repeats across
hops; that is collapsed here into one transaction node with every observed
broadcast IP attached.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

import networkx as nx
import pandas as pd

import config

WALLET, TRANSACTION, IP = "wallet", "transaction", "ip"


@dataclass
class Tx:
    """One transaction, in the shape the clustering heuristics need."""

    txid: str
    inputs: list[tuple[str, float]]
    outputs: list[tuple[str, float]]
    fee: float = 0.0
    script_type: str = ""
    timestamp: pd.Timestamp | None = None
    ips: list[str] = field(default_factory=list)

    @property
    def input_addresses(self) -> list[str]:
        return [a for a, _ in self.inputs]

    @property
    def output_addresses(self) -> list[str]:
        return [a for a, _ in self.outputs]

    @property
    def input_values(self) -> list[float]:
        return [v for _, v in self.inputs]

    @property
    def output_values(self) -> list[float]:
        return [v for _, v in self.outputs]


def load(path=None, cfg: dict | None = None) -> pd.DataFrame:
    cfg = cfg or config.load()
    return pd.read_parquet(path or cfg["ingest"]["output_path"])


def iter_transactions(df: pd.DataFrame) -> Iterator[Tx]:
    """Collapse relay rows into transactions, keeping every broadcast IP seen."""
    for txid, rows in df.groupby("txid", sort=False):
        first = rows.iloc[0]
        ips = list(dict.fromkeys(str(ip) for ip in rows["src_ip"])) if "src_ip" in rows else []
        yield Tx(
            txid=str(txid),
            inputs=list(zip(list(first["input_addresses"]), [float(v) for v in first["input_amounts"]])),
            outputs=list(zip(list(first["output_addresses"]), [float(v) for v in first["output_amounts"]])),
            fee=float(first.get("fee", 0.0) or 0.0),
            script_type=str(first.get("script_type", "") or ""),
            timestamp=first.get("timestamp"),
            ips=ips,
        )


def build_graph(source, cfg: dict | None = None) -> nx.MultiDiGraph:
    """wallet -> transaction (input), transaction -> wallet (output),
    ip -> transaction (broadcast). Amounts, times and script_type ride on edges."""
    txs = iter_transactions(source) if isinstance(source, pd.DataFrame) else source
    g = nx.MultiDiGraph()
    for tx in txs:
        ts = tx.timestamp
        g.add_node(tx.txid, node_type=TRANSACTION, fee=tx.fee, script_type=tx.script_type,
                   timestamp=ts, n_inputs=len(tx.inputs), n_outputs=len(tx.outputs),
                   value_out=sum(tx.output_values))
        for i, (addr, amount) in enumerate(tx.inputs):
            _wallet(g, addr)
            g.add_edge(addr, tx.txid, key=f"in:{i}", kind="input", index=i, amount=amount,
                       timestamp=ts, script_type=tx.script_type)
        for i, (addr, amount) in enumerate(tx.outputs):
            _wallet(g, addr)
            g.add_edge(tx.txid, addr, key=f"out:{i}", kind="output", index=i, amount=amount,
                       timestamp=ts, script_type=tx.script_type)
        for ip in tx.ips:
            if ip not in g:
                g.add_node(ip, node_type=IP)
            g.add_edge(ip, tx.txid, key="broadcast", kind="broadcast", timestamp=ts)
    return g


def _wallet(g: nx.MultiDiGraph, addr: str) -> None:
    if addr not in g:
        g.add_node(addr, node_type=WALLET)


def nodes_of_type(g: nx.MultiDiGraph, node_type: str) -> list:
    return [n for n, d in g.nodes(data=True) if d.get("node_type") == node_type]


def graph_transactions(g: nx.MultiDiGraph) -> Iterator[Tx]:
    """Read transactions back out of a built graph (the inverse of build_graph)."""
    for txid in nodes_of_type(g, TRANSACTION):
        d = g.nodes[txid]
        ins = sorted(((e["index"], u, e["amount"]) for u, _, e in g.in_edges(txid, data=True)
                      if e["kind"] == "input"))
        outs = sorted(((e["index"], v, e["amount"]) for _, v, e in g.out_edges(txid, data=True)
                       if e["kind"] == "output"))
        yield Tx(txid, [(a, v) for _, a, v in ins], [(a, v) for _, a, v in outs],
                 fee=d.get("fee", 0.0), script_type=d.get("script_type", ""),
                 timestamp=d.get("timestamp"),
                 ips=[u for u, _, e in g.in_edges(txid, data=True) if e["kind"] == "broadcast"])


def from_parquet(path=None, cfg: dict | None = None) -> nx.MultiDiGraph:
    return build_graph(load(path, cfg), cfg)


def summary(g: nx.MultiDiGraph) -> dict:
    kinds: dict[str, int] = {}
    for *_, e in g.edges(data=True):
        kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
    return {"wallets": len(nodes_of_type(g, WALLET)),
            "transactions": len(nodes_of_type(g, TRANSACTION)),
            "ips": len(nodes_of_type(g, IP)), "edges": dict(sorted(kinds.items()))}
