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
#: Tx attribute -> the ingested column it comes from. Optional: absent columns
#: leave the attributes None.
CONSTRUCTION = {"version": "tx_version", "locktime": "locktime",
                "sequences": "input_sequences", "outpoints": "input_outpoints"}


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
    # Construction fields, when the dataset carries them (a wallet-profile
    # generator run, or a dump with raw transactions): features/fingerprint.py.
    version: int | None = None
    locktime: int | None = None
    sequences: list[int] | None = None
    outpoints: list[str] | None = None

    @property
    def construction(self) -> dict:
        return {k: getattr(self, k) for k in CONSTRUCTION if getattr(self, k) is not None}

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


def _int_or_none(value):
    return None if value is None or pd.isna(value) else int(value)


def iter_transactions(df: pd.DataFrame, ip_meta: dict | None = None) -> Iterator[Tx]:
    """Collapse relay rows into transactions, keeping every broadcast IP seen.

    `ip_meta`, if given, is filled with each IP's enriched asn / geo_country so
    build_graph can put them on the ip nodes.
    """
    ip_meta = {} if ip_meta is None else ip_meta
    for txid, rows in df.groupby("txid", sort=False):
        first = rows.iloc[0]
        ips = list(dict.fromkeys(str(ip) for ip in rows["src_ip"])) if "src_ip" in rows else []
        # keep whatever ingest enriched each IP with, for the ip nodes
        for ip, asn, country in zip(rows.get("src_ip", []), rows.get("asn", [None] * len(rows)),
                                    rows.get("geo_country", [None] * len(rows))):
            ip_meta.setdefault(str(ip), {"asn": _int_or_none(asn), "geo_country": country})
        yield Tx(
            txid=str(txid),
            inputs=list(zip(list(first["input_addresses"]), [float(v) for v in first["input_amounts"]])),
            outputs=list(zip(list(first["output_addresses"]), [float(v) for v in first["output_amounts"]])),
            fee=float(first.get("fee", 0.0) or 0.0),
            script_type=str(first.get("script_type", "") or ""),
            timestamp=first.get("timestamp"),
            ips=ips,
            **{attr: _optional(first.get(column), attr)
               for attr, column in CONSTRUCTION.items() if column in rows},
        )


def _optional(value, attr: str):
    if value is None or (not hasattr(value, "__len__") and pd.isna(value)):
        return None
    if attr in ("version", "locktime"):
        return int(value)
    return [int(v) for v in value] if attr == "sequences" else [str(v) for v in value]


def build_graph(source, cfg: dict | None = None) -> nx.MultiDiGraph:
    """wallet -> transaction (input), transaction -> wallet (output),
    ip -> transaction (broadcast). Amounts, times and script_type ride on edges."""
    ip_meta: dict[str, dict] = {}
    txs = iter_transactions(source, ip_meta) if isinstance(source, pd.DataFrame) else source
    g = nx.MultiDiGraph()
    for tx in txs:
        ts = tx.timestamp
        g.add_node(tx.txid, node_type=TRANSACTION, fee=tx.fee, script_type=tx.script_type,
                   timestamp=ts, n_inputs=len(tx.inputs), n_outputs=len(tx.outputs),
                   value_out=sum(tx.output_values), **tx.construction)
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
                g.add_node(ip, node_type=IP, **ip_meta.get(ip, {"asn": None, "geo_country": None}))
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
                 ips=[u for u, _, e in g.in_edges(txid, data=True) if e["kind"] == "broadcast"],
                 **{k: d[k] for k in CONSTRUCTION if d.get(k) is not None})


def from_parquet(path=None, cfg: dict | None = None) -> nx.MultiDiGraph:
    return build_graph(load(path, cfg), cfg)


def summary(g: nx.MultiDiGraph) -> dict:
    kinds: dict[str, int] = {}
    for *_, e in g.edges(data=True):
        kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
    return {"wallets": len(nodes_of_type(g, WALLET)),
            "transactions": len(nodes_of_type(g, TRANSACTION)),
            "ips": len(nodes_of_type(g, IP)), "edges": dict(sorted(kinds.items()))}
