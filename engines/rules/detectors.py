"""Human-readable rule detectors.

Every detector returns Alerts carrying a plain-English reason with the numbers
that made it fire. Thresholds live in config.yaml under engines.rules — tuning
is a config change, not a code change.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

import networkx as nx
import pandas as pd

import config
from features.engineer import compute_all
from features.fingerprint import confident_labels
from graph.builder import Tx, from_parquet, graph_transactions
from graph.clustering import Clustering, cluster_wallets

from .schema import Alert, alerts_to_frame, ramp

HOUR = 3600.0


@dataclass
class FeatureSet:
    """What the detectors read: both feature grains plus the clustering."""

    entities: pd.DataFrame
    transactions: pd.DataFrame
    clustering: Clustering

    @classmethod
    def from_graph(cls, graph, cfg: dict | None = None) -> FeatureSet:
        cfg = cfg or config.load()
        txs = list(graph_transactions(graph)) if isinstance(graph, nx.MultiDiGraph) else list(graph)
        clustering = cluster_wallets(txs, cfg, fingerprints=confident_labels(txs, cfg))
        entities, transactions = compute_all(txs, clustering, cfg)
        return cls(entities, transactions, clustering)

    def entity_of(self, wallet: str) -> str:
        return self.clustering.cluster_of(wallet) or wallet


class TxWorld:
    """Transaction-level navigation: who spends what, and when."""

    def __init__(self, source):
        self.txs: list[Tx] = (list(graph_transactions(source))
                              if isinstance(source, nx.MultiDiGraph) else list(source))
        self.by_id = {t.txid: t for t in self.txs}
        self.spent_in: dict[str, str] = {}     # address -> txid spending it
        self.first_spend: dict[str, str] = {}  # address -> its first outgoing txid
        self.time: dict[str, float] = {}
        for tx in sorted(self.txs, key=lambda t: _epoch(t.timestamp) or 0.0):
            self.time[tx.txid] = _epoch(tx.timestamp) or 0.0
            for addr in tx.input_addresses:
                self.spent_in.setdefault(addr, tx.txid)
                self.first_spend.setdefault(addr, tx.txid)

    def spender(self, address: str) -> Tx | None:
        return self.by_id.get(self.spent_in.get(address, ""))

    def is_first_spend(self, address: str, txid: str) -> bool:
        """This wallet had never sent anything before this transaction."""
        return self.first_spend.get(address) == txid


def _epoch(ts) -> float | None:
    if ts is None:
        return None
    t = pd.Timestamp(ts)
    return None if pd.isna(t) else t.timestamp()


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def peel_walk(start: Tx, world: TxWorld, max_ratio: float) -> list[Tx]:
    """Follow a peeling chain forward: each hop keeps the bigger output moving."""
    chain: list[Tx] = []
    node, seen = start, set()
    while node is not None and node.txid not in seen and looks_peeled(node, max_ratio):
        seen.add(node.txid)
        chain.append(node)
        biggest = max(range(len(node.outputs)), key=lambda i: node.output_values[i])
        node = world.spender(node.output_addresses[biggest])
    return chain


def looks_peeled(tx: Tx, max_ratio: float) -> bool:
    """One input, two outputs, and one output takes only a small slice."""
    if len(tx.inputs) != 1 or len(tx.outputs) != 2:
        return False
    values = tx.output_values
    biggest = max(values)
    return bool(biggest) and min(values) / biggest <= max_ratio


# --- 1. ransomware collector ---------------------------------------------
def detect_ransomware_collector(features: FeatureSet, graph, cfg: dict | None = None) -> list[Alert]:
    """Many first-time wallets pay one entity, which then peels the pot away."""
    cfg = cfg or config.load()
    rules = cfg["engines"]["rules"]
    r, base = rules["ransomware_collector"], rules["base_score"]
    world = TxWorld(graph)

    max_ratio = cfg["engines"]["rules"]["peel_chain"]["max_peel_ratio"]
    incoming: dict[str, list[tuple[str, str]]] = {}  # entity -> [(sender wallet, txid)]
    collected_at: dict[str, set[str]] = {}           # entity -> wallets that received
    for tx in world.txs:
        senders = {features.entity_of(a) for a in tx.input_addresses}
        for addr, _ in tx.outputs:
            eid = features.entity_of(addr)
            if eid in senders:
                continue  # change, not a payment in
            collected_at.setdefault(eid, set()).add(addr)
            for sender_addr in tx.input_addresses:
                incoming.setdefault(eid, []).append((sender_addr, tx.txid))

    alerts = []
    for eid, payments in incoming.items():
        senders = {a for a, _ in payments}
        if len(senders) < r["min_senders"]:
            continue
        first_timers = {a for a, txid in payments if world.is_first_spend(a, txid)}
        share = len(first_timers) / len(senders)
        if share < r["first_time_sender_ratio"]:
            continue
        # Follow the outflow from whichever receiving wallet peels the furthest.
        # Walking the chain keeps this rule working even when clustering failed
        # to merge the change addresses into one entity.
        hops: list[str] = []
        for wallet in collected_at.get(eid, set()):
            spender = world.spender(wallet)
            if spender is None:
                continue
            chain = peel_walk(spender, world, max_ratio)
            if len(chain) > len(hops):
                hops = [t.txid for t in chain]
        if len(hops) < r["min_peel_hops"]:
            continue
        score = base + (1.0 - base) * (
            0.5 * ramp(len(senders), r["min_senders"], r["target_senders"]) +
            0.5 * ramp(len(hops), r["min_peel_hops"], r["target_peel_hops"]))
        reason = (f"received from {_plural(len(senders), 'distinct wallet')}, "
                  f"{len(first_timers)} of them first-time senders "
                  f"({share:.0%}), then peeled funds through {_plural(len(hops), 'hop')}")
        evidence = sorted({txid for _, txid in payments})[:20] + sorted(hops)[:20]
        alerts.append(Alert(eid, "ransomware_collector", score, reason, evidence))
    return alerts


# --- 2. CoinJoin ----------------------------------------------------------
def detect_coinjoin(features: FeatureSet, cfg: dict | None = None) -> list[Alert]:
    """Equal-value outputs in bulk: a mix, not a payment."""
    cfg = cfg or config.load()
    rules = cfg["engines"]["rules"]
    c, base = rules["coinjoin"], rules["base_score"]
    df = features.transactions
    hits = df[(df["equal_output_count"] >= c["min_equal_outputs"]) &
              (df["output_count"] >= c["min_outputs"])]
    alerts = []
    for row in hits.itertuples():
        score = ramp(row.equal_output_count, c["min_equal_outputs"],
                     c["target_equal_outputs"], base)
        reason = (f"transaction has {row.equal_output_count} outputs of equal value "
                  f"{row.equal_output_value:.8f} BTC, consistent with a CoinJoin mix")
        alerts.append(Alert(row.txid, "coinjoin", score, reason, [row.txid]))
    return alerts


# --- 3. peeling chain -----------------------------------------------------
def detect_peel_chain(features: FeatureSet, graph, cfg: dict | None = None) -> list[Alert]:
    """A run of transactions each shaving off a small slice and moving on."""
    cfg = cfg or config.load()
    rules = cfg["engines"]["rules"]
    p, base = rules["peel_chain"], rules["base_score"]
    world = TxWorld(graph)
    peel_txs = {t.txid for t in world.txs if looks_peeled(t, p["max_peel_ratio"])}

    # A chain head is a peel transaction that is not itself the continuation of one.
    continued = {t.txid for head in world.txs if head.txid in peel_txs
                 for t in peel_walk(head, world, p["max_peel_ratio"])[1:]}
    alerts = []
    for tx in world.txs:
        if tx.txid not in peel_txs or tx.txid in continued:
            continue
        chain = peel_walk(tx, world, p["max_peel_ratio"])
        if len(chain) < p["min_hops"]:
            continue
        score = ramp(len(chain), p["min_hops"], p["target_hops"], base)
        worst = max(min(n.output_values) / max(n.output_values) for n in chain)
        eid = features.entity_of(chain[0].input_addresses[0])
        reason = (f"funds moved through a {len(chain)}-hop peeling chain, "
                  f"each hop retaining under {worst:.0%} of the value as a payout")
        alerts.append(Alert(eid, "peel_chain", score, reason, [t.txid for t in chain][:30]))
    return alerts


# --- 4. layering ----------------------------------------------------------
def detect_layering(features: FeatureSet, graph, cfg: dict | None = None) -> list[Alert]:
    """Split wide, move through intermediates, merge back — inside one window."""
    cfg = cfg or config.load()
    rules = cfg["engines"]["rules"]
    lay, base = rules["layering"], rules["base_score"]
    world = TxWorld(graph)
    window = lay["window_hours"] * HOUR

    # A CoinJoin is wide on both sides by design — it is a mix, not layering.
    mixes = features.clustering.coinjoins
    splits = [t for t in world.txs
              if len(t.outputs) >= lay["min_fan_out"] and t.txid not in mixes]
    merges = {t.txid: t for t in world.txs
              if len(t.inputs) >= lay["min_fan_in"] and t.txid not in mixes}
    alerts = []
    for split in splits:
        t0 = world.time.get(split.txid, 0.0)
        # forward reachability, bounded by hops and by the time window
        frontier = {split.txid}
        seen = {split.txid}
        reached: dict[str, int] = {}
        for _ in range(lay["max_hops"]):
            nxt = set()
            for txid in frontier:
                for addr in world.by_id[txid].output_addresses:
                    spender = world.spender(addr)
                    if spender is None or spender.txid in seen:
                        continue
                    if world.time.get(spender.txid, 0.0) - t0 > window:
                        continue
                    seen.add(spender.txid)
                    nxt.add(spender.txid)
                    if spender.txid in merges:
                        reached[spender.txid] = reached.get(spender.txid, 0) + 1
            frontier = nxt
            if not frontier:
                break
        for merge_id in reached:
            merge = merges[merge_id]
            traced = sum(1 for a in merge.input_addresses if a in seen_addresses(world, seen))
            share = traced / len(merge.inputs)
            if share < lay["min_traced_inputs"]:
                continue
            hours = (world.time.get(merge_id, 0.0) - t0) / HOUR
            wallets = len({a for a in split.output_addresses})
            score = ramp(len(merge.inputs), lay["min_fan_in"], lay["min_fan_in"] * 3, base)
            reason = (f"funds split across {_plural(wallets, 'wallet')} and re-merged "
                      f"into one transaction of {len(merge.inputs)} inputs "
                      f"within {hours:.1f} hours")
            eid = features.entity_of(split.input_addresses[0]) if split.inputs else merge_id
            intermediates = sorted(seen - {split.txid, merge_id})[:28]
            alerts.append(Alert(eid, "layering", score, reason,
                                [split.txid, merge_id] + intermediates))
    return alerts


def seen_addresses(world: TxWorld, txids: set[str]) -> set[str]:
    return {a for txid in txids for a in world.by_id[txid].output_addresses}


# --- runner ---------------------------------------------------------------
DETECTORS = {
    "ransomware_collector": detect_ransomware_collector,
    "coinjoin": detect_coinjoin,
    "peel_chain": detect_peel_chain,
    "layering": detect_layering,
}


def run_all(graph, features: FeatureSet | None = None, cfg: dict | None = None) -> list[Alert]:
    cfg = cfg or config.load()
    features = features or FeatureSet.from_graph(graph, cfg)
    alerts: list[Alert] = []
    for name, fn in DETECTORS.items():
        alerts.extend(fn(features, cfg=cfg) if name == "coinjoin"
                      else fn(features, graph, cfg=cfg))
    floor = cfg["engines"]["rules"]["min_score"]
    return [a for a in alerts if a.score >= floor]


def run(input_path=None, output=None, cfg: dict | None = None) -> dict:
    cfg = cfg or config.load()
    graph = from_parquet(input_path, cfg)
    alerts = run_all(graph, cfg=cfg)
    df = alerts_to_frame(alerts)
    output = Path(output or cfg["engines"]["rules"]["alerts_path"])
    output.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(output, index=False)
    counts = df["rule_name"].value_counts().to_dict() if len(df) else {}
    return {"alerts": len(df), "by_rule": counts, "output": str(output)}


def main(argv=None) -> None:
    cfg = config.load()
    ap = argparse.ArgumentParser(prog="engines.rules", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", default=cfg["ingest"]["output_path"])
    ap.add_argument("--output", default=cfg["engines"]["rules"]["alerts_path"])
    args = ap.parse_args(argv)
    print(json.dumps(run(args.input, args.output), indent=2))
