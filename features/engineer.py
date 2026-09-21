"""Per-entity and per-transaction features.

    python -m features.engineer --input data/processed/transactions.parquet \
        --output data/processed/features.parquet

Two grains, two tables: entities (what the rules, anomaly and fusion stages
score) and transactions (what the CoinJoin/peel-shaped signals live on).
Thresholds come from config.yaml — none of them are baked in here.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Iterable
from pathlib import Path

import networkx as nx
import pandas as pd

import config
from graph.builder import IP, Tx, from_parquet, graph_transactions
from graph.clustering import Clustering, cluster_wallets, equal_value_group

DAY = 86400.0

ENTITY_COLUMNS = [
    "cluster_id", "wallets", "txs", "txs_in", "txs_out",
    "counterparties_in", "counterparties_out", "fan_in_ratio", "fan_out_ratio",
    "value_in", "value_out", "round_amount_ratio", "velocity", "lifetime_days",
    "dormant_then_active", "max_dormant_gap_days", "max_burst_transactions",
    "unique_broadcast_ips", "unique_asns", "avg_hop_distance_from_known_bad",
    "suspicious_merge",
]

TX_COLUMNS = ["txid", "timestamp", "input_count", "output_count", "equal_output_count",
              "equal_output_value", "peel_ratio", "value_in", "value_out", "fee",
              "time_since_prev_tx_same_wallet"]


def _epoch(ts) -> float | None:
    if ts is None or (isinstance(ts, float) and pd.isna(ts)):
        return None
    t = pd.Timestamp(ts)
    return None if pd.isna(t) else t.timestamp()


def is_round(amount: float, cfg: dict) -> bool:
    """A multiple of one of the configured units — the value a human typed,
    not one a coin-selection algorithm produced."""
    f = cfg["features"]
    tol = f["round_tolerance"]
    for unit in f["round_units"]:
        if amount >= unit and abs(amount / unit - round(amount / unit)) * unit <= tol:
            return True
    return False


def dormancy(times: list[float], cfg: dict) -> tuple[bool, float, int]:
    """Long quiet, then a burst. Returns (flag, largest gap in days, burst size)."""
    d = cfg["features"]["dormancy"]
    gap_s, window_s = d["gap_days"] * DAY, d["burst_window_days"] * DAY
    times = sorted(times)
    flagged, max_gap, max_burst = False, 0.0, 0
    for i in range(1, len(times)):
        gap = times[i] - times[i - 1]
        max_gap = max(max_gap, gap)
        if gap < gap_s:
            continue
        burst = sum(1 for t in times[i:] if t - times[i] <= window_s)
        max_burst = max(max_burst, burst)
        if burst >= d["burst_transactions"]:
            flagged = True
    return flagged, max_gap / DAY, max_burst


def _as_transactions(source) -> list[Tx]:
    if isinstance(source, nx.MultiDiGraph):
        return list(graph_transactions(source))
    return list(source)


def compute_features(graph, clustering: Clustering | None = None,
                     cfg: dict | None = None) -> pd.DataFrame:
    """Per-entity features, one row per cluster."""
    cfg = cfg or config.load()
    txs = _as_transactions(graph)
    clustering = clustering or cluster_wallets(txs, cfg)
    asn_of = _asn_lookup(graph)

    def entity(addr: str) -> str:
        return clustering.cluster_of(addr) or addr

    rows: dict[str, dict] = {}

    def row(eid: str) -> dict:
        if eid not in rows:
            rows[eid] = {"cluster_id": eid,
                         "wallets": len(clustering.clusters.get(eid, {eid})),
                         "txs_in": 0, "txs_out": 0, "value_in": 0.0, "value_out": 0.0,
                         "counterparties_in": set(), "counterparties_out": set(),
                         "amounts": [], "times": [], "ips": set(),
                         "suspicious_merge": bool(clustering.flags.get(eid))}
        return rows[eid]

    for tx in txs:
        ts = _epoch(tx.timestamp)
        senders: dict[str, float] = {}
        receivers: dict[str, float] = {}
        for addr, value in tx.inputs:
            senders[entity(addr)] = senders.get(entity(addr), 0.0) + value
        for addr, value in tx.outputs:
            receivers[entity(addr)] = receivers.get(entity(addr), 0.0) + value

        for eid, value in senders.items():
            r = row(eid)
            r["txs_out"] += 1
            r["value_out"] += value
            r["counterparties_out"].update(set(receivers) - {eid})
            r["amounts"].append(value)
            r["ips"].update(tx.ips)          # the spender is who broadcast it
            if ts is not None:
                r["times"].append(ts)
        for eid, value in receivers.items():
            r = row(eid)
            r["txs_in"] += 1
            r["value_in"] += value
            r["counterparties_in"].update(set(senders) - {eid})
            r["amounts"].append(value)
            if ts is not None and eid not in senders:
                r["times"].append(ts)

    out = [_finish_entity(r, asn_of, cfg) for r in rows.values()]
    df = pd.DataFrame(out, columns=ENTITY_COLUMNS)
    return df.sort_values("cluster_id", ignore_index=True)


def _finish_entity(r: dict, asn_of: dict, cfg: dict) -> dict:
    times = r["times"]
    lifetime_days = (max(times) - min(times)) / DAY if len(times) > 1 else 0.0
    window = max(lifetime_days, cfg["features"]["velocity_min_window_days"])
    txs = r["txs_in"] + r["txs_out"]
    amounts = r["amounts"]
    flagged, max_gap_days, max_burst = dormancy(times, cfg)
    asns = {asn_of[ip] for ip in r["ips"] if asn_of.get(ip) is not None}
    sides = len(r["counterparties_in"]) + len(r["counterparties_out"])
    return {
        "cluster_id": r["cluster_id"], "wallets": r["wallets"], "txs": txs,
        "txs_in": r["txs_in"], "txs_out": r["txs_out"],
        "counterparties_in": len(r["counterparties_in"]),
        "counterparties_out": len(r["counterparties_out"]),
        # how one-sided the entity is: 1.0 = pure collector, 0.0 = pure distributor.
        # Raw counterparty and tx counts are kept above, so concentration
        # (counterparties per transaction) is still derivable downstream.
        "fan_in_ratio": len(r["counterparties_in"]) / sides if sides else 0.0,
        "fan_out_ratio": len(r["counterparties_out"]) / sides if sides else 0.0,
        "value_in": r["value_in"], "value_out": r["value_out"],
        "round_amount_ratio": (sum(is_round(a, cfg) for a in amounts) / len(amounts)
                               if amounts else 0.0),
        "velocity": txs / window,
        "lifetime_days": lifetime_days,
        "dormant_then_active": flagged,
        "max_dormant_gap_days": max_gap_days,
        "max_burst_transactions": max_burst,
        "unique_broadcast_ips": len(r["ips"]),
        "unique_asns": len(asns),
        # filled in later by fusion/taint.py
        "avg_hop_distance_from_known_bad": 0.0,
        "suspicious_merge": r["suspicious_merge"],
    }


def _asn_lookup(graph) -> dict[str, int]:
    if not isinstance(graph, nx.MultiDiGraph):
        return {}
    return {n: d.get("asn") for n, d in graph.nodes(data=True) if d.get("node_type") == IP}


def transaction_features(graph, cfg: dict | None = None) -> pd.DataFrame:
    """Per-transaction features, one row per txid."""
    cfg = cfg or config.load()
    tolerance = cfg["graph"]["coinjoin"]["equal_value_tolerance"]
    txs = _as_transactions(graph)

    # Every appearance of a wallet, in time order, for the "since last seen" gap.
    seen: dict[str, list[float]] = {}
    for tx in txs:
        ts = _epoch(tx.timestamp)
        if ts is None:
            continue
        for addr in tx.input_addresses + tx.output_addresses:
            seen.setdefault(addr, []).append(ts)
    for values in seen.values():
        values.sort()

    rows = []
    for tx in txs:
        ts = _epoch(tx.timestamp)
        outs = tx.output_values
        value, group = equal_value_group(outs, tolerance) if outs else (0.0, [])
        rows.append({
            "txid": tx.txid, "timestamp": tx.timestamp,
            "input_count": len(tx.inputs), "output_count": len(tx.outputs),
            "equal_output_count": len(group), "equal_output_value": value,
            "peel_ratio": min(outs) / max(outs) if len(outs) == 2 and max(outs) else float("nan"),
            "value_in": sum(tx.input_values), "value_out": sum(outs), "fee": tx.fee,
            "time_since_prev_tx_same_wallet": _previous_gap(tx, seen, ts),
        })
    return pd.DataFrame(rows, columns=TX_COLUMNS).sort_values("txid", ignore_index=True)


def _previous_gap(tx: Tx, seen: dict[str, list[float]], ts: float | None) -> float:
    """Seconds since any input wallet was last involved in a transaction."""
    if ts is None:
        return float("nan")
    gaps = []
    for addr in tx.input_addresses:
        earlier = [t for t in seen.get(addr, []) if t < ts]
        if earlier:
            gaps.append(ts - earlier[-1])
    return min(gaps) if gaps else float("nan")


def compute_all(graph, clustering: Clustering | None = None,
                cfg: dict | None = None) -> tuple[pd.DataFrame, pd.DataFrame]:
    cfg = cfg or config.load()
    txs = _as_transactions(graph)
    clustering = clustering or cluster_wallets(txs, cfg)
    return (compute_features(graph, clustering, cfg), transaction_features(graph, cfg))


def run(input_path=None, output=None, tx_output=None, cfg: dict | None = None) -> dict:
    cfg = cfg or config.load()
    graph = from_parquet(input_path, cfg)
    entities, transactions = compute_all(graph, cfg=cfg)
    output = Path(output or cfg["features"]["entity_path"])
    tx_output = Path(tx_output or cfg["features"]["transaction_path"])
    for path, frame in ((output, entities), (tx_output, transactions)):
        path.parent.mkdir(parents=True, exist_ok=True)
        frame.to_parquet(path, index=False)
    return {"entities": len(entities), "transactions": len(transactions),
            "flagged_entities": int(entities["suspicious_merge"].sum()),
            "dormant_then_active": int(entities["dormant_then_active"].sum()),
            "output": str(output), "transaction_output": str(tx_output)}


def main(argv=None) -> None:
    cfg = config.load()
    ap = argparse.ArgumentParser(prog="features.engineer", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", default=cfg["ingest"]["output_path"])
    ap.add_argument("--output", default=cfg["features"]["entity_path"])
    ap.add_argument("--tx-output", default=cfg["features"]["transaction_path"])
    args = ap.parse_args(argv)
    print(json.dumps(run(args.input, args.output, args.tx_output), indent=2))


if __name__ == "__main__":
    main()
