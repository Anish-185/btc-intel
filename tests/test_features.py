"""Hand-built graphs with feature values worked out by hand."""

from __future__ import annotations

import json
import math

import pandas as pd
import pytest

import config
from features.engineer import (ENTITY_COLUMNS, TX_COLUMNS, compute_all, compute_features,
                               dormancy, is_round, run, transaction_features)
from graph.builder import Tx, build_graph, graph_transactions
from graph.clustering import cluster_wallets

CFG = config.load()
T0 = pd.Timestamp("2026-01-01T00:00:00Z")


def addr(name: str, kind: str = "p2wpkh") -> str:
    prefix = {"p2wpkh": "bc1q", "p2pkh": "1", "p2sh": "3"}[kind]
    return prefix + name.ljust(34, "z")


def tx(txid, inputs, outputs, minutes=0.0, ips=(), fee=0.001) -> Tx:
    return Tx(txid, list(inputs), list(outputs), fee=fee, script_type="p2wpkh",
              timestamp=T0 + pd.Timedelta(minutes=minutes), ips=list(ips))


def cfg_with(**features) -> dict:
    cfg = json.loads(json.dumps(CFG))
    for key, value in features.items():
        if isinstance(value, dict):
            cfg["features"][key].update(value)
        else:
            cfg["features"][key] = value
    return cfg


def entity_row(df: pd.DataFrame, clustering, wallet: str) -> pd.Series:
    return df.set_index("cluster_id").loc[clustering.cluster_of(wallet)]


# --- per-transaction ------------------------------------------------------
def test_coinjoin_equal_output_count_is_exact():
    cj = tx("cj", [(addr(f"in{i}"), 0.1) for i in range(5)],
            [(addr(f"out{i}"), 0.0999) for i in range(5)])
    other = tx("plain", [(addr("a"), 1.0)], [(addr("b"), 0.6), (addr("c"), 0.39)])
    df = transaction_features([cj, other]).set_index("txid")
    assert df.loc["cj", "equal_output_count"] == 5
    assert df.loc["cj", "input_count"] == 5 and df.loc["cj", "output_count"] == 5
    assert df.loc["plain", "equal_output_count"] == 1      # no two outputs match


def test_near_equal_outputs_count_within_tolerance():
    """CoinJoin outputs differ by the coordinator fee — still one group."""
    t = tx("t", [(addr(f"i{i}"), 1.0) for i in range(3)],
           [(addr("a"), 1.0), (addr("b"), 1.005), (addr("c"), 0.995)])
    assert transaction_features([t]).loc[0, "equal_output_count"] == 3


def test_peel_ratio_only_for_two_output_transactions():
    peel = tx("peel", [(addr("a"), 10.0)], [(addr("x"), 0.5), (addr("b"), 9.4)])
    three = tx("three", [(addr("a"), 1.0)], [(addr("x"), 0.3), (addr("y"), 0.3),
                                             (addr("z"), 0.39)])
    df = transaction_features([peel, three]).set_index("txid")
    assert df.loc["peel", "peel_ratio"] == pytest.approx(0.5 / 9.4)
    assert math.isnan(df.loc["three", "peel_ratio"])


def test_time_since_prev_tx_same_wallet():
    a = addr("a")
    txs = [tx("t1", [(addr("funder"), 5.0)], [(a, 4.9)], minutes=0),
           tx("t2", [(a, 4.9)], [(addr("x"), 2.0), (addr("change"), 2.8)], minutes=30),
           tx("t3", [(addr("change"), 2.8)], [(addr("y"), 2.7)], minutes=90)]
    df = transaction_features(txs).set_index("txid")
    assert math.isnan(df.loc["t1", "time_since_prev_tx_same_wallet"])  # nothing before it
    assert df.loc["t2", "time_since_prev_tx_same_wallet"] == 30 * 60   # a was funded at t1
    assert df.loc["t3", "time_since_prev_tx_same_wallet"] == 60 * 60   # change made at t2


def test_transaction_values_and_columns():
    t = tx("t", [(addr("a"), 2.0), (addr("b"), 1.0)], [(addr("c"), 2.9)], fee=0.1)
    df = transaction_features([t])
    assert list(df.columns) == TX_COLUMNS
    assert df.loc[0, "value_in"] == 3.0 and df.loc[0, "value_out"] == 2.9
    assert df.loc[0, "fee"] == 0.1


# --- round amounts --------------------------------------------------------
@pytest.mark.parametrize("amount,expected", [
    (1.0, True), (0.5, True), (2.0, True), (0.25, True), (0.1, True),
    (0.09491278, False), (1.00000001, False), (0.123456, False)])
def test_is_round(amount, expected):
    assert is_round(amount, CFG) is expected


def test_round_amount_ratio_counts_both_sides():
    """Entity a sends 1.0 (round) and 0.123456 (not) — exactly half."""
    txs = [tx("t1", [(addr("a"), 1.0)], [(addr("b"), 0.99)], minutes=0),
           tx("t2", [(addr("a"), 0.123456)], [(addr("c"), 0.12)], minutes=10)]
    cl = cluster_wallets(txs, CFG)
    df = compute_features(txs, cl, CFG)
    assert entity_row(df, cl, addr("a"))["round_amount_ratio"] == pytest.approx(0.5)


# --- entity shape ---------------------------------------------------------
def collector_txs() -> list[Tx]:
    """5 victims pay one collector, which pays out to 2 cash-out wallets."""
    victims = [tx(f"v{i}", [(addr(f"victim{i}"), 0.5)], [(addr("collector"), 0.49)],
                  minutes=i) for i in range(5)]
    outs = [tx(f"o{i}", [(addr("collector"), 0.4)], [(addr(f"cash{i}"), 0.39)],
               minutes=60 + i) for i in range(2)]
    return victims + outs


def test_fan_ratios_describe_collector_shape():
    txs = collector_txs()
    cl = cluster_wallets(txs, CFG)
    row = entity_row(compute_features(txs, cl, CFG), cl, addr("collector"))
    assert row["counterparties_in"] == 5 and row["counterparties_out"] == 2
    assert row["fan_in_ratio"] == pytest.approx(5 / 7)
    assert row["fan_out_ratio"] == pytest.approx(2 / 7)
    assert row["fan_in_ratio"] + row["fan_out_ratio"] == pytest.approx(1.0)


def test_a_victim_is_pure_fan_out():
    txs = collector_txs()
    cl = cluster_wallets(txs, CFG)
    row = entity_row(compute_features(txs, cl, CFG), cl, addr("victim0"))
    assert row["fan_out_ratio"] == 1.0 and row["fan_in_ratio"] == 0.0
    assert row["txs_out"] == 1 and row["txs_in"] == 0


def test_velocity_and_lifetime():
    """4 transactions spread over exactly 2 days -> 2 per day."""
    txs = [tx(f"t{i}", [(addr("a"), 1.0)], [(addr(f"b{i}"), 0.99)], minutes=i * 960)
           for i in range(4)]  # 0, 16h, 32h, 48h
    cl = cluster_wallets(txs, CFG)
    row = entity_row(compute_features(txs, cl, CFG), cl, addr("a"))
    assert row["lifetime_days"] == pytest.approx(2.0)
    assert row["velocity"] == pytest.approx(2.0)


def test_velocity_of_a_single_transaction_entity_is_not_divided_by_zero():
    txs = [tx("t", [(addr("a"), 1.0)], [(addr("b"), 0.99)])]
    cl = cluster_wallets(txs, CFG)
    row = entity_row(compute_features(txs, cl, CFG), cl, addr("a"))
    assert row["lifetime_days"] == 0.0 and row["velocity"] == 1.0


# --- dormancy -------------------------------------------------------------
def test_dormant_then_active_detects_gap_followed_by_burst():
    """Two early transactions, 60 days of silence, then 5 in one hour."""
    early = [tx(f"e{i}", [(addr("a"), 1.0)], [(addr(f"x{i}"), 0.99)], minutes=i) for i in range(2)]
    burst = [tx(f"b{i}", [(addr("a"), 1.0)], [(addr(f"y{i}"), 0.99)],
                minutes=60 * 24 * 60 + i * 12) for i in range(5)]
    cl = cluster_wallets(early + burst, CFG)
    row = entity_row(compute_features(early + burst, cl, CFG), cl, addr("a"))
    assert row["dormant_then_active"]
    assert row["max_dormant_gap_days"] == pytest.approx(60 - 1 / 1440, abs=0.01)
    assert row["max_burst_transactions"] == 5


def test_a_long_gap_without_a_burst_is_not_flagged():
    txs = [tx("t1", [(addr("a"), 1.0)], [(addr("x"), 0.99)], minutes=0),
           tx("t2", [(addr("a"), 1.0)], [(addr("y"), 0.99)], minutes=60 * 24 * 90)]
    cl = cluster_wallets(txs, CFG)
    row = entity_row(compute_features(txs, cl, CFG), cl, addr("a"))
    assert not row["dormant_then_active"]
    assert row["max_dormant_gap_days"] == pytest.approx(90.0)


def test_a_busy_entity_without_a_gap_is_not_flagged():
    txs = [tx(f"t{i}", [(addr("a"), 1.0)], [(addr(f"x{i}"), 0.99)], minutes=i) for i in range(20)]
    cl = cluster_wallets(txs, CFG)
    assert not entity_row(compute_features(txs, cl, CFG), cl, addr("a"))["dormant_then_active"]


def test_dormancy_thresholds_come_from_config():
    times = [0.0, 10 * 86400.0] + [10 * 86400.0 + i for i in range(3)]
    assert dormancy(times, CFG)[0] is False                      # 10-day gap < 30
    loose = cfg_with(dormancy={"gap_days": 5, "burst_transactions": 3})
    assert dormancy(times, loose)[0] is True


# --- network features -----------------------------------------------------
def test_unique_broadcast_ips_and_asns_come_from_the_graph():
    rows = []
    for i, (ip, asn) in enumerate([("10.0.0.1", 14061), ("10.0.0.2", 14061),
                                   ("10.0.0.3", 9829)]):
        rows.append({"timestamp": T0, "src_ip": ip, "dst_ip": "10.9.9.9",
                     "src_port": 40000, "dst_port": 8333, "txid": "t1",
                     "input_addresses": [addr("a")], "output_addresses": [addr("b")],
                     "input_amounts": [1.0], "output_amounts": [0.99], "fee": 0.001,
                     "script_type": "p2wpkh", "asn": asn, "geo_country": "IN"})
    g = build_graph(pd.DataFrame(rows))
    cl = cluster_wallets(list(graph_transactions(g)), CFG)
    row = entity_row(compute_features(g, cl, CFG), cl, addr("a"))
    assert row["unique_broadcast_ips"] == 3
    assert row["unique_asns"] == 2                      # two IPs share AS14061


def test_broadcast_ips_are_attributed_to_the_spender_not_the_recipient():
    txs = [tx("t", [(addr("a"), 1.0)], [(addr("b"), 0.99)], ips=["10.0.0.1", "10.0.0.2"])]
    cl = cluster_wallets(txs, CFG)
    df = compute_features(txs, cl, CFG)
    assert entity_row(df, cl, addr("a"))["unique_broadcast_ips"] == 2
    assert entity_row(df, cl, addr("b"))["unique_broadcast_ips"] == 0


# --- contract -------------------------------------------------------------
def test_entity_frame_has_the_expected_columns_and_placeholder():
    txs = collector_txs()
    df = compute_features(txs, cluster_wallets(txs, CFG), CFG)
    assert list(df.columns) == ENTITY_COLUMNS
    assert (df["avg_hop_distance_from_known_bad"] == 0.0).all()   # filled by fusion/taint
    assert df["cluster_id"].is_unique and df["cluster_id"].is_monotonic_increasing


def test_suspicious_merge_flag_reaches_the_feature_table():
    big = tx("big", [(addr(f"w{i}"), 1.0) for i in range(8)], [(addr("out"), 7.9)])
    cfg = json.loads(json.dumps(CFG))
    cfg["graph"]["collapse_guard"]["max_cluster_wallets"] = 3
    cl = cluster_wallets([big], cfg)
    df = compute_features([big], cl, cfg)
    assert entity_row(df, cl, addr("w0"))["suspicious_merge"]
    assert df["suspicious_merge"].sum() == 1


def test_compute_all_returns_both_grains():
    txs = collector_txs()
    entities, transactions = compute_all(txs, cfg=CFG)
    assert len(transactions) == len(txs)
    assert len(entities) == 8          # collector + 5 victims + 2 cash-outs


def test_cli_writes_both_parquet_files(tmp_path):
    from generator.main import build_parser, generate
    from ingest.pipeline import run as ingest_run
    from tests.test_ingest import stub_geo

    raw = tmp_path / "raw"
    generate(build_parser().parse_args(["--n-actors", "80", "--n-transactions", "500",
                                        "--output", str(raw), "--seed", "4", "--formats", "csv"]))
    ingest_run(raw, tmp_path / "t.parquet", tmp_path / "q.parquet", "csv", geo=stub_geo())
    summary = run(tmp_path / "t.parquet", tmp_path / "f.parquet", tmp_path / "ftx.parquet")

    entities = pd.read_parquet(tmp_path / "f.parquet")
    transactions = pd.read_parquet(tmp_path / "ftx.parquet")
    assert list(entities.columns) == ENTITY_COLUMNS and len(entities) == summary["entities"]
    assert list(transactions.columns) == TX_COLUMNS and len(transactions) == 500
    assert entities["velocity"].gt(0).all() and entities["txs"].gt(0).all()
    assert transactions["equal_output_count"].ge(1).all()
