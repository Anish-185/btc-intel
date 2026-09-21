"""Rule detectors against the generator's known ground truth.

Recall per pattern is printed, not just asserted — run with `pytest -rP
tests/test_rules.py` (or `-s`) to see the table when tuning thresholds.
"""

from __future__ import annotations

import json
import re

import pandas as pd
import pytest

import config
from engines.rules import (Alert, FeatureSet, alerts_to_frame, detect_coinjoin,
                           detect_layering, detect_peel_chain,
                           detect_ransomware_collector, run, run_all)
from graph.builder import Tx, build_graph

CFG = config.load()
T0 = pd.Timestamp("2026-01-01T00:00:00Z")


def addr(name: str) -> str:
    return "bc1q" + name.ljust(34, "z")


def tx(txid, inputs, outputs, minutes=0.0) -> Tx:
    return Tx(txid, list(inputs), list(outputs), fee=0.001, script_type="p2wpkh",
              timestamp=T0 + pd.Timedelta(minutes=minutes), ips=["10.0.0.1"])


def analyse(txs):
    g = build_graph(txs)
    return FeatureSet.from_graph(g, CFG), g


# --- hand-built cases, exact numbers in the reason -----------------------
def collector_case() -> list[Tx]:
    """8 first-time victims pay one collector, which peels 3 times."""
    txs = [tx(f"v{i}", [(addr(f"victim{i}"), 0.5)], [(addr("collector"), 0.49)], minutes=i)
           for i in range(8)]
    held, src = 3.9, addr("collector")
    for hop in range(3):
        change = addr(f"change{hop}")
        txs.append(tx(f"peel{hop}", [(src, held)],
                      [(addr(f"cash{hop}"), round(held * 0.1, 8)),
                       (change, round(held * 0.9, 8))], minutes=60 + hop))
        held, src = held * 0.9, change
    return txs


def test_ransomware_collector_reason_states_the_evidence():
    txs = collector_case()
    fs, g = analyse(txs)
    alerts = detect_ransomware_collector(fs, g, CFG)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.rule_name == "ransomware_collector"
    assert "received from 8 distinct wallets" in a.reason
    assert "8 of them first-time senders (100%)" in a.reason
    assert "peeled funds through 3 hops" in a.reason
    assert a.score > CFG["engines"]["rules"]["base_score"]
    assert set(a.evidence) >= {f"v{i}" for i in range(8)}


def test_ransomware_needs_both_the_fan_in_and_the_peeling():
    """Many first-time senders alone is an exchange, not a collector."""
    txs = [tx(f"v{i}", [(addr(f"victim{i}"), 0.5)], [(addr("collector"), 0.49)], minutes=i)
           for i in range(8)]
    fs, g = analyse(txs)
    assert detect_ransomware_collector(fs, g, CFG) == []


def test_ransomware_ignores_repeat_senders():
    """Regular counterparties are not victims — first-time share must be high."""
    txs = [tx(f"warm{i}", [(addr(f"c{i}"), 1.0)], [(addr("sink"), 0.99)], minutes=i)
           for i in range(6)]
    txs += [tx(f"again{i}", [(addr(f"c{i}"), 0.5)], [(addr("collector"), 0.49)],
               minutes=10 + i) for i in range(6)]
    fs, g = analyse(txs)
    assert detect_ransomware_collector(fs, g, CFG) == []


def test_coinjoin_reason_states_count_and_value():
    cj = tx("cj", [(addr(f"in{i}"), 0.1) for i in range(6)],
            [(addr(f"out{i}"), 0.1) for i in range(6)])
    fs, _ = analyse([cj])
    alerts = detect_coinjoin(fs, CFG)
    assert len(alerts) == 1
    assert alerts[0].entity_id == "cj"          # transaction-level rule
    assert alerts[0].reason == ("transaction has 6 outputs of equal value 0.10000000 BTC, "
                                "consistent with a CoinJoin mix")
    assert alerts[0].evidence == ["cj"]


def test_ordinary_payment_is_not_a_coinjoin():
    fs, _ = analyse([tx("t", [(addr("a"), 1.0)], [(addr("b"), 0.6), (addr("c"), 0.39)])])
    assert detect_coinjoin(fs, CFG) == []


def test_peel_chain_reason_states_hops_and_retention():
    txs = collector_case()
    fs, g = analyse(txs)
    alerts = detect_peel_chain(fs, g, CFG)
    assert len(alerts) == 1
    assert re.search(r"funds moved through a 3-hop peeling chain", alerts[0].reason)
    assert re.search(r"retaining under 1[12]% of the value", alerts[0].reason)
    assert [e for e in alerts[0].evidence] == ["peel0", "peel1", "peel2"]


def test_short_peel_chain_is_below_the_configured_minimum():
    txs = [tx("p0", [(addr("a"), 10.0)], [(addr("x"), 1.0), (addr("b"), 8.9)]),
           tx("p1", [(addr("b"), 8.9)], [(addr("y"), 0.9), (addr("c"), 7.9)], minutes=5)]
    fs, g = analyse(txs)
    assert detect_peel_chain(fs, g, CFG) == []     # 2 hops < min_hops 3


def test_layering_reason_states_width_and_window():
    split = tx("split", [(addr("src"), 10.0)],
               [(addr(f"mid{i}"), 2.4) for i in range(4)], minutes=0)
    merge = tx("merge", [(addr(f"mid{i}"), 2.4) for i in range(4)],
               [(addr("sink"), 9.5)], minutes=120)
    fs, g = analyse([split, merge])
    alerts = detect_layering(fs, g, CFG)
    assert len(alerts) == 1
    assert alerts[0].reason == ("funds split across 4 wallets and re-merged into one "
                                "transaction of 4 inputs within 2.0 hours")
    assert alerts[0].evidence[:2] == ["split", "merge"]


def test_layering_ignores_a_remerge_outside_the_window():
    split = tx("split", [(addr("src"), 10.0)],
               [(addr(f"mid{i}"), 2.4) for i in range(4)], minutes=0)
    merge = tx("merge", [(addr(f"mid{i}"), 2.4) for i in range(4)],
               [(addr("sink"), 9.5)], minutes=60 * 24 * 3)   # 3 days later
    fs, g = analyse([split, merge])
    assert detect_layering(fs, g, CFG) == []


def test_layering_does_not_fire_on_a_coinjoin():
    """A mix is wide on both sides by construction — that is not layering."""
    cj = tx("cj", [(addr(f"in{i}"), 0.1) for i in range(6)],
            [(addr(f"out{i}"), 0.1) for i in range(6)])
    spend = tx("spend", [(addr(f"out{i}"), 0.1) for i in range(6)],
               [(addr("sink"), 0.59)], minutes=30)
    fs, g = analyse([cj, spend])
    assert detect_layering(fs, g, CFG) == []


# --- alert contract -------------------------------------------------------
def test_alert_clamps_score_and_demands_a_reason():
    assert Alert("e", "r", 5.0, "because").score == 1.0
    assert Alert("e", "r", -1.0, "because").score == 0.0
    with pytest.raises(ValueError, match="no reason"):
        Alert("e", "r", 0.5, "")


def test_alerts_frame_is_sorted_by_score():
    df = alerts_to_frame([Alert("a", "r", 0.2, "low"), Alert("b", "r", 0.9, "high")])
    assert list(df["entity_id"]) == ["b", "a"]
    assert list(df.columns) == ["entity_id", "rule_name", "score", "reason", "evidence"]


def test_min_score_filters_what_gets_written():
    txs = collector_case()
    _, g = analyse(txs)
    strict = json.loads(json.dumps(CFG))
    strict["engines"]["rules"]["min_score"] = 0.99
    assert len(run_all(g, cfg=strict)) < len(run_all(g, cfg=CFG))


# --- against generated ground truth --------------------------------------
@pytest.fixture(scope="module")
def dataset(tmp_path_factory):
    from generator.main import build_parser, generate
    from graph.builder import from_parquet
    from ingest.pipeline import run as ingest_run
    from tests.test_ingest import stub_geo

    d = tmp_path_factory.mktemp("rules")
    raw = d / "raw"
    generate(build_parser().parse_args(["--n-actors", "400", "--n-transactions", "2500",
                                        "--output", str(raw), "--seed", "11",
                                        "--formats", "csv"]))
    ingest_run(raw, d / "t.parquet", d / "q.parquet", "csv", geo=stub_geo())
    graph = from_parquet(d / "t.parquet", CFG)
    features = FeatureSet.from_graph(graph, CFG)
    gt = json.loads((raw / "ground_truth.json").read_text())
    alerts = alerts_to_frame(run_all(graph, features, CFG))
    return {"dir": d, "graph": graph, "features": features, "gt": gt, "alerts": alerts}


def _recall_table(dataset) -> dict[str, tuple[int, int, float]]:
    gt, alerts, fs = dataset["gt"], dataset["alerts"], dataset["features"]
    typology = {t: m["typology"] for t, m in gt["transactions"].items()}
    pattern = {t: m["pattern"] for t, m in gt["transactions"].items()}

    def evidence_of(rule: str) -> set[str]:
        rows = alerts[alerts["rule_name"] == rule]
        return {t for ev in rows["evidence"] for t in ev}

    def ids_of(rule: str) -> set[str]:
        return set(alerts[alerts["rule_name"] == rule]["entity_id"])

    out = {}
    # one instance per true collector cluster, matched on the entity that holds it
    collectors = {fs.entity_of(c["wallets"][0]) for c in gt["clusters"].values()
                  if c["pattern_type"] == "ransomware_collector"}
    found = collectors & ids_of("ransomware_collector")
    out["ransomware_collector"] = (len(found), len(collectors),
                                   len(found) / max(len(ids_of("ransomware_collector")), 1))
    cj = {t for t, v in typology.items() if v == "coinjoin"}
    hit = cj & ids_of("coinjoin")
    out["coinjoin"] = (len(hit), len(cj), len(hit) / max(len(ids_of("coinjoin")), 1))
    peels = {t for t, v in pattern.items() if v == "ransomware_peel"}
    ev = evidence_of("peel_chain")
    out["peel_chain"] = (len(ev & peels), len(peels), len(ev & peels) / max(len(ev), 1))
    merges = {t for t, v in pattern.items() if v == "layering_merge"}
    ev = evidence_of("layering")
    lay = {t for t, v in typology.items() if v == "layering"}
    out["layering"] = (len(ev & merges), len(merges), len(ev & lay) / max(len(ev), 1))
    return out


def test_recall_per_pattern(dataset):
    table = _recall_table(dataset)
    print("\n  rule                    recall            evidence precision")
    for rule, (found, total, precision) in table.items():
        print(f"  {rule:<22} {found:>4}/{total:<4} = {found / max(total, 1):>5.0%}"
              f"        {precision:>5.0%}")
    print(f"  alerts written: {len(dataset['alerts'])}"
          f"  (min_score={CFG['engines']['rules']['min_score']})")

    # Deliberately loose: these are tuning floors, not accuracy targets.
    assert table["coinjoin"][0] / table["coinjoin"][1] >= 0.90
    assert table["ransomware_collector"][0] / table["ransomware_collector"][1] >= 0.60
    assert table["peel_chain"][0] / table["peel_chain"][1] >= 0.50
    assert table["layering"][0] / table["layering"][1] >= 0.50


def test_every_alert_carries_a_usable_reason(dataset):
    alerts = dataset["alerts"]
    assert len(alerts) > 0
    assert alerts["reason"].str.len().min() > 20
    assert alerts["reason"].str.contains(r"\d").all()      # every reason cites a number
    assert alerts["evidence"].map(len).gt(0).all()
    assert alerts["score"].between(0, 1).all()
    assert alerts["score"].ge(CFG["engines"]["rules"]["min_score"]).all()


def test_alerts_name_only_real_transactions_and_entities(dataset):
    known_tx = set(dataset["gt"]["transactions"])
    known_wallets = set(dataset["gt"]["wallets"])
    for row in dataset["alerts"].itertuples():
        assert row.entity_id in known_tx or row.entity_id in known_wallets
        for item in row.evidence:
            assert item in known_tx or item in known_wallets


def test_normal_traffic_is_not_mostly_alerted(dataset):
    """The noise class is the majority; rules must not fire on most of it."""
    gt = dataset["gt"]
    normal = {t for t, m in gt["transactions"].items() if m["typology"] == "normal"}
    flagged = {t for ev in dataset["alerts"]["evidence"] for t in ev} & normal
    assert len(flagged) / len(normal) < 0.15


def test_cli_writes_alerts_parquet(dataset, tmp_path):
    summary = run(dataset["dir"] / "t.parquet", tmp_path / "alerts.parquet", CFG)
    df = pd.read_parquet(tmp_path / "alerts.parquet")
    assert len(df) == summary["alerts"] == len(dataset["alerts"])
    assert set(summary["by_rule"]) <= {"ransomware_collector", "coinjoin", "peel_chain",
                                       "layering"}
