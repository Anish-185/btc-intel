"""IP correlation: penalties, saturation, and the language of the output.

The two required cases — a Tor exit must score below an otherwise identical
residential IP, and a widely shared IP below an exclusive one — plus guards on
the wording, because this module's whole risk is being read as attribution.
"""

from __future__ import annotations

import json
import math

import pandas as pd
import pytest

import config
from engines.correlation import scorer
from engines.correlation.scorer import (COLUMNS, asn_penalty, collect_observations,
                                        correlate, raw_confidence, run, shared_ip_penalty)
from engines.rules.detectors import FeatureSet
from graph.builder import build_graph

CFG = config.load()
T0 = pd.Timestamp("2026-01-01T00:00:00Z")

RESIDENTIAL_ASN = 9829        # BSNL — not in geoip.high_risk_asns
TOR_ASN = 208294              # Tor exit operator — in geoip.high_risk_asns
HOSTING_ASN = 14061           # DigitalOcean — in geoip.high_risk_asns


def addr(name: str) -> str:
    return "bc1q" + name.ljust(34, "z")


def row(txid, src_ip, asn, minutes, inputs, outputs, hop=0):
    return {"timestamp": T0 + pd.Timedelta(minutes=minutes), "src_ip": src_ip,
            "dst_ip": "10.255.0.1", "src_port": 40000 + hop, "dst_port": 8333,
            "txid": txid, "input_addresses": list(inputs),
            "output_addresses": [o for o, _ in outputs],
            "input_amounts": [1.0] * len(inputs),
            "output_amounts": [v for _, v in outputs], "fee": 0.001,
            "script_type": "p2wpkh", "asn": asn, "asn_org": f"AS{asn}",
            "geo_country": "IN", "high_risk_asn": False, "asn_source": "dataset"}


def broadcasts(prefix: str, ip: str, asn: int, n: int, start: float = 0.0) -> list[dict]:
    """n separate transactions from one wallet, all broadcast from one IP."""
    return [row(f"{prefix}{i}", ip, asn, start + i * 60,
                [addr(f"{prefix}wallet")], [(addr(f"{prefix}payee{i}"), 0.9)])
            for i in range(n)]


def score_of(links: pd.DataFrame, ip: str) -> float:
    match = links[links["ip"] == ip]
    assert len(match) == 1, f"expected one link for {ip}, got {len(match)}"
    return float(match.iloc[0]["final_score"])


def frame(rows) -> pd.DataFrame:
    return pd.DataFrame(rows)


# --- the required comparisons --------------------------------------------
def test_tor_exit_scores_below_an_identical_residential_ip():
    """Same cluster shape, same observation count — only the ASN differs."""
    rows = broadcasts("res", "117.200.1.10", RESIDENTIAL_ASN, 5)
    rows += broadcasts("tor", "185.220.9.9", TOR_ASN, 5, start=1000)
    links = correlate(frame(rows), cfg=CFG)
    residential = score_of(links, "117.200.1.10")
    tor = score_of(links, "185.220.9.9")
    assert tor < residential
    assert tor == pytest.approx(residential * CFG["engines"]["correlation"]["high_risk_asn_factor"])


def test_hosting_asn_is_penalised_the_same_way():
    rows = broadcasts("res", "117.200.1.10", RESIDENTIAL_ASN, 4)
    rows += broadcasts("host", "159.65.2.2", HOSTING_ASN, 4, start=1000)
    links = correlate(frame(rows), cfg=CFG)
    assert score_of(links, "159.65.2.2") < score_of(links, "117.200.1.10")


def test_an_ip_shared_across_unrelated_clusters_scores_below_an_exclusive_one():
    """A NAT gateway or café wifi looks exactly like this, and means nothing."""
    rows = broadcasts("solo", "117.200.1.10", RESIDENTIAL_ASN, 4)
    shared = "117.200.5.5"
    for c in range(10):                       # ten unrelated wallets, one IP
        rows += broadcasts(f"nat{c}", shared, RESIDENTIAL_ASN, 4, start=2000 + c * 500)
    links = correlate(frame(rows), cfg=CFG)
    exclusive = score_of(links, "117.200.1.10")
    shared_scores = links[links["ip"] == shared]["final_score"]
    assert len(shared_scores) == 10
    assert shared_scores.max() < exclusive
    assert links[links["ip"] == shared]["distinct_entities"].iloc[0] == 10


def test_penalties_compound():
    """Tor exit *and* widely shared: both discounts apply."""
    rows = broadcasts("res", "117.200.1.10", RESIDENTIAL_ASN, 4)
    for c in range(8):
        rows += broadcasts(f"m{c}", "185.220.7.7", TOR_ASN, 4, start=2000 + c * 500)
    links = correlate(frame(rows), cfg=CFG)
    worst = links[links["ip"] == "185.220.7.7"].iloc[0]
    assert worst["asn_penalty"] < 1.0 and worst["shared_ip_penalty"] < 1.0
    assert worst["final_score"] == pytest.approx(
        worst["raw_confidence"] * worst["asn_penalty"] * worst["shared_ip_penalty"])


# --- confidence curve -----------------------------------------------------
def test_raw_confidence_saturates_and_never_reaches_certainty():
    values = [raw_confidence(n, CFG) for n in range(1, 60)]
    assert all(b > a for a, b in zip(values, values[1:]))       # monotonic
    assert all(v < 1.0 for v in values)                          # never certain
    # the 20th sighting adds far less than the 2nd
    assert (values[19] - values[18]) < (values[1] - values[0]) / 10


def test_a_single_coincidence_is_never_a_strong_link():
    k = CFG["engines"]["correlation"]["saturation_k"]
    assert raw_confidence(1, CFG) == pytest.approx(1 - math.exp(-1 / k))
    assert raw_confidence(1, CFG) < 0.3


def test_saturation_k_is_configurable():
    slow = json.loads(json.dumps(CFG))
    slow["engines"]["correlation"]["saturation_k"] = 20
    assert raw_confidence(5, slow) < raw_confidence(5, CFG)


@pytest.mark.parametrize("distinct,expected", [(1, 1.0), (3, 1.0), (6, 0.5), (30, 0.1)])
def test_shared_ip_penalty_curve(distinct, expected):
    assert shared_ip_penalty(distinct, CFG) == pytest.approx(expected)


def test_shared_ip_penalty_has_a_floor():
    """Weakened to almost nothing, but never erased — the link still exists."""
    assert shared_ip_penalty(100000, CFG) >= CFG["engines"]["correlation"]["shared_ip"]["min_factor"]


def test_unknown_asn_is_not_penalised_as_if_it_were_clean_or_dirty():
    assert asn_penalty(None, CFG) == 1.0
    assert asn_penalty(RESIDENTIAL_ASN, CFG) == 1.0
    assert asn_penalty(TOR_ASN, CFG) < 1.0


# --- what counts as an observation ---------------------------------------
def test_observations_count_transactions_not_relay_rows():
    """One transaction seen at five hops is one broadcast, not five."""
    rows = [row("t1", "117.200.1.10", RESIDENTIAL_ASN, i, [addr("a")], [(addr("b"), 0.9)], hop=i)
            for i in range(5)]
    cfg = json.loads(json.dumps(CFG))
    cfg["engines"]["correlation"]["evidence"] = "all_hops"
    links = correlate(frame(rows), cfg=cfg)
    assert links["observation_count"].max() == 1


def test_earliest_hop_mode_keeps_only_the_first_sighting_per_transaction():
    rows = [row("t1", "117.200.1.10", RESIDENTIAL_ASN, 0, [addr("a")], [(addr("b"), 0.9)]),
            row("t1", "159.65.9.9", HOSTING_ASN, 5, [addr("a")], [(addr("b"), 0.9)], hop=1)]
    df = frame(rows)
    features = FeatureSet.from_graph(build_graph(df), CFG)
    earliest = collect_observations(df, features, CFG)
    assert {o.ip for o in earliest} == {"117.200.1.10"}

    cfg = json.loads(json.dumps(CFG))
    cfg["engines"]["correlation"]["evidence"] = "all_hops"
    assert {o.ip for o in collect_observations(df, features, cfg)} == {"117.200.1.10", "159.65.9.9"}


def test_coinjoin_broadcasts_are_not_attributed_to_participants():
    """One participant broadcasts for everyone; tying that IP to all of them
    would invent associations that do not exist."""
    cj = row("cj", "117.200.1.10", RESIDENTIAL_ASN, 0,
             [addr(f"p{i}") for i in range(5)],
             [(addr(f"o{i}"), 0.0999) for i in range(5)])
    df = frame([cj])
    features = FeatureSet.from_graph(build_graph(df), CFG)
    assert "cj" in features.clustering.coinjoins
    assert collect_observations(df, features, CFG) == []


# --- output contract ------------------------------------------------------
def test_scores_stay_within_bounds_and_decompose():
    rows = broadcasts("a", "117.200.1.10", RESIDENTIAL_ASN, 7)
    links = correlate(frame(rows), cfg=CFG)
    assert list(links.columns) == COLUMNS
    assert links["final_score"].between(0, 1).all()
    for r in links.itertuples():
        assert r.final_score == pytest.approx(
            r.raw_confidence * r.asn_penalty * r.shared_ip_penalty)


def test_reason_states_ip_asn_kind_count_and_span():
    rows = broadcasts("a", "117.200.1.10", RESIDENTIAL_ASN, 6)
    reason = correlate(frame(rows), cfg=CFG).iloc[0]["reason"]
    assert "IP 117.200.1.10" in reason
    assert f"ASN {RESIDENTIAL_ASN}" in reason and "residential" in reason
    assert "6 transactions from this cluster" in reason
    assert "not an attribution" in reason


def test_reason_names_every_penalty_it_applied():
    rows = broadcasts("res", "117.200.1.10", RESIDENTIAL_ASN, 4)
    for c in range(8):
        rows += broadcasts(f"m{c}", "185.220.7.7", TOR_ASN, 4, start=2000 + c * 500)
    links = correlate(frame(rows), cfg=CFG)
    reason = links[links["ip"] == "185.220.7.7"].iloc[0]["reason"]
    assert "VPN/hosting/Tor-adjacent" in reason
    assert "7 other clusters" in reason
    assert "NAT gateway" in reason


def test_module_never_claims_ownership():
    """Guard on the wording itself: this module may only express association."""
    doc = scorer.__doc__
    assert "NEVER A CERTAIN" in doc and "PROBABILISTIC LEAD" in doc
    assert "never answers" in doc
    rows = broadcasts("a", "117.200.1.10", RESIDENTIAL_ASN, 40)
    links = correlate(frame(rows), cfg=CFG)
    for reason in links["reason"]:
        assert "belongs to" not in reason.lower()
        assert "owned by" not in reason.lower()
        assert "not an attribution" in reason
    assert links["final_score"].max() < 1.0, "no evidence may reach certainty"


def test_cli_writes_parquet(tmp_path):
    rows = broadcasts("a", "117.200.1.10", RESIDENTIAL_ASN, 5)
    frame(rows).to_parquet(tmp_path / "t.parquet", index=False)
    summary = run(tmp_path / "t.parquet", tmp_path / "ip.parquet", CFG)
    written = pd.read_parquet(tmp_path / "ip.parquet")
    assert len(written) == summary["links"] >= 1
    assert "never attribution" in summary["caveat"]
    assert list(written.columns) == COLUMNS


# --- against generated ground truth --------------------------------------
@pytest.fixture(scope="module")
def generated(tmp_path_factory):
    from generator.main import build_parser, generate
    from graph.builder import load
    from ingest.pipeline import run as ingest_run

    d = tmp_path_factory.mktemp("corr")
    raw = d / "raw"
    generate(build_parser().parse_args(["--n-actors", "250", "--n-transactions", "2000",
                                        "--output", str(raw), "--seed", "21",
                                        "--formats", "csv"]))
    ingest_run(raw, d / "t.parquet", d / "q.parquet", "csv")
    df = load(d / "t.parquet", CFG)
    features = FeatureSet.from_graph(build_graph(df, CFG), CFG)
    gt = json.loads((raw / "ground_truth.json").read_text())
    truth: dict[str, set[str]] = {}
    for cluster in gt["clusters"].values():
        for wallet in cluster["wallets"]:
            truth.setdefault(features.entity_of(wallet), set()).add(cluster["true_broadcast_ip"])
    return correlate(df, features, CFG), truth, gt


def test_repeated_observations_identify_the_real_broadcast_ip(generated):
    """The design claim: one sighting is a coincidence, several are a lead."""
    links, truth, _ = generated
    top = links.sort_values("final_score", ascending=False).drop_duplicates("entity_id")
    strong = top[top["observation_count"] >= 3]
    assert len(strong) >= 5, "not enough multi-observation clusters to judge"
    correct = sum(r.ip in truth.get(r.entity_id, set()) for r in strong.itertuples())
    print(f"\n  top-1 correct, observation_count >= 3: {correct}/{len(strong)}")
    assert correct / len(strong) >= 0.8


def test_score_is_calibrated_not_just_ordered(generated):
    """High-scoring links must be right more often than low-scoring ones."""
    links, truth, _ = generated
    links = links.assign(correct=[r.ip in truth.get(r.entity_id, set())
                                  for r in links.itertuples()])
    high = links[links["final_score"] >= 0.4]["correct"]
    low = links[links["final_score"] < 0.2]["correct"]
    print(f"  accuracy at score >= 0.4: {high.mean():.0%} ({len(high)} links); "
          f"at score < 0.2: {low.mean():.0%} ({len(low)} links)")
    assert high.mean() > low.mean()


def test_masked_broadcasts_are_discounted(generated):
    """Tor and hosting broadcasts hide the real origin — our score must say so."""
    links, _, gt = generated
    tor_ips = set(gt["ips"]["tor_exit"])
    tor_links = links[links["ip"].isin(tor_ips)]
    if len(tor_links):
        assert (tor_links["asn_penalty"] < 1.0).all()
        assert tor_links["final_score"].max() < links["final_score"].max()
