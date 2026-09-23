"""Origin estimation: the algorithms, the relay penalty, and degraded mode.

The accuracy comparison used to be printed here and quoted from the test output.
It is now produced by `eval.origin` and published in `eval/results.md`; what
remains here asserts the invariants that table has to satisfy, **through the
same functions the report calls**. One implementation, so the published figures
and the test cannot disagree about what "top-1" means — which they did, with two
different ceiling definitions in circulation at once.
"""

from __future__ import annotations

import json

import networkx as nx
import pandas as pd
import pytest

import config
from engines.propagation.estimators import (ESTIMATORS, apply_class_weights, confidence_of,
                                            estimate_all, estimate_origin, first_timestamp,
                                            rumor_centrality, timestamp_weighted_centrality)
from engines.propagation.pipeline import run
from engines.propagation.tree import PropagationTree, build_trees, degraded_mode
from ingest.ip_intel import (HOSTING, KNOWN_RELAY, RESIDENTIAL, TOR_EXIT, IpIntel,
                             classify_ip, load_intel)

CFG = config.load()
T0 = pd.Timestamp("2026-01-01T00:00:00Z")


def row(txid, src, dst, seconds, asn=9829):
    return {"timestamp": T0 + pd.Timedelta(seconds=seconds), "src_ip": src, "dst_ip": dst,
            "src_port": 40000, "dst_port": 8333, "txid": txid,
            "input_addresses": ["bc1qa"], "output_addresses": ["bc1qb"],
            "input_amounts": [1.0], "output_amounts": [0.9], "fee": 0.001,
            "script_type": "p2wpkh", "asn": asn, "asn_org": f"AS{asn}",
            "geo_country": "IN", "high_risk_asn": False, "asn_source": "dataset"}


def intel_with(**kinds) -> IpIntel:
    """An IpIntel backed by nothing but the labels we hand it."""
    intel = IpIntel(intel_dir="/nonexistent", cfg=CFG)
    intel.add_synthetic({"relay": kinds.get("relay", []), "tor_exit": kinds.get("tor", []),
                         "hosting": kinds.get("hosting", []), "hosting_asns": []})
    return intel


def seven_node_tree() -> tuple[pd.DataFrame, str]:
    """A balanced tree whose true source is its centre, 10.0.0.1.

            10.0.0.1
           /        \\
        .2            .3
       /  \\          /  \\
     .4    .5      .6    .7
    """
    edges = [("10.0.0.1", "10.0.0.2", 1), ("10.0.0.1", "10.0.0.3", 2),
             ("10.0.0.2", "10.0.0.4", 3), ("10.0.0.2", "10.0.0.5", 4),
             ("10.0.0.3", "10.0.0.6", 5), ("10.0.0.3", "10.0.0.7", 6)]
    return pd.DataFrame([row("tx", s, d, t) for s, d, t in edges]), "10.0.0.1"


# --- trees ----------------------------------------------------------------
def test_tree_is_built_from_relay_rows():
    df, _ = seven_node_tree()
    tree = build_trees(df)["tx"]
    assert tree.size == 7 and tree.n_observations == 6
    assert isinstance(tree.graph, nx.DiGraph)
    assert tree.graph.edges["10.0.0.1", "10.0.0.2"]["timestamp"] == (T0 + pd.Timedelta(seconds=1)).timestamp()
    assert tree.earliest() == "10.0.0.1"


def test_cycles_are_reduced_to_a_spanning_tree():
    """Rumor centrality is defined on a tree; observations can contain cycles."""
    df = pd.DataFrame([row("tx", "10.0.0.1", "10.0.0.2", 1),
                       row("tx", "10.0.0.2", "10.0.0.3", 2),
                       row("tx", "10.0.0.3", "10.0.0.1", 3)])
    t = build_trees(df)["tx"].undirected_tree()
    assert t.number_of_edges() == t.number_of_nodes() - 1
    assert nx.is_tree(t)


# --- the required algorithm check ----------------------------------------
def test_rumor_centrality_picks_the_source_of_a_seven_node_tree():
    """Shah & Zaman (2011): the maximiser is the ML source on a full tree."""
    df, source = seven_node_tree()
    tree = build_trees(df)["tx"]
    scores = rumor_centrality(tree)
    assert max(scores, key=scores.get) == source
    assert scores[source] == 1.0                       # normalised to the maximum
    assert scores["10.0.0.4"] < scores["10.0.0.2"] < scores[source]


def test_rumor_centrality_is_symmetric_under_relabelling():
    df, _ = seven_node_tree()
    scores = rumor_centrality(build_trees(df)["tx"])
    leaves = ["10.0.0.4", "10.0.0.5", "10.0.0.6", "10.0.0.7"]
    assert len({round(scores[ip], 9) for ip in leaves}) == 1   # all leaves equivalent


def test_rumor_centrality_handles_a_single_node():
    tree = PropagationTree("t", nx.DiGraph([("a", "a")]), {"a": 0.0}, n_observations=2)
    assert rumor_centrality(tree)["a"] == 1.0


def test_first_timestamp_is_the_first_spy_baseline():
    df, source = seven_node_tree()
    scores = first_timestamp(build_trees(df)["tx"])
    assert max(scores, key=scores.get) == source


def test_timestamp_weighted_blends_both_signals():
    df, _ = seven_node_tree()
    tree = build_trees(df)["tx"]
    centrality, timing = rumor_centrality(tree), first_timestamp(tree)
    blended = timestamp_weighted_centrality(tree, CFG)
    p = CFG["engines"]["propagation"]
    for ip in blended:
        assert blended[ip] == pytest.approx(
            p["centrality_weight"] * centrality[ip] + p["timing_weight"] * timing[ip])


# --- the required relay-penalty check ------------------------------------
def test_a_known_relay_seen_slightly_earlier_does_not_outrank_a_central_residential_ip():
    """A public node forwards everyone's transactions; being early there is
    expected, not incriminating."""
    relay = "10.9.9.9"
    df = pd.DataFrame([
        row("tx", relay, "10.0.0.1", 0),               # relay seen first...
        row("tx", "10.0.0.1", "10.0.0.2", 1),          # ...but .1 sits at the centre
        row("tx", "10.0.0.1", "10.0.0.3", 2),
        row("tx", "10.0.0.2", "10.0.0.4", 3),
        row("tx", "10.0.0.3", "10.0.0.5", 4)])
    tree = build_trees(df)["tx"]
    intel = intel_with(relay=[relay])
    assert classify_ip(relay, intel=intel).ip_class == KNOWN_RELAY

    unweighted = first_timestamp(tree)
    assert max(unweighted, key=unweighted.get) == relay, "fixture should favour the relay"

    estimate = estimate_origin(tree, intel, CFG, "timestamp_weighted_centrality")
    assert estimate.ip != relay, "a known relay was ranked first"
    assert estimate.ip_class == RESIDENTIAL


def _mixed_class_tree():
    tree = build_trees(pd.DataFrame([row("tx", "10.0.0.1", "10.0.0.2", 1),
                                     row("tx", "10.0.0.2", "10.0.0.3", 2)]))["tx"]
    intel = intel_with(relay=["10.0.0.1"], tor=["10.0.0.2"], hosting=["10.0.0.3"])
    return tree, intel, {ip: 1.0 for ip in tree.ips}


def test_the_split_filter_penalises_relays_only():
    """Tor and hosting keep their rank: a masked broadcast really does start there."""
    tree, intel, flat = _mixed_class_tree()
    weighted, classified = apply_class_weights(flat, tree, intel, CFG, "split")
    assert weighted["10.0.0.1"] < weighted["10.0.0.2"] == weighted["10.0.0.3"] == 1.0
    assert classified["10.0.0.1"].ip_class == KNOWN_RELAY
    assert classified["10.0.0.2"].ip_class == TOR_EXIT
    assert classified["10.0.0.3"].ip_class == HOSTING


def test_the_old_combined_filter_still_penalises_all_three_in_order():
    tree, intel, flat = _mixed_class_tree()
    weighted, _ = apply_class_weights(flat, tree, intel, CFG, "combined")
    assert weighted["10.0.0.1"] < weighted["10.0.0.2"] < weighted["10.0.0.3"] < 1.0


def test_an_anonymized_entry_point_keeps_its_rank_and_loses_attribution_confidence():
    """The discount moved from the ranking to what correlation may treat as evidence."""
    tree, intel, _ = _mixed_class_tree()
    estimate = estimate_origin(tree, intel, CFG, "first_timestamp", "split")
    assert estimate.ip_class in (TOR_EXIT, HOSTING, RESIDENTIAL, KNOWN_RELAY)
    if estimate.anonymized_entry_point:
        factor = CFG["engines"]["propagation"]["origin_filter"]["attribution_confidence_factor"]
        assert estimate.attribution_confidence == pytest.approx(
            round(estimate.confidence * factor, 4))
        assert any("anonymized entry point" in e for e in estimate.evidence)
    else:
        assert estimate.attribution_confidence == estimate.confidence


# --- confidence -----------------------------------------------------------
def test_confidence_rises_with_observations_and_with_a_clear_winner():
    clear = [("a", 1.0), ("b", 0.05)]
    muddy = [("a", 1.0), ("b", 0.95), ("c", 0.9)]
    assert confidence_of(clear, 10) > confidence_of(muddy, 10)
    assert confidence_of(clear, 2) < confidence_of(clear, 20)
    assert 0.0 <= confidence_of(muddy, 1) <= 1.0


# --- the required degraded-mode check ------------------------------------
def test_single_row_input_falls_back_without_crashing():
    df = pd.DataFrame([row("only", "10.0.0.1", "10.0.0.2", 0)])
    origins, status = estimate_all(df, intel_with(), CFG)
    assert len(origins) == 1
    assert origins.iloc[0]["estimator_used"] == "first_timestamp"
    assert origins.iloc[0]["degraded"]
    assert origins.iloc[0]["confidence"] == CFG["engines"]["propagation"]["single_row_confidence"]
    assert origins.iloc[0]["estimated_origin_ip"] == "10.0.0.1"


def test_whole_dataset_single_row_is_reported_as_degraded_mode():
    df = pd.DataFrame([row(f"t{i}", f"10.0.0.{i}", "10.9.9.9", i) for i in range(5)])
    status = degraded_mode(df)
    assert status["degraded"] and "single relay record" in status["reason"]
    assert status["multi_row_transactions"] == 0 and status["transactions"] == 5


def test_a_dataset_with_structure_is_not_degraded():
    df, _ = seven_node_tree()
    status = degraded_mode(df)
    assert not status["degraded"] and status["reason"] is None
    assert status["mean_observations"] == 6.0


def test_empty_input_is_survivable():
    empty = pd.DataFrame(columns=["txid", "src_ip", "dst_ip", "timestamp", "asn"])
    assert degraded_mode(empty)["degraded"]


# --- intel classification -------------------------------------------------
def test_classification_precedence_and_evidence():
    intel = intel_with(relay=["10.0.0.1"], tor=["10.0.0.2"], hosting=["10.0.0.3"])
    assert intel.classify("10.0.0.1").ip_class == KNOWN_RELAY
    assert "reachable Bitcoin node" in intel.classify("10.0.0.1").evidence[0]
    assert intel.classify("10.0.0.2").ip_class == TOR_EXIT
    assert intel.classify("10.0.0.3").ip_class == HOSTING
    residential = intel.classify("117.200.1.1")
    assert residential.ip_class == RESIDENTIAL
    assert residential.evidence and not residential.is_shared_infrastructure


def test_hosting_asn_alone_is_enough():
    intel = intel_with()
    assert intel.classify("1.2.3.4", asn=14061).ip_class == HOSTING
    assert intel.classify("1.2.3.4", asn=9829).ip_class == RESIDENTIAL


def test_missing_intel_files_degrade_to_config_only():
    intel = IpIntel(intel_dir="/nonexistent", cfg=CFG)
    assert not intel.available
    assert intel.hosting_asns == set(CFG["geoip"]["high_risk_asns"])
    assert intel.classify("8.8.8.8").ip_class == RESIDENTIAL   # unknown, not guessed


# --- end to end -----------------------------------------------------------
@pytest.fixture(scope="module")
def datasets(tmp_path_factory):
    """One dataset per relay-observation rate, built by `eval.datasets`.

    The same builder the report uses, so a change to how evaluation datasets are
    generated cannot leave the test measuring something else. Smaller than the
    canonical sizes — this is a test, and the published figures come from
    `eval/results.md`, not from here.
    """
    from eval.datasets import build

    cfg = json.loads(json.dumps(CFG))
    cfg["eval"].update({"n_actors": 150, "n_transactions": 900})
    base = tmp_path_factory.mktemp("prop")
    return {rate: build(rate, False, CFG["eval"]["seed"], cfg, root=base)
            for rate in (0.1, 0.3, 0.6)}


def test_the_published_accuracy_table_holds(datasets):
    """The invariants `eval/results.md` section 2 depends on.

    Scored with `eval.origin.score_estimator` and `eval.origin.ceiling` — the
    functions that generate the published table — rather than a second copy of
    the arithmetic living in a test. The numbers here are from a smaller
    dataset than the canonical one and are deliberately not asserted against
    fixed values: the report owns the figures, this owns the properties they
    must have.
    """
    from eval import origin as origin_eval

    for rate, dataset in sorted(datasets.items()):
        cap, n_trees = origin_eval.ceiling(dataset)
        assert n_trees > 0, "no multi-hop transactions to score"
        assert 0.0 <= cap <= 1.0
        for name in ESTIMATORS:
            result = origin_eval.score_estimator(dataset, name, CFG)
            assert result["n"] > 0
            assert result["top1"] <= cap + 1e-9, (
                f"{name} at rate {rate} beat the ceiling — impossible, the true origin "
                "is not in the tree for the rest")
            assert result["top3"] >= result["top1"] - 1e-9
            assert 0.0 <= result["conditional_top1"] <= 1.0
            # Conditional accuracy is accuracy over a subset where the answer is
            # present, so it can only be higher.
            assert result["conditional_top1"] >= result["top1"] - 1e-9


def test_the_rate_filter_cross_covers_every_combination(datasets):
    """Section 2's full cross is complete and internally consistent."""
    from eval import origin as origin_eval

    cross = origin_eval.rate_filter_cross(datasets, CFG)
    assert len(cross) == len(datasets) * len(ESTIMATORS) * len(origin_eval.FILTER_MODES)
    assert (cross["top-3"] >= cross["top-1"] - 1e-9).all()
    assert (cross["top-1"] <= cross["ceiling"] + 1e-9).all()
    # A higher observation rate cannot lower the ceiling: more relays observed
    # is strictly more chances for the true origin to appear.
    ceilings = cross.groupby("rate")["ceiling"].first()
    assert list(ceilings) == sorted(ceilings), "the ceiling fell as observation rose"


def test_cli_writes_origins_parquet(datasets, tmp_path):
    dataset = datasets[0.3]
    summary = run(dataset.transactions, tmp_path / "origins.parquet",
                  node_intel=dataset.raw, cfg=CFG)
    origins = pd.read_parquet(tmp_path / "origins.parquet")
    assert len(origins) == summary["transactions"]
    assert set(origins.columns) >= {"txid", "estimated_origin_ip", "ip_class",
                                    "estimator_used", "confidence", "runner_up_ips",
                                    "n_observations"}
    assert origins["confidence"].between(0, 1).all()
    assert not summary["degraded_mode"]["degraded"]
    assert origins["runner_up_ips"].map(len).max() <= CFG["engines"]["propagation"]["runner_ups"]
