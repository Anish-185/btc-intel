"""Hand-built transaction sets where the right answer is known by construction.

The two that matter: CoinJoin participants must NOT be merged, and a two-hop
peeling chain MUST be.
"""

from __future__ import annotations

import json

import networkx as nx
import pytest

import config
from graph.builder import (IP, TRANSACTION, WALLET, Tx, build_graph, graph_transactions,
                           nodes_of_type, summary)
from graph.clustering import (DSU, TxIndex, change_address_heuristic, cluster_collapse_guard,
                              cluster_wallets, common_input_ownership, h_address_reuse,
                              h_address_type, h_optimal_change, h_peeling_chain, is_coinjoin,
                              is_peeling_chain, looks_like_peeling, script_type_of)
from graph.entity_graph import build_entity_graph

CFG = config.load()

# Addresses whose prefix encodes the script type, as in real data.
def addr(name: str, kind: str = "p2wpkh") -> str:
    """Readable stand-in addresses. Padded with 'z' so w1 and w10 stay distinct."""
    prefix = {"p2wpkh": "bc1q", "p2pkh": "1", "p2sh": "3", "p2tr": "bc1p"}[kind]
    return prefix + name.ljust(34, "z")


def tx(txid, inputs, outputs, script_type="p2wpkh", ips=()) -> Tx:
    return Tx(txid, list(inputs), list(outputs), fee=0.001, script_type=script_type,
              timestamp=None, ips=list(ips))


def cfg_with(**graph_overrides) -> dict:
    """A copy of config.yaml with some graph settings changed."""
    cfg = json.loads(json.dumps(CFG))
    for key, value in graph_overrides.items():
        if isinstance(value, dict):
            cfg["graph"][key].update(value)
        else:
            cfg["graph"][key] = value
    return cfg


# --- union-find -----------------------------------------------------------
def test_dsu_merges_transitively_and_reports_groups():
    d = DSU()
    d.union("a", "b")
    d.union("b", "c")
    d.add("z")
    assert d.find("a") == d.find("c") != d.find("z")
    assert sorted(len(g) for g in d.groups().values()) == [1, 3]


def test_dsu_union_is_idempotent():
    d = DSU()
    for _ in range(3):
        d.union("a", "b")
    assert len(d.groups()) == 1


# --- script types ---------------------------------------------------------
@pytest.mark.parametrize("address,kind", [
    ("bc1q" + "0" * 38, "p2wpkh"), ("bc1q" + "0" * 58, "p2wsh"),
    ("bc1p" + "0" * 58, "p2tr"), ("1" + "0" * 33, "p2pkh"), ("3" + "0" * 33, "p2sh"),
    ("garbage", "")])
def test_script_type_is_read_from_the_address(address, kind):
    assert script_type_of(address) == kind


# --- CoinJoin: must NOT merge --------------------------------------------
def coinjoin_tx(n=5, denom=0.1) -> Tx:
    return tx("cj", [(addr(f"in{i}"), denom) for i in range(n)],
              [(addr(f"out{i}"), denom * 0.999) for i in range(n)])


def test_coinjoin_is_detected():
    assert is_coinjoin(coinjoin_tx(), CFG)
    assert is_coinjoin(coinjoin_tx(n=3), CFG)


def test_coinjoin_suppresses_common_input_ownership():
    assert common_input_ownership(coinjoin_tx(), CFG) == set()


def test_coinjoin_participants_are_never_merged():
    cl = cluster_wallets([coinjoin_tx(n=6)], CFG)
    ins = [addr(f"in{i}") for i in range(6)]
    assert "cj" in cl.coinjoins
    assert len({cl.cluster_of(a) for a in ins}) == 6, "CoinJoin inputs were merged"
    for a, b in zip(ins, ins[1:]):
        assert not cl.same_cluster(a, b)


def test_coinjoin_gets_no_change_guess():
    assert change_address_heuristic(coinjoin_tx(), TxIndex([coinjoin_tx()]), CFG) is None


def test_ordinary_multi_input_transaction_is_not_a_coinjoin_and_is_merged():
    """Same input count, but the outputs are not a near-equal group."""
    t = tx("t", [(addr("a"), 1.0), (addr("b"), 2.0), (addr("c"), 0.5)],
           [(addr("x"), 3.1), (addr("y"), 0.2), (addr("z"), 0.19)])
    assert not is_coinjoin(t, CFG)
    assert common_input_ownership(t, CFG) == {addr("a"), addr("b"), addr("c")}
    cl = cluster_wallets([t], CFG)
    assert cl.same_cluster(addr("a"), addr("b"), addr("c"))


def test_dust_equal_outputs_are_not_a_coinjoin():
    t = tx("dust", [(addr(f"i{i}"), 0.001) for i in range(4)],
           [(addr(f"o{i}"), 0.00001) for i in range(4)])
    assert not is_coinjoin(t, CFG)


def test_coinjoin_thresholds_come_from_config():
    small = tx("small", [(addr("a"), 1.0), (addr("b"), 1.0)],
               [(addr("x"), 0.99), (addr("y"), 0.99)])
    assert not is_coinjoin(small, CFG)                       # 2 in / 2 out, below default
    assert is_coinjoin(small, cfg_with(coinjoin={"min_inputs": 2, "min_outputs": 2,
                                                 "min_equal_outputs": 2}))


# --- peeling chain: MUST merge -------------------------------------------
def peel_chain() -> list[Tx]:
    """A -> (peel X, change B) -> (peel Y, change C). Truth: {A, B, C} is one
    entity; X and Y belong to whoever was paid."""
    a, b, c = addr("collector"), addr("change1"), addr("change2")
    x, y = addr("peel1", "p2pkh"), addr("peel2", "p2pkh")
    return [tx("p1", [(a, 10.0)], [(x, 0.5), (b, 9.4)]),
            tx("p2", [(b, 9.4)], [(y, 0.4), (c, 8.9)])]


def test_peeling_shape_and_chain_detection():
    txs = peel_chain()
    idx = TxIndex(txs)
    assert all(looks_like_peeling(t) for t in txs)
    assert all(is_peeling_chain(t, idx) for t in txs)
    assert not looks_like_peeling(tx("t", [(addr("a"), 1), (addr("b"), 1)], [(addr("c"), 2)]))


def test_lone_peel_shaped_transaction_is_not_a_chain():
    """One input, two outputs, but no peel-shaped neighbour — not a chain."""
    lone = tx("lone", [(addr("a"), 1.0)], [(addr("x"), 0.4), (addr("b"), 0.59)])
    feeder = tx("feeder", [(addr("s1"), 0.5), (addr("s2"), 0.6)], [(addr("a"), 1.0)])
    assert not is_peeling_chain(lone, TxIndex([feeder, lone]))


def test_two_hop_peeling_chain_is_clustered():
    txs = peel_chain()
    cl = cluster_wallets(txs, CFG)
    a, b, c = addr("collector"), addr("change1"), addr("change2")
    assert cl.same_cluster(a, b, c), "peeling chain was not clustered"
    assert cl.change_outputs == {"p1": b, "p2": c}
    for peel in (addr("peel1", "p2pkh"), addr("peel2", "p2pkh")):
        assert not cl.same_cluster(a, peel), "the peeled-off payment was merged in"


def test_peel_chain_collapses_to_one_entity():
    txs = peel_chain()
    cl = cluster_wallets(txs, CFG)
    eg = build_entity_graph(txs, cl)
    collector = cl.cluster_of(addr("collector"))
    assert eg.nodes[collector]["wallets"] == 3
    # two payments out, and the internal change moves are not drawn as links
    assert eg.out_degree(collector) == 2
    assert not eg.has_edge(collector, collector)
    assert eg.nodes[collector]["internal_txs"] >= 1


# --- individual sub-heuristics -------------------------------------------
def test_address_reuse_candidates():
    t = tx("t", [(addr("a"), 5.0)], [(addr("b"), 2.0), (addr("a"), 2.9)])
    assert h_address_reuse(t, TxIndex([t])) == {1}


def test_address_type_candidates():
    t = tx("t", [(addr("a"), 5.0)], [(addr("b", "p2pkh"), 2.0), (addr("c"), 2.9)])
    assert h_address_type(t, TxIndex([t])) == {1}


def test_address_type_gives_no_signal_when_every_output_matches():
    t = tx("t", [(addr("a"), 5.0)], [(addr("b"), 2.0), (addr("c"), 2.9)])
    assert h_address_type(t, TxIndex([t])) == set()


def test_optimal_change_candidates():
    t = tx("t", [(addr("a"), 5.0), (addr("b"), 3.0)], [(addr("x"), 6.0), (addr("y"), 1.9)])
    assert h_optimal_change(t, TxIndex([t])) == {1}


def test_optimal_change_gives_no_signal_when_every_output_is_smaller():
    t = tx("t", [(addr("a"), 10.0)], [(addr("x"), 0.5), (addr("y"), 9.4)])
    assert h_optimal_change(t, TxIndex([t])) == set()


def test_peeling_chain_candidates_include_unspent_outputs():
    txs = peel_chain()
    assert h_peeling_chain(txs[0], TxIndex(txs)) == {0, 1}
    assert h_peeling_chain(tx("nope", [(addr("a"), 1.0)], [(addr("x"), 0.9)]),
                           TxIndex([])) == set()


# --- the vote -------------------------------------------------------------
def test_change_vote_refuses_to_guess_on_a_tie():
    """Both outputs equally plausible — no link is better than a wrong one."""
    t = tx("t", [(addr("a"), 10.0)], [(addr("x"), 4.9), (addr("y"), 5.0)])
    assert change_address_heuristic(t, TxIndex([t]), CFG) is None


def test_change_vote_respects_min_votes():
    t = tx("t", [(addr("a"), 5.0)], [(addr("b", "p2pkh"), 2.0), (addr("c"), 2.9)])
    assert change_address_heuristic(t, TxIndex([t]), CFG) is None       # 1 vote < min 2
    assert change_address_heuristic(t, TxIndex([t]), cfg_with(change={"min_votes": 1})) == addr("c")


def test_single_output_transaction_has_no_change():
    t = tx("t", [(addr("a"), 1.0)], [(addr("b"), 0.99)])
    assert change_address_heuristic(t, TxIndex([t]), CFG) is None


def test_change_detection_can_be_switched_off_in_config():
    txs = peel_chain()
    cl = cluster_wallets(txs, cfg_with(change_detection=False))
    assert not cl.same_cluster(addr("collector"), addr("change1"))


# --- collapse guard -------------------------------------------------------
def test_collapse_guard_flags_oversized_clusters():
    clusters = {"big": {f"w{i}" for i in range(600)}, "small": {"a", "b"}}
    flags = cluster_collapse_guard(clusters, CFG)
    assert set(flags) == {"big"}
    assert flags["big"] == CFG["graph"]["collapse_guard"]["reason"]
    assert "needs review" in flags["big"]


def test_collapse_guard_threshold_is_configurable_and_flags_not_drops():
    """A flagged cluster is still returned — it is marked, never silently cut."""
    big = tx("big", [(addr(f"w{i}"), 1.0) for i in range(12)], [(addr("out"), 11.0),
                                                                (addr("rest"), 0.9)])
    cl = cluster_wallets([big], cfg_with(collapse_guard={"max_cluster_wallets": 5}))
    assert cl.suspicious and len(cl.clusters[cl.suspicious[0]]) >= 12
    assert cl.same_cluster(addr("w0"), addr("w11"))


# --- builder --------------------------------------------------------------
def test_graph_has_three_node_types_and_the_right_edges():
    t = tx("t1", [(addr("a"), 1.0)], [(addr("b"), 0.5), (addr("c"), 0.49)],
           script_type="p2wpkh", ips=["10.0.0.1", "10.0.0.2"])
    g = build_graph([t])
    assert isinstance(g, nx.MultiDiGraph)
    assert nodes_of_type(g, TRANSACTION) == ["t1"]
    assert set(nodes_of_type(g, WALLET)) == {addr("a"), addr("b"), addr("c")}
    assert set(nodes_of_type(g, IP)) == {"10.0.0.1", "10.0.0.2"}
    assert summary(g)["edges"] == {"broadcast": 2, "input": 1, "output": 2}
    e = g.edges[addr("a"), "t1", "in:0"]
    assert e["kind"] == "input" and e["amount"] == 1.0 and e["script_type"] == "p2wpkh"
    assert g.edges["t1", addr("b"), "out:0"]["amount"] == 0.5


def test_transactions_survive_a_graph_round_trip():
    txs = peel_chain()
    back = {t.txid: t for t in graph_transactions(build_graph(txs))}
    for original in txs:
        assert back[original.txid].inputs == original.inputs
        assert back[original.txid].outputs == original.outputs


# --- entity graph ---------------------------------------------------------
def test_entity_graph_keeps_coinjoin_participants_apart():
    cj = coinjoin_tx(n=4)
    cl = cluster_wallets([cj], CFG)
    eg = build_entity_graph([cj], cl)
    assert eg.number_of_nodes() == 8          # 4 inputs + 4 outputs, none merged
    assert eg.number_of_edges() == 16         # every sender linked to every receiver


def test_entity_edges_aggregate_value_and_keep_txids():
    a, b = addr("a"), addr("b")
    txs = [tx("t1", [(a, 1.0)], [(b, 0.9)]), tx("t2", [(a, 2.0)], [(b, 1.9)])]
    cl = cluster_wallets(txs, CFG)
    eg = build_entity_graph(txs, cl)
    edge = eg.edges[cl.cluster_of(a), cl.cluster_of(b)]
    assert edge["count"] == 2 and edge["value"] == pytest.approx(2.8)
    assert sorted(edge["txids"]) == ["t1", "t2"]


def test_entity_nodes_carry_flags_and_broadcast_ips():
    t = tx("t", [(addr(f"w{i}"), 1.0) for i in range(8)], [(addr("out"), 7.9)],
           ips=["10.0.0.1", "10.0.0.2"])
    cl = cluster_wallets([t], cfg_with(collapse_guard={"max_cluster_wallets": 3}))
    eg = build_entity_graph([t], cl)
    sender = cl.cluster_of(addr("w0"))
    assert eg.nodes[sender]["flag"] == CFG["graph"]["collapse_guard"]["reason"]
    assert eg.nodes[sender]["ips"] == ["10.0.0.1", "10.0.0.2"]
    assert eg.nodes[sender]["shared_ip_count"] == 2


# --- end to end against generated ground truth ---------------------------
def test_clustering_against_generated_ground_truth(tmp_path):
    from generator.main import build_parser, generate
    from ingest.pipeline import run as ingest_run
    from tests.test_ingest import stub_geo

    raw = tmp_path / "raw"
    args = build_parser().parse_args(["--n-actors", "150", "--n-transactions", "1200",
                                      "--output", str(raw), "--seed", "5", "--formats", "csv"])
    generate(args)
    ingest_run(raw, tmp_path / "t.parquet", tmp_path / "q.parquet", "csv", geo=stub_geo())

    from graph.builder import iter_transactions, load
    txs = list(iter_transactions(load(tmp_path / "t.parquet")))
    cl = cluster_wallets(txs, CFG)
    gt = json.loads((raw / "ground_truth.json").read_text())

    true_coinjoins = {t for t, m in gt["transactions"].items() if m["typology"] == "coinjoin"}
    assert cl.coinjoins == true_coinjoins, "CoinJoin detection disagrees with ground truth"

    impure = [c for c, members in cl.clusters.items()
              if len({gt["wallets"].get(w) for w in members}) > 1]
    assert len(impure) / len(cl.clusters) < 0.02, f"{len(impure)} clusters merged two entities"
    assert cl.change_outputs, "change detection found nothing on realistic data"
