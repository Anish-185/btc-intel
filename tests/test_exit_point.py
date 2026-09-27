"""analysis/exit_point.py and fusion.taint.trace: haircut and poison, CoinJoin
termination, untagged sinks, actors traced per member, and the packet."""

from __future__ import annotations

import ast
import inspect
import re
from datetime import UTC, datetime

import networkx as nx
import pytest

import config
from analysis import exit_point as X
from api import case_report
from fusion.taint import trace
from graph.clustering import Clustering
from intel.store import TagStore
from intel.tags import Tag

CFG = config.load()


def edge(g, a, b, value, mix=0, count=1, txid=None):
    g.add_edge(a, b, value=value, count=count, mix_count=mix, txids=[txid or f"t-{a}-{b}"],
               first_seen="2026-01-01T00:00:00Z", last_seen="2026-01-02T00:00:00Z")


def world():
    """S pays A 6 and B 4. A pays the exchange V 3 and keeps 3; B sends 4 into
    a CoinJoin M; M pays V2 (another exchange) 4. U is an untagged sink paid
    by A... no: A pays U 3. C (in cluster c) is only joined to S by an actor."""
    g = nx.DiGraph()
    edge(g, "S", "A", 6.0)
    edge(g, "S", "B", 4.0)
    edge(g, "A", "V", 3.0)
    edge(g, "A", "U", 3.0)
    edge(g, "B", "M", 4.0, mix=1, txid="coinjoin-1")
    edge(g, "M", "V2", 4.0)
    edge(g, "C", "V", 1.0)
    clusters = {"S": {"s1"}, "A": {"a1", "a2"}, "B": {"b1"}, "V": {"v1", "v2"},
                "U": {"u1"}, "M": {"m1"}, "V2": {"w1"}, "C": {"c1"}}
    clustering = Clustering(wallet_to_cluster={w: c for c, ws in clusters.items() for w in ws},
                            clusters=clusters, confidence={"A": 0.5})

    class Features:
        def entity_of(self, wallet):
            return clustering.cluster_of(wallet) or wallet
    features = Features()
    features.clustering = clustering
    store = TagStore(risk=CFG["tags"]["risk"])
    tag = {"source": "simulated", "reference": "generator ground_truth.json, cluster X",
           "collected": "2026-01-01", "confidence": 1.0, "applies_to": "cluster"}
    store.add("demo", [Tag(subject="v1", label="simulated exchange", category="exchange/VASP", **tag),
                       Tag(subject="w1", label="simulated exchange 2", category="exchange/VASP", **tag)])
    return g, features, store


def test_haircut_and_poison_amounts_and_path_confidence():
    g, f, _ = world()
    t = trace(g, "S", "haircut", f.clustering.confidence, stop={"V"}, cfg=CFG)
    assert t.seed_amount == 10.0
    assert t.received["A"] == pytest.approx(6.0)
    assert t.received["V"] == pytest.approx(3.0)          # 6 x 3/6
    (best,) = t.paths["V"][:1]
    assert best["entities"] == ["S", "A", "V"]
    assert best["confidence"] == pytest.approx(0.6 * 0.5 * 0.5)   # fractions x A's merge
    p = trace(g, "S", "poison", f.clustering.confidence, stop={"V"}, cfg=CFG)
    assert p.received["V"] == pytest.approx(3.0) and p.paths["V"][0]["confidence"] == 0.5


def test_tracing_stops_at_a_coinjoin_and_says_so():
    g, f, store = world()
    result = X.trace_entity("S", g, f, store, {}, CFG)
    reached = {c["entity_id"] for c in result["candidates"]}
    assert "V2" not in reached and "M" not in {s["entity_id"] for s in result["sinks"]}
    for model in ("haircut", "poison"):
        (mix,) = result["mixes"][model]
        assert mix["from"] == "B" and mix["txids"] == ["coinjoin-1"]
    assert reached == {"V"}


def test_a_partly_mixed_edge_is_followed_and_the_hop_says_so():
    g, f, store = world()
    g.edges["B", "M"].update(count=2, mix_count=1)
    result = X.trace_entity("S", g, f, store, {}, CFG)
    v2 = next(c for c in result["candidates"] if c["entity_id"] == "V2")
    hop = v2["models"]["haircut"]["paths"][0]["hops"][1]
    assert "CoinJoins, but the edge is not only mixes" in hop["reason"]


def test_untagged_sinks_are_never_named_as_services():
    g, f, store = world()
    result = X.trace_entity("S", g, f, store, {}, CFG)
    (sink,) = [s for s in result["sinks"] if s["entity_id"] == "U"]
    assert sink["label"] == "untagged sink" and sink["tags"] == []
    assert all(c["tags"] and all(t["category"] == "exchange/VASP" for t in c["tags"])
               for c in result["candidates"])
    assert "U" not in {c["entity_id"] for c in result["candidates"]}


def test_an_actor_is_traced_per_member_and_its_join_is_never_a_flow():
    g, f, store = world()
    actor = {"actor_id": "A-1", "members": ["S", "C"]}
    result = X.exit_points("actor", "A-1", g, f, store, {}, actor, CFG)
    s_trace, c_trace = result["traces"]
    assert (s_trace["seed"], c_trace["seed"]) == ("S", "C")
    assert c_trace["seed_amount"] == 1.0                     # C's own outflow only
    assert "U" not in {x["entity_id"] for x in c_trace["sinks"]}
    assert not g.has_edge("S", "C") and not g.has_edge("C", "S")
    for module in (X, __import__("fusion.taint", fromlist=["x"])):
        imported = {n.module for n in ast.walk(ast.parse(inspect.getsource(module)))
                    if isinstance(n, ast.ImportFrom)}
        assert not any("actors" in (m or "") for m in imported)


def test_candidates_carry_tag_source_date_window_and_evidence_hash():
    g, f, store = world()
    (cand,) = X.trace_entity("S", g, f, store, {}, CFG)["candidates"]
    (tag,) = cand["tags"]
    assert tag["source"] == "simulated" and tag["collected"] == "2026-01-01" and tag["simulated"]
    assert cand["time_window"] == ["2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z"]
    assert len(cand["evidence_sha256"]) == 64 and cand["rank"] == 1
    assert set(cand["models"]) == {"haircut", "poison"}


def _first_page_text(pdf: bytes) -> str:
    """Page one's content stream, from an uncompressed render."""
    return re.findall(rb"stream\r?\n(.*?)\r?\nendstream", pdf, re.DOTALL)[0].decode("latin-1")


def test_the_packet_states_its_limits_on_the_first_page(monkeypatch):
    from reportlab import rl_config
    monkeypatch.setattr(rl_config, "pageCompression", 0)
    g, f, store = world()
    result = X.exit_points("entity", "S", g, f, store, {}, None, CFG)
    assert result["simulated_tags"] is False          # a TagStore built in memory
    result["simulated_tags"] = True
    lines = case_report.packet_disclaimers(result)
    assert lines[0].startswith("An investigative lead, not proof of identity or ownership")
    assert "Simulated tags are simulated" in lines[1]
    assert "sealed (tamper-evident)" in lines[2] and "not signed" in lines[2]
    pdf = case_report.render_packet(result, datetime.now(UTC), {"head": "h", "files": []})
    first_page = _first_page_text(pdf)
    for phrase in ("not proof of identity or ownership", "Simulated tags are simulated",
                   "not signed"):
        assert phrase in first_page


def test_the_evaluation_never_reads_the_operator_tag_store(tmp_path_factory, monkeypatch):
    """Ground-truth tags are built in memory; loading data/tags would fail here."""
    import intel.bundle
    import intel.store
    from eval import exit_eval
    from eval.datasets import build

    def refuse(*_, **__):
        raise AssertionError("the evaluation read the tag store")
    monkeypatch.setattr(intel.store, "load", refuse)
    monkeypatch.setattr(intel.bundle, "store_dir", refuse)
    cfg = config.load()
    small = {**cfg, "eval": {**cfg["eval"], "n_actors": 200, "n_transactions": 1200}}
    dataset = build(cfg["eval"]["default_rate"], False, 11, small,
                    root=tmp_path_factory.mktemp("exit"), name_prefix="exit-eval")
    result = exit_eval.evaluate(dataset, cfg)
    ops = result["operations"]
    assert len(ops) and set(ops["model"]) == {"haircut", "poison"}
    summary = exit_eval.summarise([result])
    assert {"top1", "top3", "reached"} <= set(summary["ranking"].columns)
