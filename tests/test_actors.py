"""fusion/actors.py: joining, scoring through the one stacker, and naming."""

from __future__ import annotations

import inspect

import pandas as pd

import config
from fusion import actors as A
from fusion.stacker import SIGNALS, Stacker

CFG = config.load()
STACKER = Stacker(fallback_weights={s: 1.0 for s in SIGNALS})


def signals(**by_entity):
    rows = [{"entity_id": e, **dict.fromkeys(SIGNALS, 0.0), **v} for e, v in by_entity.items()]
    return pd.DataFrame(rows)


def link(peer, cluster, basis="both", confidence=0.6, ip_class="residential_or_unknown",
         reasons=(), kind="IP"):
    return {"peer": peer, "peer_kind": kind, "ip_class": ip_class, "cluster_id": cluster,
            "basis": basis, "confidence": confidence, "by_basis": {}, "origin_tiers": ["PASS"],
            "evidence": [{"basis": "origination", "txid": f"t-{peer}-{cluster}",
                          "probability": confidence, "tier": "PASS", "reasons": list(reasons),
                          "rows": [{"row": 1}]}],
            "evidence_total": 1, "evidence_chain": "raw rows -> transaction -> inputs -> cluster"}


def actor_of(frame, entity):
    return frame[frame["members"].map(lambda m: entity in m)].iloc[0]


def test_a_corroborated_residential_link_joins_two_clusters():
    s = signals(c1={"rule_score": 0.9}, c2={"taint_score": 0.5}, c3={})
    out = A.build(s, STACKER, [link("10.0.0.1", "c1", confidence=0.8),
                               link("10.0.0.1", "c2", confidence=0.4)], CFG)
    joined = actor_of(out, "c1")
    assert joined["members"] == ["c1", "c2"] and joined["peers"] == ["10.0.0.1"]
    assert joined["membership_confidence"] == 0.4          # the weakest link
    assert actor_of(out, "c3")["members"] == ["c3"]        # zero peers is an actor too


def test_shared_infrastructure_and_lead_only_links_attach_but_never_join():
    s = signals(c1={"rule_score": 0.9}, c2={"rule_score": 0.1})
    for lk in ([link("5.5.5.5", "c1", ip_class="hosting_vpn"), link("5.5.5.5", "c2", ip_class="hosting_vpn")],
               [link("10.0.0.2", "c1", basis="correlation lead"),
                link("10.0.0.2", "c2", basis="correlation lead", confidence=0.05)]):
        out = A.build(s, STACKER, lk, CFG)
        assert len(out) == 2, "clusters stay separate actors"
        weak = actor_of(out, "c2")
        assert weak["peers"] and not weak["links"][0]["joins"]
        assert weak["membership_confidence"] == lk[1]["confidence"]   # lowered, not dropped


def test_a_coinjoin_qualified_origination_never_joins_participants():
    s = signals(c1={"rule_score": 0.9}, c2={})
    mix = [link("10.0.0.3", "c1", reasons=["COINJOIN"]), link("10.0.0.3", "c2", reasons=["COINJOIN"])]
    assert not any(A.may_join(lk) for lk in mix)
    out = A.build(s, STACKER, mix, CFG)
    assert all(len(m) == 1 for m in out["members"])
    assert all(not r for r in out["links"]), "a COINJOIN-only link is not a membership link"


def test_the_actor_is_scored_by_the_same_stacker_on_weighted_signals():
    s = signals(c1={"rule_score": 0.9}, c2={"taint_score": 0.8})
    out = A.build(s, STACKER, [link("10.0.0.1", "c1", confidence=0.9),
                               link("10.0.0.1", "c2", confidence=0.5)], CFG)
    joined = actor_of(out, "c1")
    expected = dict.fromkeys(SIGNALS, 0.0) | {"rule_score": 0.9, "taint_score": 0.8 * 0.5}
    assert joined["signals"] == {k: round(v, 4) for k, v in expected.items()}
    assert abs(joined["risk_score"] - STACKER.score(pd.DataFrame([expected]))[0]) < 1e-12
    alone = A.build(s, STACKER, [], CFG)
    assert abs(actor_of(alone, "c1")["risk_score"] - STACKER.score(s)[0]) < 1e-12


def test_actors_are_handles_not_people():
    out = A.build(signals(c1={}, c2={}), STACKER, [], CFG)
    assert all(n == f"actor {i}" and i.startswith("A-") for n, i in zip(out["name"], out["actor_id"]))
    assert "does not name or imply a person or an organisation" in A.STATEMENT
    for word in ("owner", "person ", "suspect", "operated by", "belongs to"):
        assert word not in out["name"].str.cat().lower()


def test_fingerprints_contribute_nothing_to_membership():
    source = inspect.getsource(A)
    assert "import fingerprint" not in source and "fingerprint." not in source


def test_the_seed_sweep_pairs_queues_per_seed_and_drops_measures_a_seed_lacks():
    from eval.actor_queue import summarise_power
    quality = {k: 0.0 for k in ("illicit operations present", "alert count reduction",
                                "actor purity (alerted, mean)",
                                "wrong-merge rate (alerted multi-cluster actors)",
                                "wrong-merge rate (all multi-cluster actors)",
                                "entity alerts", "actor alerts")}
    per = []
    for seed, (before, after) in enumerate([(0.5, 0.6), (0.6, 0.7), (0.7, 0.9)]):
        cols = {"items": [10, 8], "precision@10": [before, after]}
        if seed:
            cols["reviewed to find 3"] = [5, 4]
        table = pd.DataFrame(cols, index=pd.Index(["entity", "actor"], name="queue"))
        per.append({"condition": "standard", "seed": seed, "table": table,
                    "quality": {**quality, "alerted actors joining 2+ clusters": 1}})
    s = summarise_power(per)
    assert "reviewed to find 3" not in s["queues"].columns
    assert s["queues"].set_index("queue").loc["entity", "precision@10"] == "0.600 [0.352, 0.848]"
    paired = s["paired"].set_index("measure")["actor − entity"]
    assert paired["precision@10"].startswith("0.133 [")      # (0.1 + 0.1 + 0.2) / 3
    assert s["quality"]["alerted multi-cluster actors (total)"].iloc[0] == 3


def test_an_actor_link_scores_as_its_peer_page_does(tmp_path_factory):
    """The actor view and the peer page show one link's confidence, so they
    must compute it from the same evidence. write_actors once built its links
    without the dataset's node_intel.json, so the generator's relays read as
    residential and every lead scored about half what the peer page showed."""
    import json

    from engines.correlation import profile as P
    from eval.datasets import build
    from fusion.pipeline import collect_signals, write_actors
    from fusion.stacker import default_weights
    from ingest.ip_intel import load_intel

    cfg = json.loads(json.dumps(config.load()))
    cfg["eval"]["n_actors"], cfg["eval"]["n_transactions"] = 200, 1200
    dataset = build(cfg["eval"]["default_rate"], False, 7, cfg,
                    root=tmp_path_factory.mktemp("actor-leads"), name_prefix="leads")
    cfg["ingest"]["input_dir"] = str(dataset.raw)
    cfg["features"]["relay_path"] = str(dataset.directory / "no-relay-matrix.parquet")
    df = dataset.frame()
    bundle = collect_signals(df, cfg)
    stacker = Stacker(fallback_weights=default_weights(cfg))
    out = dataset.directory / "actors.json"
    write_actors(df, bundle, stacker, pd.DataFrame({"entity_id": []}), cfg, out)

    src = P.build_sources(cfg, df, None, None, bundle["features"],
                          load_intel(None, dataset.raw, cfg))
    compared = 0
    for actor in json.loads(out.read_text())["actors"]:
        for lk in actor["links"]:
            mine = lk["by_basis"].get("correlation lead")
            if not mine:
                continue
            page = P.peer_profile(lk["peer"], src, cfg)
            theirs = next(c["by_basis"]["correlation lead"] for c in page["linked_clusters"]
                          if c["cluster_id"] == lk["cluster_id"])
            assert mine["confidence"] == theirs["confidence"], (lk["peer"], lk["cluster_id"])
            compared += 1
    assert compared
