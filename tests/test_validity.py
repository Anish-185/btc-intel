"""The validity layer: every detector can fire and can fail, the generator
produces what the detectors look for, and a failed check abstains through the
one existing rule. The API-boundary assertion is in tests/test_api.py, beside
the pipeline-backed client it needs.
"""

from __future__ import annotations

import random

import pandas as pd
import pytest

import config
from analysis import validity as v
from eval import origin as origin_eval
from engines.propagation.estimators import low_confidence_origin
from fusion.taint import propagate
from generator.net import build_net
from generator.typologies import shape
from graph.builder import Tx
from graph.clustering import cluster_wallets
from graph.entity_graph import build_entity_graph
from origination import corpus
from p2p import capture_reader as cr

CFG = config.load()
ONION = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion"


def cj_tx(txid="cj", n=6) -> Tx:
    return Tx(txid, [(f"in{i}", 0.1) for i in range(n)],
              [(f"out{i}", 0.0999) for i in range(n)])


# --- each detector fires, and each can fail -----------------------------------
def test_degenerate_fires_on_one_candidate_and_not_on_two():
    assert v.degenerate(0).reason == v.degenerate(1).reason == v.DEGENERATE
    assert v.degenerate(2) is None


def test_not_reachable_is_the_scope_out_signal():
    assert v.not_reachable(True).reason == v.NOT_REACHABLE
    assert v.not_reachable(False) is None


def test_coinjoin_fires_on_the_generators_mix_and_not_on_a_payment():
    rng = random.Random(3)
    mix = v.tx_of("a", shape(rng, "coinjoin", "s0", CFG))
    payment = v.tx_of("b", shape(rng, "payment", "s0", CFG))
    assert v.coinjoin(mix, CFG).reason == v.COINJOIN
    assert v.coinjoin(payment, CFG) is None
    assert v.coinjoin(None, CFG) is None       # no structure, no verdict


def test_coinjoin_cannot_tell_a_batch_payout_from_a_mix():
    """The documented false positive: structure does not show input ownership.
    A batch with no more equal outputs than inputs looks like a mix; one paying
    out more amounts than it spends inputs does not."""
    narrow = Tx("c", [(f"x{i}", 1.0) for i in range(4)], [(f"y{i}", 0.05) for i in range(4)])
    wide = Tx("d", [(f"x{i}", 1.0) for i in range(3)], [(f"y{i}", 0.05) for i in range(10)])
    assert v.coinjoin(narrow, CFG).reason == v.COINJOIN
    assert v.coinjoin(wide, CFG) is None


def test_tor_or_v2_fires_on_onion_and_on_v2_and_not_on_clearnet_v1():
    assert v.tor_or_v2(ONION, None).reason == v.TOR_OR_V2
    assert v.tor_or_v2("203.0.113.9", "v2").reason == v.TOR_OR_V2
    assert v.tor_or_v2("203.0.113.9", "v1") is None
    assert v.tor_or_v2("203.0.113.9", None) is None


def test_dandelion_fires_on_an_isolated_first_announcement_and_not_on_steady_diffusion():
    fired = v.dandelion_stem([0.0, 2.0, 2.05, 2.1, 2.2], CFG)
    assert fired.reason == v.DANDELION_STEM and 0.5 < fired.confidence <= 1.0
    assert v.dandelion_stem([0.0, 0.1, 0.2, 0.3, 0.4], CFG) is None
    assert v.dandelion_stem([0.0, 5.0, 5.1], CFG) is None     # too few to judge


def test_assess_reports_the_first_reason_in_order_and_passes_a_clean_case():
    everything = v.assess(1, True, ONION, "v2", [0, 2, 2.1, 2.2, 2.3], cj_tx(), CFG)
    assert everything.reason == v.DEGENERATE
    assert v.assess(5, False, ONION, None, [0, 2, 2.1, 2.2, 2.3], cj_tx(), CFG).reason \
        == v.COINJOIN
    clean = v.assess(5, False, "203.0.113.9", "v1", [0, 0.1, 0.2, 0.3, 0.4], None, CFG)
    assert clean.passed and clean.as_dict()["status"] == "PASS"
    assert everything.as_dict()["status"] == "INCONCLUSIVE" and everything.evidence


# --- one abstention path ------------------------------------------------------
def test_a_failed_check_abstains_through_the_existing_rule_and_only_when_enforced():
    frame = pd.DataFrame({"ip_class": ["residential_or_unknown"] * 2,
                          "confidence": [0.99, 0.99],
                          "validity": [v.PASS, v.DANDELION_STEM]})
    assert origin_eval.flagged_at(frame, CFG).tolist() == [False, True]
    off = {**CFG, "validity": {**CFG["validity"], "enforce": False}}
    assert origin_eval.flagged_at(frame, off).tolist() == [False, False]
    stem = v.dandelion_stem([0.0, 2.0, 2.05, 2.1, 2.2], CFG)
    assert low_confidence_origin("residential_or_unknown", 0.99, CFG, stem)
    assert not low_confidence_origin("residential_or_unknown", 0.99, CFG, v.VALID)


# --- the generator makes the conditions ---------------------------------------
def test_a_stem_is_a_serial_single_peer_chain():
    net = build_net(random.Random(1), CFG)
    origin = net.nodes[0]
    hops, fluff, t_fluff = net.stem(origin, 0.0, random.Random(2), [5, 6, 7], 6)
    assert 1 <= len(hops) <= 6 and hops[0][1] is origin
    for (_, _, dst), (_, src, _) in zip(hops, hops[1:]):
        assert src is dst                      # each hop forwards what it received
    receivers = [dst.addr for _, _, dst in hops]
    assert len(set(receivers)) == len(receivers)
    assert net.nodes[fluff].addr == receivers[-1] and t_fluff == hops[-1][0]


def test_the_variant_labels_every_condition():
    specs = corpus.expand(corpus.load_manifest(corpus.VALIDITY_MANIFEST))
    spec = next(s for s in specs if all(s[k] for k in ("dandelion", "onion", "v2", "coinjoin"))
                and s["placement"] == "hub")
    truth = corpus.featurise(spec, CFG)["truth"]
    for column in ("stem_length", "stem_through_observer", "onion_origin", "shape",
                   "in_addrs", "out_vals"):
        assert column in truth
    assert (truth["stem_length"] > 0).any()
    assert truth["onion_origin"].any()


def test_switching_every_condition_off_reproduces_the_base_capture():
    base = corpus.expand(corpus.load_manifest())[7]
    variant = next(s for s in corpus.expand(corpus.load_manifest(corpus.VALIDITY_MANIFEST))
                   if s["capture_id"] == base["capture_id"])
    off = {**variant, "dandelion": False, "onion": False, "v2": False, "coinjoin": False}
    a = corpus.featurise(base, CFG)["features"]
    b = corpus.featurise(off, CFG)["features"]
    columns = [c for c in a.columns if c != "transport_v2" and a[c].notna().any()]
    pd.testing.assert_frame_equal(a[columns], b[columns])


# --- the capture reader keeps onion peers and learns transport ---------------
def test_debug_log_keeps_onion_peers_and_records_v2_transport(tmp_path):
    txid = "ab" * 32
    log = tmp_path / "onion.debug.log"
    log.write_text(
        "2026-09-24T10:00:00.000000Z New outbound-full-relay v2 peer connected: "
        f"transport: v2, version: 70016, blocks=840000, peer=4, peeraddr={ONION}:8333\n"
        f"2026-09-24T10:00:01.000000Z got inv: tx {txid}  new peer=4\n")
    (event,) = cr.parse_debug_log(log)
    assert event.peer_ip == ONION and event.transport == "v2"


def test_a_btcap_event_carries_its_transport(tmp_path):
    path = tmp_path / "t.btcap"
    path.write_text('{"txid": "' + "cd" * 32 + '", "peer_ip": "' + ONION + '", '
                    '"message_type": "inv", "wall_clock_ts": 1790000000, "transport": "v1"}\n')
    (event,) = cr.parse_btcap(path)
    assert event.transport == "v1" and event.peer_ip.endswith(".onion")


# --- CoinJoin terminates taint ------------------------------------------------
def test_taint_stops_at_a_coinjoin_and_still_follows_an_ordinary_payment():
    mix = Tx("mix", [("dirty", 0.1)] + [(f"p{i}", 0.1) for i in range(5)],
             [("clean_out", 0.0999)] + [(f"q{i}", 0.0999) for i in range(5)])
    pay = Tx("pay", [("dirty", 0.3)], [("payee", 0.2), ("dirty", 0.0999)])
    clustering = cluster_wallets([mix, pay], CFG)
    assert "mix" in clustering.coinjoins
    graph = build_entity_graph([mix, pay], clustering, CFG)
    entity = clustering.cluster_of
    taint = propagate(graph, {entity("dirty"): 1.0}, CFG)
    assert entity("payee") in taint
    assert entity("clean_out") not in taint


@pytest.mark.parametrize("reason", v.REASONS)
def test_every_reason_code_is_named_in_the_taxonomy(reason):
    from analysis.evaluate import TAXONOMY
    assert f"`{reason}`" in TAXONOMY
