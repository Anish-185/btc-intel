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


def test_tor_onion_fires_on_an_onion_peer_and_not_on_clearnet():
    assert v.tor_onion(ONION).reason == v.TOR_ONION
    assert v.tor_onion("203.0.113.9") is None and v.tor_onion(None) is None


def test_v2_passive_tap_fires_only_on_a_pcap_with_undecodable_flows():
    assert v.v2_passive_tap("pcap:tap.pcap", 3).reason == v.V2_PASSIVE_TAP
    assert v.v2_passive_tap("pcap:tap.pcap", 0) is None         # every flow decoded
    # The node wrote these: it is a session endpoint and decrypts v2 itself.
    assert v.v2_passive_tap("debug.log:node1.debug.log", 3) is None
    assert v.v2_passive_tap("btcap:a.btcap", 3) is None


def test_dandelion_fires_on_an_isolated_first_announcement_and_not_on_steady_diffusion():
    fired = v.dandelion_stem([0.0, 2.0, 2.05, 2.1, 2.2], CFG)
    assert fired.reason == v.DANDELION_STEM and 0.5 < fired.confidence <= 1.0
    assert v.dandelion_stem([0.0, 0.1, 0.2, 0.3, 0.4], CFG) is None
    assert v.dandelion_stem([0.0, 5.0, 5.1], CFG) is None     # too few to judge


def test_every_reason_is_reported_and_the_tier_is_the_most_severe():
    stem = [0, 2, 2.1, 2.2, 2.3]
    everything = v.assess(1, True, ONION, stem, cj_tx(), CFG, "pcap:x", 2)
    assert everything.reason == v.DEGENERATE and everything.tier == v.ABSTAIN
    assert everything.reasons == v.REASONS
    mix_over_tor = v.assess(5, False, ONION, stem, cj_tx(), CFG)
    assert mix_over_tor.tier == v.QUALIFIED
    assert mix_over_tor.reasons == (v.COINJOIN, v.TOR_ONION, v.DANDELION_STEM)
    assert v.assess(5, False, "203.0.113.9", stem, None, CFG).tier == v.ANNOTATE
    clean = v.assess(5, False, "203.0.113.9", [0, 0.1, 0.2, 0.3, 0.4], None, CFG)
    assert clean.passed and clean.as_dict()["tier"] == v.PASS


# --- only ABSTAIN withholds, through the existing rule ------------------------
BINARY = {**CFG, "validity": {**CFG["validity"], "mode": "binary"}}
OFF = {**CFG, "validity": {**CFG["validity"], "enforce": False}}


def test_only_the_abstain_tier_abstains_and_binary_mode_restores_p6():
    tiers = [v.PASS, v.ANNOTATE, v.QUALIFIED, v.ABSTAIN]
    frame = pd.DataFrame({"ip_class": ["residential_or_unknown"] * 4,
                          "confidence": [0.99] * 4, "validity_tier": tiers})
    assert origin_eval.flagged_at(frame, CFG).tolist() == [False, False, False, True]
    assert origin_eval.flagged_at(frame, BINARY).tolist() == [False, True, True, True]
    assert origin_eval.flagged_at(frame, OFF).tolist() == [False] * 4
    stem = v.dandelion_stem([0.0, 2.0, 2.05, 2.1, 2.2], CFG)
    assert not low_confidence_origin("residential_or_unknown", 0.99, CFG, v.combine([stem]))
    assert low_confidence_origin("residential_or_unknown", 0.99, BINARY, v.combine([stem]))
    assert low_confidence_origin("residential_or_unknown", 0.99, CFG, v.assess(1, cfg=CFG))


# --- the revised outcomes -----------------------------------------------------
def scored(rows: list[dict], cfg=CFG, metric="revised") -> list[str]:
    frame = pd.DataFrame([{"ip_class": "residential_or_unknown", "confidence": 0.99,
                           "validity_tier": v.PASS, "validity_reasons": (),
                           "coinjoin_truth": False, **r} for r in rows])
    return origin_eval.outcomes(frame, cfg, 0.5, metric).tolist()


def test_a_qualified_answer_is_scored_as_qualified():
    rows = [{"correct": True, "validity_tier": v.QUALIFIED, "validity_reasons": (v.TOR_ONION,)},
            {"correct": False, "validity_tier": v.QUALIFIED, "validity_reasons": (v.TOR_ONION,)}]
    assert scored(rows) == ["qualified_correct", "qualified_wrong"]
    assert scored(rows, metric="p6") == ["correct_actionable", "wrong_uninvolved_third_party"]


def test_an_unqualified_answer_about_a_coinjoin_is_a_misattribution_right_or_wrong():
    mix = {"coinjoin_truth": True, "validity_tier": v.QUALIFIED,
           "validity_reasons": (v.COINJOIN,)}
    assert scored([{**mix, "correct": True}]) == ["qualified_correct"]
    assert scored([{**mix, "correct": True}], OFF) == ["coinjoin_input_misattribution"]
    assert scored([{**mix, "correct": False}], OFF) == ["coinjoin_input_misattribution"]
    missed = {"coinjoin_truth": True, "correct": True}     # the detector did not fire
    assert scored([missed]) == ["coinjoin_input_misattribution"]
    # A TOR_ONION qualification does not disclaim input ownership.
    onion_mix = {"coinjoin_truth": True, "correct": True, "validity_tier": v.QUALIFIED,
                 "validity_reasons": (v.TOR_ONION,)}
    assert scored([onion_mix]) == ["coinjoin_input_misattribution"]
    assert scored([missed], metric="p6") == ["correct_actionable"]


def test_an_annotated_answer_scores_as_before():
    rows = [{"correct": True, "validity_tier": v.ANNOTATE,
             "validity_reasons": (v.DANDELION_STEM,)}]
    assert scored(rows) == scored(rows, OFF) == ["correct_actionable"]


def test_a_withheld_answer_is_free_whatever_it_would_have_been():
    assert scored([{"correct": False, "validity_tier": v.ABSTAIN,
                    "validity_reasons": (v.DEGENERATE,), "coinjoin_truth": True}]) \
        == ["abstained"]


# --- what a qualified answer may say -----------------------------------------
def test_a_tor_onion_answer_carries_no_ip():
    answer = v.answer(ONION, v.assess(5, False, ONION, cfg=CFG), CFG)
    assert answer["kind"] == "onion_identity" and "ip" not in answer
    assert answer["onion"] == ONION


def test_a_coinjoin_answer_never_attributes_input_ownership():
    answer = v.answer("203.0.113.9", v.assess(5, False, "203.0.113.9", tx=cj_tx(), cfg=CFG), CFG)
    assert answer["kind"] == "broadcasting_peer"
    assert answer["input_ownership"].startswith("not attributable")
    assert v.answer("203.0.113.9", v.assess(1, cfg=CFG), CFG) is None      # withheld
    assert v.answer("203.0.113.9", v.VALID, CFG)["kind"] == "ip_attribution"


def test_no_correlation_lead_is_built_from_a_qualified_answer():
    from engines.correlation.scorer import collect_observations
    from engines.rules.detectors import FeatureSet
    from graph.builder import build_graph
    rows = pd.DataFrame([{"timestamp": pd.Timestamp("2026-01-01", tz="UTC"),
                          "src_ip": "203.0.113.9", "dst_ip": "10.0.0.1", "txid": t,
                          "input_addresses": [f"in{t}"], "output_addresses": [f"out{t}"],
                          "input_amounts": [1.0], "output_amounts": [0.9], "fee": 0.001,
                          "script_type": "p2wpkh", "asn": 9829, "geo_country": "IN"}
                         for t in ("a", "b", "c")])
    features = FeatureSet.from_graph(build_graph(rows, CFG), CFG)
    origins = pd.DataFrame([
        {"txid": t, "estimated_origin_ip": "203.0.113.9", "ip_class": "residential_or_unknown",
         "confidence": 0.9, "attribution_confidence": 0.9, "validity_reasons": reasons}
        for t, reasons in (("a", ()), ("b", (v.COINJOIN,)), ("c", (v.TOR_ONION,)))])
    kept = {o.txid for o in collect_observations(rows, features, CFG, origins)}
    assert kept == {"a"}


# --- the pcap reader counts what it could not read ---------------------------
def test_a_pcap_counts_the_flows_it_could_not_decode(tmp_path):
    from tests.test_capture_reader import inv_message, tcp_frame, write_pcap
    txid = "ef" * 32
    readable = tcp_frame("203.0.113.9", "10.0.0.1", 50000, 8333, inv_message([(1, txid)]))
    encrypted = tcp_frame("198.51.100.7", "10.0.0.1", 50001, 8333, bytes(range(200)))
    path = write_pcap(tmp_path / "tap.pcap", [(1.0, readable), (1.1, encrypted)])
    (event,) = cr.parse_pcap(path, CFG, local_ips=["10.0.0.1"])
    assert event.unreadable_flows == 1
    assert v.v2_passive_tap(event.capture_source, event.unreadable_flows).reason \
        == v.V2_PASSIVE_TAP


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


# --- the pre-registration survives every regeneration --------------------------
def test_regenerating_the_doc_keeps_the_preregistration_and_p6_verbatim(tmp_path, monkeypatch):
    from pathlib import Path
    from analysis import evaluate
    source = Path(CFG["validity"]["results_doc"])
    before = evaluate.preserved(source)
    assert "## Metric revision" in before and "## P6 results (frozen)" in before
    doc = tmp_path / "VALIDITY.md"
    doc.write_text(source.read_text())
    monkeypatch.setattr(evaluate, "section", lambda result, md_table: "new results\n")
    evaluate.write_doc({}, None, doc)
    evaluate.write_doc({}, None, doc)          # and again: nothing drifts
    assert evaluate.preserved(doc).rstrip() == before.rstrip()
    doc.write_text("# stripped\n")
    with pytest.raises(RuntimeError):
        evaluate.write_doc({}, None, doc)
