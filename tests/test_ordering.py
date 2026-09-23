"""The alert queue's order: total, deterministic, and the same everywhere.

The composite score cannot rank the top of the queue — `eval/results.md` §4
measures every one of the top fifty printing 1.000 — so the order comes from
`fusion.ordering.SORT_KEY`. These tests exist because an order that depends on
dict iteration or row arrival looks fine on one run and is different on the
next, and nobody notices until two people compare screenshots.
"""

from __future__ import annotations

import json

import pandas as pd
import pytest

import config
from fusion import ordering
from fusion.ordering import NO_TAINT, sort_key

CFG = config.load()


def alert(entity_id: str, **over) -> dict:
    row = {"entity_id": entity_id, "alert_id": entity_id, "risk_score": 1.0,
           "pattern_types": [], "taint_path": [], "leads": "[]",
           "rule_typologies": 0, "taint_hops": NO_TAINT,
           "lead_confidence": 0.0, "tx_count": 0}
    row.update(over)
    return row


def order_of(rows: list[dict]) -> list[str]:
    return list(ordering.sort(pd.DataFrame(rows))["entity_id"])


# --- the published order --------------------------------------------------
def test_the_composite_decides_before_any_tiebreaker():
    """A higher risk score outranks everything, however weak its tiebreakers."""
    rows = [alert("weak-but-risky", risk_score=0.9),
            alert("strong-but-safe", risk_score=0.8, rule_typologies=5,
                  taint_hops=0, lead_confidence=1.0, tx_count=9999)]
    assert order_of(rows) == ["weak-but-risky", "strong-but-safe"]


def test_more_distinct_rule_detectors_wins_a_tie():
    rows = [alert("one-detector", rule_typologies=1),
            alert("three-detectors", rule_typologies=3),
            alert("none", rule_typologies=0)]
    assert order_of(rows) == ["three-detectors", "one-detector", "none"]


def test_closer_to_a_watchlist_seed_wins_next():
    rows = [alert("four-hops", taint_hops=4),
            alert("one-hop", taint_hops=1),
            alert("direct", taint_hops=0)]
    assert order_of(rows) == ["direct", "one-hop", "four-hops"]


def test_no_taint_path_sorts_last_not_first():
    """Zero hops is the strongest possible taint; no path is the absence of one.

    Treating a missing path as 0 would put every untainted entity at the top —
    which is what `NO_TAINT` exists to prevent, and what `x or NO_TAINT` would
    quietly reintroduce for a genuine zero.
    """
    rows = [alert("unconnected"), alert("direct-hit", taint_hops=0)]
    assert order_of(rows) == ["direct-hit", "unconnected"]
    assert sort_key(alert("direct-hit", taint_hops=0))[2] == 0


def test_the_strongest_attribution_lead_then_volume_break_the_rest():
    rows = [alert("quiet", lead_confidence=0.1, tx_count=500),
            alert("attributable", lead_confidence=0.9, tx_count=2)]
    assert order_of(rows) == ["attributable", "quiet"]

    same_lead = [alert("small", lead_confidence=0.5, tx_count=2),
                 alert("large", lead_confidence=0.5, tx_count=900)]
    assert order_of(same_lead) == ["large", "small"]


def test_identical_alerts_fall_back_to_the_entity_id():
    rows = [alert("zzz"), alert("aaa"), alert("mmm")]
    assert order_of(rows) == ["aaa", "mmm", "zzz"]


# --- determinism ----------------------------------------------------------
def test_the_same_alerts_in_any_input_order_give_the_same_queue():
    """The order must be a property of the alerts, not of how they arrived.

    Shuffling the input is how a dependence on row order shows itself; this
    runs every rotation rather than one shuffle, so the test cannot pass by
    luck.
    """
    rows = [alert("a", risk_score=1.0, rule_typologies=2),
            alert("b", risk_score=1.0, rule_typologies=2, taint_hops=3),
            alert("c", risk_score=1.0, lead_confidence=0.7),
            alert("d", risk_score=0.9, rule_typologies=9),
            alert("e", risk_score=1.0, lead_confidence=0.7, tx_count=5)]
    expected = order_of(rows)
    for i in range(len(rows)):
        rotated = rows[i:] + rows[:i]
        assert order_of(rotated) == expected, f"rotation by {i} changed the order"
    assert order_of(list(reversed(rows))) == expected


def test_two_runs_over_the_same_dataset_produce_the_same_queue(tmp_path):
    """End to end, through the real pipeline, twice.

    The unit tests above use hand-built rows; this one asks whether the whole
    path — clustering, features, every engine, fusion — lands on the same queue
    when run again over identical input.
    """
    from fusion.pipeline import build_alerts, collect_signals
    from fusion.stacker import Stacker, default_weights
    from generator.main import build_parser, generate
    from ingest.pipeline import run as ingest_run

    raw = tmp_path / "raw"
    generate(build_parser().parse_args(
        ["--n-actors", "60", "--n-transactions", "400", "--output", str(raw),
         "--seed", "23", "--formats", "csv"]), CFG)
    ingest_run(raw, tmp_path / "t.parquet", tmp_path / "q.parquet", "csv", cfg=CFG)
    frame = pd.read_parquet(tmp_path / "t.parquet")

    # A fixed model, so this measures the ordering rather than a refit, and a
    # threshold of zero so every entity becomes a row to order. That is not
    # threshold tuning — it is the absence of a filter, chosen so the test has
    # a queue to check rather than the handful of alerts a small synthetic set
    # happens to raise.
    cfg = json.loads(json.dumps(CFG))
    cfg["fusion"]["alert_threshold"] = 0.0
    stacker = Stacker(fallback_weights=default_weights(cfg), metrics={"fitted": False})
    first = build_alerts(collect_signals(frame, cfg, raw), stacker, cfg)
    second = build_alerts(collect_signals(frame, cfg, raw), stacker, cfg)

    assert len(first) > 1, "not enough alerts to order"
    assert list(first["entity_id"]) == list(second["entity_id"])
    assert list(first["sort_key"]) == list(second["sort_key"])


def test_the_exported_key_reproduces_the_queue():
    """`sort_key` on the record must be exactly what the sort compared.

    If it is not, a consumer that re-sorts on it — the PDF, another tool —
    produces a different order from the screen. Rounding the composite is
    enough to break this: it invents ties with the rows genuinely at 1.000.
    """
    rows = [alert("a", risk_score=0.9999996, rule_typologies=5),
            alert("b", risk_score=1.0, rule_typologies=0),
            alert("c", risk_score=1.0, rule_typologies=1)]
    queue = ordering.sort(pd.DataFrame(rows))
    keys = [sort_key(r) for _, r in queue.iterrows()]

    replayed = sorted(range(len(keys)),
                      key=lambda i: (-keys[i][0], -keys[i][1], keys[i][2],
                                     -keys[i][3], -keys[i][4], keys[i][5]))
    assert replayed == list(range(len(keys))), "the key does not reproduce the queue"
    # c and b both sit at 1.0; c fired one detector and b fired none, so c is
    # first. `a` is last despite five detectors, because 0.9999996 really is a
    # lower composite — which is the case the rounding bug used to hide.
    assert list(queue["entity_id"]) == ["c", "b", "a"]


def test_the_key_survives_a_json_round_trip():
    """It travels to the console and the PDF as JSON."""
    key = sort_key(alert("bc1qexample", risk_score=0.75, rule_typologies=2,
                         taint_hops=0, lead_confidence=0.5, tx_count=7))
    assert json.loads(json.dumps(key)) == key
    assert key == [0.75, 2, 0, 0.5, 7, "bc1qexample"]


# --- the derivations ------------------------------------------------------
@pytest.mark.parametrize("path, hops", [([], NO_TAINT), (["seed"], 0),
                                        (["seed", "a"], 1), (["seed", "a", "b"], 2)])
def test_taint_hops_counts_edges_not_nodes(path, hops):
    assert ordering.taint_hops(path) == hops


def test_lead_confidence_takes_the_strongest_and_survives_json():
    leads = [{"ip": "1.1.1.1", "confidence": 0.2}, {"ip": "2.2.2.2", "confidence": 0.7}]
    assert ordering.lead_confidence(leads) == 0.7
    assert ordering.lead_confidence(json.dumps(leads)) == 0.7
    assert ordering.lead_confidence([]) == 0.0
    assert ordering.lead_confidence("not json") == 0.0
