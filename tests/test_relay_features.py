"""The relay grain: candidate rows, and the four hard constraints.

The causality tests are the ones that matter. A relay feature matrix is training
data for a model that answers "did this peer originate this transaction", and the
most natural way to write these features leaks the answer: a peer aggregate
computed over the whole capture encodes how often that peer *will* be first,
which is most of the way to the label. So the strict-class features are asserted
to be byte-identical when later events are added, and
`test_the_causality_check_can_actually_fail` proves the assertion is not vacuous.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

import pandas as pd
import pytest

import config
from eval.ground_truth.preflight import PreflightError
from features import relay
from ingest.ip_intel import load_intel
from p2p.capture_reader import RelayEvent, read_directory

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "ground_truth"
OBSERVER = "198.51.100.2"


@pytest.fixture(scope="module")
def cfg():
    return config.load()


@pytest.fixture(scope="module")
def intel(cfg):
    """One IpIntel for the whole module: loading it is the slow part."""
    return load_intel(None, None, cfg)


@pytest.fixture(scope="module")
def geoip(cfg):
    from ingest.geoip import GeoIp

    return GeoIp(cfg)


def event(ts: float, txid: str = "a" * 64, peer: str = "192.0.2.14",
          **kwargs) -> RelayEvent:
    defaults = dict(txid=txid, peer_ip=peer, peer_port=8333, peer_id=1, user_agent=None,
                    wall_clock_ts=ts, monotonic_or_derived_ts=0.0, message_type="inv",
                    direction="inbound", capture_source="test")
    return RelayEvent(**{**defaults, **kwargs})


def build(events, cfg, intel, geoip, capture_id="test"):
    return relay.compute_relay_features(events, capture_id, [OBSERVER], cfg,
                                        intel=intel, geoip=geoip)


@pytest.fixture(scope="module")
def fixture_events(cfg):
    from eval.ground_truth.broadcast import load_labels, resolve_from_labels

    directory = FIXTURES / "adjacent-synthetic"
    events = read_directory(directory, cfg=cfg)
    resolve_from_labels(events, load_labels(next(directory.glob("*.labels.json"))))
    return events


@pytest.fixture(scope="module")
def fixture_matrix(fixture_events, cfg, intel, geoip):
    return build(fixture_events, cfg, intel, geoip, "adjacent-synthetic")


# --- 1. CAUSALITY ---------------------------------------------------------
def test_input_order_does_not_change_a_single_value(fixture_events, cfg, intel, geoip):
    """The matrix is a function of the events, not of the order they were read
    in — a capture concatenated from two rotated log files must give the same
    answer as one read in timestamp order."""
    straight, _ = build(fixture_events, cfg, intel, geoip)
    shuffled_events = list(fixture_events)
    random.Random(41).shuffle(shuffled_events)
    shuffled, _ = build(shuffled_events, cfg, intel, geoip)
    pd.testing.assert_frame_equal(straight, shuffled)


def test_later_events_cannot_change_an_earlier_rows_features(fixture_events, cfg,
                                                             intel, geoip):
    """The whole constraint, in one assertion.

    Every row of the original matrix must survive the arrival of more traffic
    unchanged — including the strict peer-history columns, which are the ones
    that would otherwise encode the future.
    """
    before, _ = build(fixture_events, cfg, intel, geoip)
    latest = max(e.wall_clock_ts for e in fixture_events)
    extra = [event(latest + 60 + i, txid=f"{i:064x}", peer=peer)
             for i in range(5)
             for peer in ("203.0.113.9", "192.0.2.14", "198.51.100.77")]
    after, _ = build(fixture_events + extra, cfg, intel, geoip)
    overlap = after[after["txid"].isin(set(before["txid"]))].reset_index(drop=True)
    pd.testing.assert_frame_equal(before, overlap)


def test_shuffling_the_post_announcement_events_changes_nothing(fixture_events, cfg,
                                                                intel, geoip):
    """Same assertion, with the future reordered rather than extended."""
    ordered = sorted(fixture_events, key=lambda e: e.wall_clock_ts)
    cut = len(ordered) // 2
    head, tail = ordered[:cut], ordered[cut:]
    first_half_txids = {e.txid for e in head} - {e.txid for e in tail}
    before, _ = build(ordered, cfg, intel, geoip)
    shuffled_tail = list(tail)
    random.Random(7).shuffle(shuffled_tail)
    after, _ = build(head + shuffled_tail, cfg, intel, geoip)
    for frame in (before, after):
        frame.set_index(relay.KEY_COLUMNS, inplace=True)
    pd.testing.assert_frame_equal(before.loc[sorted(
        [k for k in before.index if k[0] in first_half_txids])],
        after.loc[sorted([k for k in after.index if k[0] in first_half_txids])])


def test_the_causality_check_can_actually_fail(fixture_events, cfg, intel, geoip):
    """A test that cannot fail proves nothing. Inserting an announcement
    *earlier* than an existing one must change that transaction's features —
    if it does not, the two tests above are measuring nothing."""
    before, _ = build(fixture_events, cfg, intel, geoip)
    target = before.iloc[0]
    earlier = event(float(target["announce_ts"]) - 5.0, txid=target["txid"],
                    peer="203.0.113.55")
    after, _ = build(list(fixture_events) + [earlier], cfg, intel, geoip)
    row_before = before[(before["txid"] == target["txid"])
                        & (before["peer_ip"] == target["peer_ip"])].iloc[0]
    row_after = after[(after["txid"] == target["txid"])
                      & (after["peer_ip"] == target["peer_ip"])].iloc[0]
    assert row_after["announce_rank"] > row_before["announce_rank"]
    assert row_after["delta_vs_first_s"] > row_before["delta_vs_first_s"]


def test_peer_history_counts_only_what_came_before(cfg, intel, geoip):
    """The strict class, checked by hand on four announcements."""
    events = [
        event(1000.5, txid="a" * 64, peer="192.0.2.14"),
        event(1000.9, txid="a" * 64, peer="192.0.2.37"),
        event(1010.5, txid="b" * 64, peer="192.0.2.14"),
        event(1010.9, txid="b" * 64, peer="192.0.2.37"),
    ]
    features, _ = build(events, cfg, intel, geoip)
    rows = features.set_index(["txid", "peer_ip"])
    first_tx, second_tx = "a" * 64, "b" * 64
    # Nothing precedes the first transaction.
    assert rows.loc[(first_tx, "192.0.2.14"), "peer_txids_before"] == 0
    assert pd.isna(rows.loc[(first_tx, "192.0.2.14"), "peer_fraction_first_before"])
    # By the second, each peer has exactly one earlier transaction, and .14 was
    # first on it while .37 was not.
    assert rows.loc[(second_tx, "192.0.2.14"), "peer_txids_before"] == 1
    assert rows.loc[(second_tx, "192.0.2.14"), "peer_firsts_before"] == 1
    assert rows.loc[(second_tx, "192.0.2.14"), "peer_fraction_first_before"] == 1.0
    assert rows.loc[(second_tx, "192.0.2.37"), "peer_firsts_before"] == 0
    assert rows.loc[(second_tx, "192.0.2.37"), "peer_fraction_first_before"] == 0.0


# --- 2. WTXID -------------------------------------------------------------
def test_unresolved_wtxid_rows_are_quarantined_not_merged(cfg, intel, geoip):
    """A wtxid and a txid are different identifiers. Merging them would split
    one transaction's announcements across two grains, or pool two
    transactions under one."""
    events = [event(1000.5, txid="a" * 64),
              event(1000.7, txid="b" * 64, message_type="inv_wtx", peer="192.0.2.37")]
    features, quarantine = build(events, cfg, intel, geoip)
    assert set(features["txid"]) == {"a" * 64}
    assert len(quarantine) == 1
    assert list(quarantine.columns) == list(relay.QUARANTINE_COLUMNS)
    assert "unresolved wtxid" in quarantine.iloc[0]["reason"]
    assert json.loads(quarantine.iloc[0]["raw"])["txid"] == "b" * 64
    assert not features["wtxid_unresolved"].any()


def test_the_fixture_labels_resolve_every_wtxid_so_nothing_is_quarantined(fixture_matrix):
    features, quarantine = fixture_matrix
    assert len(quarantine) == 0
    assert len(features) > 0


def test_without_its_label_file_the_same_bundle_quarantines_rows(cfg, intel, geoip):
    """The label file is what resolves a wtxid a log-only capture could not."""
    events = read_directory(FIXTURES / "adjacent-synthetic", cfg=cfg)
    _, quarantine = build(events, cfg, intel, geoip)
    assert len(quarantine) > 0, "the fixture must contain wtxid announcements"


# --- 3. CLOCK RESOLUTION --------------------------------------------------
def test_whole_second_timestamps_are_refused(cfg, intel, geoip):
    events = [event(1000.0 + i, txid=f"{i:064x}") for i in range(6)]
    with pytest.raises(PreflightError) as raised:
        build(events, cfg, intel, geoip)
    assert any("sub-second resolution" in f for f in raised.value.failures)


def test_the_threshold_is_evals_not_a_second_copy():
    """The number lives in one place; this asserts the module reads it there."""
    source = Path(relay.__file__).read_text()
    assert "eval.ground_truth.preflight" in source
    assert 'cfg["eval"]["ground_truth"]["min_subsecond_share"]' in source


# --- 4. VANTAGE -----------------------------------------------------------
def test_every_row_carries_the_capture_and_the_observer(fixture_matrix):
    features, _ = fixture_matrix
    assert (features["capture_id"] == "adjacent-synthetic").all()
    assert (features["observer_ip"] == OBSERVER).all()
    assert (features["observer_ips"] == OBSERVER).all()
    assert features["capture_source"].notna().all()


def test_an_unknown_observer_is_refused(cfg):
    with pytest.raises(relay.VantageError, match="observer's own address is unknown"):
        relay.observer_of(None, cfg, None)


def test_the_observer_is_never_a_candidate(cfg, intel, geoip):
    events = [event(1000.5, peer=OBSERVER), event(1000.7, peer="192.0.2.37")]
    features, _ = build(events, cfg, intel, geoip)
    assert OBSERVER not in set(features["peer_ip"])
    assert set(features["peer_ip"]) == {"192.0.2.37"}


def test_two_observers_are_not_pooled_without_saying_so(tmp_path, cfg):
    """An arrival delta is measured against one observer's clock and one
    observer's peer set. Pooling two silently would make one column mean two
    different things."""
    for name, observer in (("north", "198.51.100.2"), ("south", "198.51.100.3")):
        bundle = tmp_path / name
        bundle.mkdir()
        rows = [{"txid": f"{i:064x}", "message_type": "inv", "peer_ip": "192.0.2.14",
                 "peer_port": 8333, "wall_clock_ts": 1000.5 + i, "direction": "inbound"}
                for i in range(3)]
        (bundle / "capture.btcap").write_text(
            "".join(json.dumps(r) + "\n" for r in rows))
        (bundle / f"{name}.labels.json").write_text(json.dumps({
            "source": "synthetic-test-fixture", "topology_condition": "adjacent",
            "observer_local_ips": [observer],
            "transactions": [{"txid": r["txid"], "wtxid": "f" * 64} for r in rows]}))

    with pytest.raises(relay.VantageError, match="different observers"):
        relay.build([tmp_path / "north", tmp_path / "south"], cfg=cfg)

    features, _, meta = relay.build([tmp_path / "north", tmp_path / "south"], cfg=cfg,
                                    allow_cross_vantage=True)
    assert meta["cross_vantage"] is True
    assert len(meta["observers"]) == 2
    assert set(features["observer_ip"]) == {"198.51.100.2", "198.51.100.3"}


def test_the_direction_basis_is_carried_not_dropped(fixture_matrix, cfg):
    """Direction is always inferred; what varies is how the observer's address
    was established, and that is what the row records."""
    features, _ = fixture_matrix
    assert set(features["direction_basis"]) == {"explicit"}
    assert (features["direction_confidence"] == 1.0).all()
    assert set(features["direction"]) == {"inbound"}


def test_the_label_file_can_establish_the_observer(cfg, intel, geoip):
    events = [event(1000.5), event(1000.9, peer="192.0.2.37")]
    labels = {"observer_local_ips": [OBSERVER]}
    features, _ = relay.compute_relay_features(events, "test", None, cfg, labels,
                                              intel=intel, geoip=geoip)
    assert set(features["direction_basis"]) == {"label_file"}


# --- 5. SCOPE and degeneracy ---------------------------------------------
def test_a_single_candidate_is_marked_degenerate(cfg, intel, geoip):
    events = [event(1000.5, txid="a" * 64),
              event(1001.5, txid="b" * 64), event(1001.9, txid="b" * 64, peer="192.0.2.37")]
    features, _ = build(events, cfg, intel, geoip)
    rows = features.set_index(["txid", "peer_ip"])
    assert rows.loc[("a" * 64, "192.0.2.14"), "degenerate"]
    assert rows.loc[("a" * 64, "192.0.2.14"), "candidate_count"] == 1
    assert not rows.loc[("b" * 64, "192.0.2.14"), "degenerate"]


def test_a_transaction_only_public_relays_announced_is_out_of_scope(cfg, geoip):
    """No candidate could plausibly be the sender, so there is nothing here for
    a model to learn from — and the zero-ceiling case must be labelled, not
    silently trained on."""
    intel = load_intel(None, None, cfg)
    intel.add_synthetic({"relay": ["192.0.2.14", "192.0.2.37"]})
    events = [event(1000.5, peer="192.0.2.14"), event(1000.9, peer="192.0.2.37")]
    features, _ = relay.compute_relay_features(events, "test", [OBSERVER], cfg,
                                               intel=intel, geoip=geoip)
    assert features["scope_out"].all()
    assert set(features["ip_class"]) == {"known_bitcoin_relay"}


def test_a_residential_candidate_is_in_scope(fixture_matrix):
    features, _ = fixture_matrix
    assert not features["scope_out"].any()


# --- the matrix itself ---------------------------------------------------
def test_the_columns_are_the_documented_ones(fixture_matrix):
    features, _ = fixture_matrix
    assert list(features.columns) == relay.RELAY_COLUMNS
    documented = Path("docs/FEATURE_SCHEMA_RELAY.md").read_text()
    missing = [c for c in relay.RELAY_COLUMNS if f"`{c}`" not in documented]
    assert not missing, f"columns with no entry in the schema doc: {missing}"


def test_the_grain_is_one_row_per_candidate_per_txid_per_capture(fixture_matrix):
    features, _ = fixture_matrix
    assert not features.duplicated(subset=relay.KEY_COLUMNS).any()


def test_a_peer_announcing_twice_is_one_candidate_timed_from_the_earlier(cfg, intel, geoip):
    """inv then tx from the same peer is one candidate, not two."""
    events = [event(1000.5, peer="192.0.2.14"),
              event(1000.9, peer="192.0.2.14", message_type="tx"),
              event(1001.5, peer="192.0.2.37")]
    features, _ = build(events, cfg, intel, geoip)
    assert len(features) == 2
    row = features[features["peer_ip"] == "192.0.2.14"].iloc[0]
    assert row["is_first"] and row["delta_vs_first_s"] == 0.0
    assert row["announcements_of_txid"] == 3


def test_the_estimator_features_come_from_the_existing_estimators(fixture_matrix):
    from engines.propagation.estimators import ESTIMATORS

    features, _ = fixture_matrix
    for name in ESTIMATORS:
        assert f"est_{name}_score" in features.columns
        assert f"est_{name}_rank" in features.columns
    ranks = features[features["candidate_count"] > 1]["est_first_timestamp_rank"]
    assert ranks.notna().all() and ranks.min() == 1


def test_connection_age_is_null_with_an_indicator(fixture_matrix):
    """The reader's events carry announcements, not connection lifecycle, so the
    true connection time is not derivable — said with a column, not guessed."""
    features, _ = fixture_matrix
    assert features["connection_age_s"].isna().all()
    assert not features["connection_age_known"].any()
    assert (features["peer_first_seen_age_s"] >= 0).all()


def test_user_agent_class_maps_the_families():
    assert relay.user_agent_class("/Satoshi:25.0.0/") == "core"
    assert relay.user_agent_class("/bitcoinj:0.16.2/") == "bitcoinj"
    assert relay.user_agent_class("/SomethingElse:1.0/") == "other"
    assert relay.user_agent_class(None) == "unknown"


def test_summarise_reports_the_three_proportions(fixture_matrix):
    summary = relay.summarise(*fixture_matrix)
    assert summary["features"] == len(relay.RELAY_COLUMNS) - len(relay.KEY_COLUMNS)
    assert summary["degenerate_share"] == 0.0
    assert summary["scope_out_share"] == 0.0
    assert summary["quarantined_share"] == 0.0
    assert summary["transactions"] > 0 and summary["peers"] > 0


def test_an_empty_capture_yields_an_empty_matrix_with_the_right_columns(cfg, intel, geoip):
    events = [event(1000.5, peer=OBSERVER)]      # only our own address
    features, quarantine = build(events, cfg, intel, geoip)
    assert features.empty and list(features.columns) == relay.RELAY_COLUMNS
    assert quarantine.empty
