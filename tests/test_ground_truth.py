"""The ground-truth harness: preflight refusals, label-side wtxid resolution,
and the adjacent / non-adjacent separation.

The two fixture bundles under `tests/fixtures/ground_truth/` are **synthetic**
and say so in their label files' `source`. That is not a detail: the scorer only
treats a bundle as a signet measurement when its label file says
`source: "signet"`, so a fixture can never be published in `eval/results.md` as
a statement about Bitcoin. `test_a_fixture_is_never_scored_as_signet` is the
assertion that keeps that true.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import config
from eval.ground_truth import broadcast, preflight, score
from p2p.capture_reader import RelayEvent, read_directory

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "ground_truth"
OBSERVER = "198.51.100.2"


@pytest.fixture(scope="module")
def cfg():
    return config.load()


def bundle(name: str):
    directory = FIXTURES / name
    labels = broadcast.load_labels(next(directory.glob("*.labels.json")))
    return directory, labels


def loaded(name: str, cfg):
    """A bundle read, wtxid-resolved and scored — the whole analysis path."""
    directory, labels = bundle(name)
    events = read_directory(directory, cfg=cfg)
    resolution = broadcast.resolve_from_labels(events, labels)
    local = set(labels["observer_local_ips"])
    checked = preflight.check(events, labels, local, cfg, resolution)
    frame = score.relay_frame(events, sorted(local)[0])
    result = score.score_condition(frame, broadcast.truth_of(labels),
                                   labels["topology_condition"], cfg, local)
    return {"labels": labels, "events": events, "resolution": resolution,
            "preflight": checked, "result": result}


def event(**kwargs) -> RelayEvent:
    defaults = dict(txid="a" * 64, peer_ip="192.0.2.14", peer_port=8333, peer_id=1,
                    user_agent=None, wall_clock_ts=1_790_244_000.25,
                    monotonic_or_derived_ts=0.0, message_type="inv",
                    direction="inbound", capture_source="test")
    return RelayEvent(**{**defaults, **kwargs})


def labels_for(events, condition="non_adjacent", origin="203.0.113.9",
               source="synthetic-test-fixture") -> dict:
    return {"source": source, "topology_condition": condition, "true_origin_ip": origin,
            "observer_local_ips": [OBSERVER],
            "topology_check": {"as_claimed": True, "detail": "test"},
            "transactions": [{"txid": e.txid, "wtxid": "f" * 64,
                              "true_origin_ip": origin} for e in events]}


# --- label-side wtxid resolution -----------------------------------------
def test_labels_resolve_the_wtxid_rows_a_capture_cannot(cfg):
    """A log-only capture sees `got inv: wtx <hash>` and cannot know which
    transaction it was. The broadcaster held the raw bytes, so it can."""
    loaded_bundle = loaded("adjacent-synthetic", cfg)
    resolution = loaded_bundle["resolution"]
    assert resolution["unresolved_before"] > 0, "the fixture must contain wtxid rows"
    assert resolution["recovered"] == resolution["unresolved_before"]
    assert resolution["unresolved_after"] == 0
    assert resolution["recovered_share"] == 1.0
    assert not any(e.message_type == "inv_wtx" for e in loaded_bundle["events"])


def test_resolution_leaves_a_wtxid_the_labels_do_not_know(cfg):
    events = [event(txid="b" * 64, message_type="inv_wtx")]
    labels = {"source": "synthetic-test-fixture", "topology_condition": "adjacent",
              "transactions": [{"txid": "c" * 64, "wtxid": "d" * 64}]}
    resolution = broadcast.resolve_from_labels(events, labels)
    assert resolution == {"unresolved_before": 1, "recovered": 0, "unresolved_after": 1,
                          "recovered_share": 0.0}
    assert events[0].message_type == "inv_wtx", "an unknown wtxid keeps its marker"


def test_the_wtxid_map_comes_from_the_broadcasters_own_raw_transaction():
    """`broadcast.send_one` recomputes the txid from `getrawtransaction` and
    refuses a mismatch — a label file whose txid does not match its raw_hex
    labels the wrong transaction."""
    from p2p.capture_reader import txids_of

    raw = bytes.fromhex(
        "01000000010000000000000000000000000000000000000000000000000000000000000000"
        "ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f3230303920436861"
        "6e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f72"
        "2062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b710"
        "5cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b"
        "8d578a4c702b6bf11d5fac00000000")
    real_txid, _ = txids_of(raw)
    calls = iter([real_txid, raw.hex()])

    class Done:
        returncode, stderr, stdout = 0, "", ""

    def runner(command, **kwargs):
        done = Done()
        done.stdout = next(calls)
        return done

    record = broadcast.send_one(None, "signet", "addr", 0.0001, runner)
    assert record["txid"] == real_txid
    assert record["wtxid"] == real_txid, "a non-segwit transaction has one identifier"


def test_a_txid_that_disagrees_with_its_raw_hex_is_refused():
    calls = iter(["ab" * 32, "01000000010000000000000000000000000000000000000000000000"
                            "000000000000000000ffffffff0100ffffffff0100f2052a01000000"
                            "0000000000"])

    class Done:
        returncode, stderr, stdout = 0, "", ""

    def runner(command, **kwargs):
        done = Done()
        done.stdout = next(calls)
        return done

    with pytest.raises(RuntimeError, match="txid mismatch"):
        broadcast.send_one(None, "signet", "addr", 0.0001, runner)


# --- preflight refuses, loudly -------------------------------------------
def test_whole_second_timestamps_are_refused(cfg):
    events = [event(wall_clock_ts=1_790_244_000.0 + i) for i in range(5)]
    with pytest.raises(preflight.PreflightError) as raised:
        preflight.check(events, labels_for(events), {OBSERVER}, cfg)
    assert any("sub-second resolution" in f for f in raised.value.failures)
    assert any("logtimemicros=1" in f for f in raised.value.failures)


def test_unresolved_wtxid_above_the_threshold_is_refused(cfg):
    events = [event(txid=f"{i:064x}", message_type="inv_wtx") for i in range(5)]
    resolution = {"unresolved_before": 5, "recovered": 0, "unresolved_after": 5,
                  "recovered_share": 0.0}
    with pytest.raises(preflight.PreflightError) as raised:
        preflight.check(events, labels_for(events), {OBSERVER}, cfg, resolution)
    assert any("identified by wtxid after label-side resolution" in f
               for f in raised.value.failures)


def test_unset_local_ips_is_refused(cfg):
    events = [event()]
    with pytest.raises(preflight.PreflightError) as raised:
        preflight.check(events, labels_for(events), set(), cfg)
    assert any("local_ips is unset" in f for f in raised.value.failures)


def test_ambiguous_local_ips_is_refused(cfg):
    """The observer must not be a candidate for its own observations."""
    events = [event(peer_ip=OBSERVER)]
    with pytest.raises(preflight.PreflightError) as raised:
        preflight.check(events, labels_for(events), {OBSERVER}, cfg)
    assert any("local_ips is ambiguous" in f for f in raised.value.failures)


def test_an_unrecorded_topology_condition_is_refused(cfg):
    events = [event()]
    labels = labels_for(events)
    del labels["topology_condition"]
    with pytest.raises(preflight.PreflightError) as raised:
        preflight.check(events, labels, {OBSERVER}, cfg)
    assert any("topology_condition is None" in f for f in raised.value.failures)


def test_a_topology_check_that_failed_at_broadcast_time_is_refused(cfg):
    events = [event()]
    labels = labels_for(events)
    labels["topology_check"] = {"as_claimed": False,
                                "detail": "claimed non_adjacent but observer_is_a_peer=True"}
    with pytest.raises(preflight.PreflightError) as raised:
        preflight.check(events, labels, {OBSERVER}, cfg)
    assert any("trivial upper bound" in f for f in raised.value.failures)


def test_a_capture_from_a_different_run_is_refused(cfg):
    events = [event(txid="e" * 64)]
    labels = labels_for([event(txid="f" * 64)])
    with pytest.raises(preflight.PreflightError) as raised:
        preflight.check(events, labels, {OBSERVER}, cfg)
    assert any("from different runs" in f for f in raised.value.failures)


def test_every_failure_is_reported_at_once_not_just_the_first(cfg):
    """An operator fixing a capture should learn everything wrong with it in one
    run, not discover the next problem after each repair."""
    events = [event(wall_clock_ts=1_790_244_000.0 + i, message_type="inv_wtx")
              for i in range(5)]
    labels = labels_for(events)
    del labels["topology_condition"]
    with pytest.raises(preflight.PreflightError) as raised:
        preflight.check(events, labels, set(), cfg)
    assert len(raised.value.failures) >= 4


def test_an_empty_capture_is_refused(cfg):
    with pytest.raises(preflight.PreflightError):
        preflight.check([], labels_for([event()]), {OBSERVER}, cfg)


def test_a_clean_capture_passes_and_reports_what_it_checked(cfg):
    checked = loaded("adjacent-synthetic", cfg)["preflight"]
    assert checked["subsecond_share"] == 1.0
    assert checked["unresolved_wtxid"] == 0
    assert checked["topology_condition"] == "adjacent"
    assert checked["topology_verified"]
    assert checked["labelled_transactions_observed"] == checked["labelled_transactions"]


# --- the two conditions are different measurements -----------------------
def test_adjacent_and_non_adjacent_are_separated_by_the_ceiling(cfg):
    """With one observer the separation is structural, not a matter of degree.

    Adjacent: the broadcaster is a peer, so its address is in every tree and the
    ceiling is 1.0. Non-adjacent: the broadcaster is not a peer, so its address
    never appears at all and the ceiling is 0.0 — no estimator can clear it.
    Pooling the two would average an upper bound with an impossibility.
    """
    adjacent = loaded("adjacent-synthetic", cfg)["result"]
    non_adjacent = loaded("non_adjacent-synthetic", cfg)["result"]

    def ceiling(result):
        table = result["table"]
        return float(table[table["estimator"] == score.FIRST_SPY]
                     ["ceiling (origin observed)"].iloc[0])

    assert ceiling(adjacent) == 1.0
    assert ceiling(non_adjacent) == 0.0
    assert adjacent["condition"] == "adjacent"
    assert non_adjacent["condition"] == "non_adjacent"


def test_the_floor_is_beaten_on_the_adjacent_condition(cfg):
    """The baseline exists to be compared against, so it has to be scored on the
    same rows as the estimators."""
    table = loaded("adjacent-synthetic", cfg)["result"]["table"]
    rows = table.set_index("estimator")
    assert rows.loc[score.FIRST_SPY, "n"] == rows.loc["first_timestamp", "n"] == "40"
    assert rows.loc["first_timestamp", "top1"] >= rows.loc[score.FIRST_SPY, "top1"]


def test_the_floor_does_not_abstain(cfg):
    """Scored under the shared abstention rule the floor posts 100% abstention,
    which is an artifact of the confidence formula, not caution."""
    import pandas as pd

    rows = loaded("adjacent-synthetic", cfg)["result"]["table"].set_index("estimator")
    assert pd.isna(rows.loc[score.FIRST_SPY, "abstention rate"])
    assert not pd.isna(rows.loc["first_timestamp", "abstention rate"])
    assert "never abstains" in rows.loc[score.FIRST_SPY, "acc if answered 95% CI"]


def test_every_accuracy_figure_carries_a_wilson_interval(cfg):
    table = loaded("adjacent-synthetic", cfg)["result"]["table"]
    scored = table[table["estimator"] != score.PENDING_MODEL]
    for column in ("top1 95% CI", "top3 95% CI"):
        assert scored[column].map(lambda v: "–" in str(v)).all()


def test_wilson_stays_inside_zero_and_one():
    """The normal approximation runs past 1.0 at these sample sizes, which on a
    table of forty-transaction runs would be most of the rows."""
    assert score.wilson(40, 40) == (0.9124, 1.0)
    assert score.wilson(0, 40)[0] == 0.0
    assert score.wilson(0, 0) == (0.0, 0.0)


def test_the_supervised_row_is_held_open_and_marked_pending(cfg):
    table = loaded("adjacent-synthetic", cfg)["result"]["table"]
    row = table[table["estimator"] == score.PENDING_MODEL]
    assert len(row) == 1
    assert row["top1 95% CI"].iloc[0] == "PENDING"
    assert row["top1"].isna().all()


def test_the_three_estimators_appear_unchanged(cfg):
    """Rows 2-4 are `engines/propagation`'s estimators, not reimplementations."""
    from engines.propagation.estimators import ESTIMATORS

    table = loaded("adjacent-synthetic", cfg)["result"]["table"]
    assert list(table["estimator"]) == [score.FIRST_SPY, *ESTIMATORS, score.PENDING_MODEL]


# --- the noise floor -----------------------------------------------------
def test_the_noise_floor_measures_real_inter_peer_deltas(cfg):
    floor = loaded("adjacent-synthetic", cfg)["result"]["noise_floor"]
    assert floor["transactions with 2+ announcing peers"] > 0
    assert floor["inter-peer deltas measured"] > 0
    assert 0 < floor["p50 delta (s)"] < floor["p99 delta (s)"]
    assert floor["timing ceiling"] == 1.0


def test_the_timing_ceiling_is_zero_when_the_origin_never_announces(cfg):
    floor = loaded("non_adjacent-synthetic", cfg)["result"]["noise_floor"]
    assert floor["origin announced first"] == 0
    assert floor["timing ceiling"] == 0.0


# --- simulated and signet can never be confused --------------------------
def test_a_fixture_is_never_scored_as_signet(cfg):
    """The fixtures live in the configured fixtures directory. They must be
    skipped, by name of their source, rather than reported as signet rows."""
    conditions = score.signet_conditions(cfg)
    skipped = conditions.pop("_skipped", {"bundles": []})["bundles"]
    assert conditions == {}, "no fixture may become a signet row"
    assert {b["bundle"] for b in skipped} == {"adjacent-synthetic", "non_adjacent-synthetic"}
    assert {b["source"] for b in skipped} == {"synthetic-test-fixture"}


def test_the_fixture_label_files_do_not_claim_to_be_signet():
    for name in ("adjacent-synthetic", "non_adjacent-synthetic"):
        labels = json.loads((FIXTURES / name / f"{name}.labels.json").read_text())
        assert labels["source"] == "synthetic-test-fixture"


def test_a_label_file_with_an_unknown_source_is_refused(tmp_path):
    path = tmp_path / "x.labels.json"
    path.write_text(json.dumps({"source": "mainnet-probably", "transactions": [{}]}))
    with pytest.raises(ValueError, match="no recognised source"):
        broadcast.load_labels(path)


def test_the_report_never_imports_the_broadcaster():
    """`broadcast` runs on the collection host and shells out to bitcoin-cli.
    Nothing on the analysis side may import it — the same import boundary p2p/
    keeps, asserted rather than documented."""
    import re

    import eval.report

    source = Path(eval.report.__file__).read_text()
    imports = re.findall(r"^\s*(?:from|import)\s+.*broadcast.*$", source, re.MULTILINE)
    assert not imports, f"eval.report imports the collection-host module: {imports}"
    assert "from .ground_truth import score" in source


def test_the_manifest_of_each_fixture_bundle_verifies(cfg):
    from p2p.manifest import verify_capture

    for name in ("adjacent-synthetic", "non_adjacent-synthetic"):
        result = verify_capture(FIXTURES / name, cfg=cfg, record=False)
        assert result["ok"], result
        assert "SYNTHETIC" in json.loads(
            (FIXTURES / name / "manifest.json").read_text())["note"]


# --- topology verification at broadcast time -----------------------------
def test_adjacency_is_verified_against_getpeerinfo_not_assumed():
    peers = [{"addr": "203.0.113.9:8333"}, {"addr": "192.0.2.14:8333"}]
    assert broadcast.verify_condition("adjacent", "203.0.113.9", peers)["as_claimed"]
    assert not broadcast.verify_condition("non_adjacent", "203.0.113.9", peers)["as_claimed"]
    assert broadcast.verify_condition("non_adjacent", "198.51.100.2", peers)["as_claimed"]


def test_an_unverifiable_condition_is_not_reported_as_verified():
    check = broadcast.verify_condition("adjacent", None, [{"addr": "192.0.2.14:8333"}])
    assert check["as_claimed"] is False
    assert "unverified" in check["detail"]


def test_an_unknown_condition_is_rejected():
    with pytest.raises(ValueError, match="condition must be one of"):
        broadcast.verify_condition("somewhere_in_between", "1.2.3.4", [])
