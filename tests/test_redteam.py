"""Red team: injection, the incremental re-run, and reset.

The third test is the one that matters. "Incremental" is only a performance
idea if it gives the same answer as recomputing everything — otherwise it is a
different, faster, wrong detector. So the incremental result is checked against
a full re-run over the same post-injection dataset.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pandas as pd
import pytest

import config
from api import redteam
from api.redteam import Injection, Run, execute, file_hashes, take_snapshot
from fusion import incremental
from fusion.pipeline import build_alerts, collect_signals
from generator.main import GROUND_TRUTH, build_parser, generate
from ingest.pipeline import run as ingest_run

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")

TYPOLOGIES = ["ransomware_collector", "peel_chain", "layering", "coinjoin",
              "same_actor_cluster"]


@pytest.fixture
def demo(tmp_path, monkeypatch):
    """A small dataset, ingested, with the stack's state already built.

    Everything is redirected into tmp_path: a red-team run writes to the
    dataset it is given, and a test that writes to data/ is a test that eats
    someone's demo.
    """
    cfg = json.loads(json.dumps(config.load()))
    raw = tmp_path / "raw"
    cfg["ingest"]["input_dir"] = str(raw)
    cfg["ingest"]["output_path"] = str(tmp_path / "transactions.parquet")
    cfg["ingest"]["quarantine_path"] = str(tmp_path / "quarantine.parquet")
    cfg["redteam"]["snapshot_dir"] = str(tmp_path / "snapshot")
    cfg["fusion"]["alerts_parquet"] = str(tmp_path / "final_alerts.parquet")
    cfg["fusion"]["alerts_json"] = str(tmp_path / "final_alerts.json")
    cfg["fusion"]["model_path"] = str(tmp_path / "stacker.joblib")
    monkeypatch.setattr(config, "load", lambda *a, **k: json.loads(json.dumps(cfg)))

    generate(build_parser().parse_args(
        ["--n-actors", "60", "--n-transactions", "400", "--output", str(raw),
         "--seed", "11", "--formats", "csv"]), cfg)
    ingest_run(raw, cfg["ingest"]["output_path"], cfg["ingest"]["quarantine_path"], "csv", cfg=cfg)

    df = pd.read_parquet(cfg["ingest"]["output_path"])
    state = collect_signals(df, cfg, raw)
    state["df"] = df
    state["stacker"] = incremental.load_stacker(cfg)

    def publish(frame) -> None:
        """What api.app.commit_bundle does: write where the console reads."""
        frame.to_parquet(cfg["fusion"]["alerts_parquet"], index=False)
        Path(cfg["fusion"]["alerts_json"]).write_text(json.dumps(
            {"alert_threshold": cfg["fusion"]["alert_threshold"],
             "alerts": json.loads(frame.to_json(orient="records"))}))

    publish(build_alerts(state, state["stacker"], cfg))   # as a full run would

    committed: dict = {}
    dropped: list[bool] = []

    def rebuild() -> dict:
        """What the API does on the next request after its cache is dropped."""
        if dropped:
            dropped.clear()
            fresh = pd.read_parquet(cfg["ingest"]["output_path"])
            state.update(collect_signals(fresh, cfg, raw))
            state["df"] = fresh
            state["stacker"] = incremental.load_stacker(cfg)
        return state

    redteam.router.state_provider = rebuild                  # type: ignore[attr-defined]
    def commit(bundle: dict) -> None:
        committed.update(bundle)
        publish(bundle["alerts_frame"])

    redteam.router.commit = commit                           # type: ignore[attr-defined]
    redteam.router.invalidate = lambda: dropped.append(True)  # type: ignore[attr-defined]
    return {"cfg": cfg, "raw": raw, "state": state, "committed": committed,
            "rebuild": rebuild, "dropped": dropped, "tmp": tmp_path}


def run_injection(demo, **kwargs) -> Run:
    run = Run(id=f"t{int(time.time()*1000)%100000}", request=Injection(**kwargs),
              started_at="test", started=time.perf_counter())
    execute(run, demo["rebuild"], demo["cfg"])
    return run


# --- every typology injects and completes ---------------------------------
@pytest.mark.parametrize("typology", TYPOLOGIES)
def test_every_typology_injects_and_completes(demo, typology):
    run = run_injection(demo, typology=typology, hops=3, total_btc=2.0, wallets=6, seed=7)

    assert run.status == "done", run.error
    result = run.result
    assert result["transactions"] > 0 and result["rows"] > 0
    assert result["entity_count"] > 0
    assert isinstance(result["detected"], bool)

    # Ground truth records the injection, so the eval can tell planted from
    # generated later.
    gt = json.loads((demo["raw"] / GROUND_TRUTH).read_text())
    assert gt["injections"], "the injection was not recorded in ground truth"
    last = gt["injections"][-1]
    assert last["typology"] == result["typology"]
    assert set(last["txids"]) <= set(gt["transactions"])
    for txid in last["txids"]:
        assert gt["transactions"][txid]["injected"] is True

    # Every stage is timed, and the whole run is nowhere near the 30s target.
    assert result["timing"]["stages"], "no stage timings were recorded"
    assert result["time_to_detect"] < 30


def test_peel_chain_is_a_chain_and_not_a_collector(demo):
    """Both use the same generator, and they must not inject the same thing.

    A judge who picks "peel chain" and gets a ransomware collector with twelve
    victims has been shown a different attack under the name they chose.
    """
    chain = run_injection(demo, typology="peel_chain", hops=6, total_btc=4.0, wallets=12, seed=31)
    collector = run_injection(demo, typology="ransomware_collector", hops=6, total_btc=4.0,
                              wallets=12, seed=37)
    assert chain.status == "done", chain.error
    assert collector.status == "done", collector.error

    gt = json.loads((demo["raw"] / GROUND_TRUTH).read_text())
    patterns = lambda run: [gt["transactions"][t]["pattern"] for t in run.result["txids"]]
    chain_payments = patterns(chain).count("ransomware_victim_payment")

    assert chain_payments <= 2, "a peel chain should not collect from a crowd"
    assert patterns(chain).count("ransomware_peel") >= 2, "and it should actually peel"
    assert patterns(collector).count("ransomware_victim_payment") > chain_payments

    # The run reports what was asked as well as what was built, so the
    # scoreboard and the result view can both say "peel chain".
    assert chain.result["requested_typology"] == "peel_chain"
    assert chain.result["typology"] == "ransomware_collector"


def test_a_miss_is_reported_with_every_engine_score(demo):
    """The honest half: when nothing fires, say so and show the numbers."""
    run = run_injection(demo, typology="coinjoin", wallets=6, total_btc=1.0, seed=3)
    assert run.status == "done", run.error
    result = run.result

    assert result["entity_scores"], "a run must report scores even when it detects nothing"
    for row in result["entity_scores"]:
        assert {"rule_score", "anomaly_score", "gnn_score", "taint_score", "risk_score"} <= set(row)
    assert result["threshold"] == demo["cfg"]["fusion"]["alert_threshold"]
    if not result["detected"]:
        assert all(row["risk_score"] < result["threshold"] for row in result["entity_scores"])


def test_the_origin_report_ranks_the_true_injected_ip(demo):
    run = run_injection(demo, typology="ransomware_collector", hops=3, total_btc=2.0,
                        wallets=6, broadcast="residential", seed=5)
    origin = run.result["origin"]
    assert origin["transactions"] > 0
    assert origin["best_rank"] == 1, "a residential broadcast should be named outright"
    assert all(d["true_origin_ip"] for d in origin["detail"])


# --- incremental == full ---------------------------------------------------
def test_incremental_matches_a_full_rerun(demo):
    """The proof that "incremental" is a speed-up and not a different answer.

    Both sides score with the same saved model — the point is whether folding
    new transactions into existing state produces the same signals as building
    everything from scratch, not whether two fits agree.
    """
    run = run_injection(demo, typology="layering", hops=3, total_btc=5.0, wallets=12, seed=13)
    assert run.status == "done", run.error
    injected = set(run.result["entities"])
    incremental_bundle = demo["committed"]

    cfg = demo["cfg"]
    full_df = pd.read_parquet(cfg["ingest"]["output_path"])
    full = collect_signals(full_df, cfg, demo["raw"])
    stacker = incremental_bundle["stacker"]

    a = incremental_bundle["signals"].set_index("entity_id")
    b = full["signals"].set_index("entity_id")

    assert injected <= set(b.index), "the full re-run did not see the injected entities"
    assert set(a.index) == set(b.index), "the two runs disagree about which entities exist"

    for entity in sorted(injected):
        left, right = a.loc[entity], b.loc[entity]
        for signal in ("rule_score", "gnn_score", "taint_score"):
            assert left[signal] == pytest.approx(right[signal], abs=1e-9), (
                f"{signal} differs for {entity}: {left[signal]} vs {right[signal]}"
            )
        # IsolationForest is refit over the whole population in both paths with
        # a fixed seed, so this is an equality too — it is asserted with a
        # tolerance only because it is a float pipeline, not because the two
        # are expected to differ.
        assert left["anomaly_score"] == pytest.approx(right["anomaly_score"], abs=1e-6)

    left_scores = pd.Series(stacker.score(a.loc[sorted(injected)].reset_index()),
                            index=sorted(injected))
    right_scores = pd.Series(stacker.score(b.loc[sorted(injected)].reset_index()),
                             index=sorted(injected))
    pd.testing.assert_series_equal(left_scores, right_scores, atol=1e-6, check_names=False)


def test_incremental_is_not_slower_than_a_full_rerun(demo):
    """If it were, there would be no reason for it to exist."""
    run = run_injection(demo, typology="peel_chain", hops=4, total_btc=3.0, wallets=8, seed=17)
    incremental_seconds = run.result["timing"]["total_seconds"]

    cfg = demo["cfg"]
    start = time.perf_counter()
    collect_signals(pd.read_parquet(cfg["ingest"]["output_path"]), cfg, demo["raw"])
    full_seconds = time.perf_counter() - start

    assert incremental_seconds <= full_seconds * 1.35, (
        f"incremental {incremental_seconds:.2f}s vs full {full_seconds:.2f}s — "
        "the incremental path has stopped paying for itself"
    )


# --- reset -----------------------------------------------------------------
def test_reset_restores_the_dataset_byte_for_byte(demo, monkeypatch):
    cfg = demo["cfg"]
    before = file_hashes(demo["raw"])
    assert before, "nothing to snapshot"

    take_snapshot(cfg, force=True)
    run = run_injection(demo, typology="ransomware_collector", hops=3, total_btc=2.0,
                        wallets=6, seed=23)
    assert run.status == "done", run.error

    after_injection = file_hashes(demo["raw"])
    assert after_injection != before, "the injection did not change the dataset"

    restored = redteam.reset()
    assert restored["hashes_match"] is True
    assert file_hashes(demo["raw"]) == before, "reset did not restore the dataset exactly"

    # The alert list the console reads is derived from the dataset, so it comes
    # back too — otherwise the queue still shows an attack that was undone.
    alerts = Path(cfg["fusion"]["alerts_json"])
    assert alerts.exists()
    entities = {a["entity_id"] for a in json.loads(alerts.read_text())["alerts"]}
    assert not (set(run.result["entities"]) & entities), (
        "the injected entity is still in the alert list after a reset")

    # And the run history is cleared, so the scoreboard starts again.
    assert redteam.list_runs()["total"] == 0


def test_reset_drops_the_state_built_from_the_injection(demo):
    """Restoring the files is only half of it.

    A server that still holds a graph containing the injected transactions
    shows the console an attack that is no longer in the dataset — and folds
    those rows in a second time on the next run, which is how the same seed
    ends up rejected as a duplicate.
    """
    take_snapshot(demo["cfg"], force=True)
    first = run_injection(demo, typology="layering", hops=3, total_btc=2.0, wallets=8, seed=101)
    assert first.status == "done", first.error

    redteam.reset()
    assert demo["dropped"], "reset did not drop the cached state"

    # The same seed mints the same addresses. It only injects cleanly if the
    # state really was rebuilt from the restored dataset.
    again = run_injection(demo, typology="layering", hops=3, total_btc=2.0, wallets=8, seed=101)
    assert again.status == "done", again.error
    assert again.result["entities"] == first.result["entities"]


def test_reset_without_a_snapshot_says_so(demo):
    from fastapi import HTTPException

    snapshot = Path(demo["cfg"]["redteam"]["snapshot_dir"])
    assert not snapshot.exists()
    with pytest.raises(HTTPException) as caught:
        redteam.reset()
    assert caught.value.status_code == 409
    assert "nothing has been injected" in caught.value.detail
