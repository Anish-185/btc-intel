"""Live monitoring: an arriving file is scored, and arriving twice is not.

The idempotence test is the one that matters. A monitoring system re-reads
files — a retried copy, an overlapping export, an operator dropping the same
capture twice — and folding a transaction in a second time would double every
amount on it and invent a wallet that never existed.
"""

from __future__ import annotations

import json
import shutil
import threading
import time
from pathlib import Path

import pandas as pd
import pytest

import config
import custody
from api import monitor
from fusion import incremental
from fusion.pipeline import build_alerts, collect_signals
from generator.main import build_parser, generate
from ingest.pipeline import run as ingest_run

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


@pytest.fixture
def console(tmp_path, monkeypatch):
    """A small dataset already analysed, plus an empty inbox to drop into."""
    cfg = json.loads(json.dumps(config.load()))
    raw = tmp_path / "raw"
    cfg["ingest"]["input_dir"] = str(raw)
    cfg["ingest"]["output_path"] = str(tmp_path / "transactions.parquet")
    cfg["ingest"]["quarantine_path"] = str(tmp_path / "quarantine.parquet")
    cfg["fusion"]["alerts_parquet"] = str(tmp_path / "final_alerts.parquet")
    cfg["fusion"]["alerts_json"] = str(tmp_path / "final_alerts.json")
    cfg["fusion"]["model_path"] = str(tmp_path / "stacker.joblib")
    cfg["custody"]["ledger_path"] = str(tmp_path / "custody.jsonl")
    cfg["monitor"].update({"inbox_dir": str(tmp_path / "inbox"),
                           "archive_dir": str(tmp_path / "archive"),
                           "scratch_dir": str(tmp_path / "scratch"),
                           "settle_seconds": 0.0, "poll_seconds": 0.05})
    monkeypatch.setattr(config, "load", lambda *a, **k: json.loads(json.dumps(cfg)))

    generate(build_parser().parse_args(
        ["--n-actors", "50", "--n-transactions", "300", "--output", str(raw),
         "--seed", "5", "--formats", "csv"]), cfg)
    ingest_run(raw, cfg["ingest"]["output_path"], cfg["ingest"]["quarantine_path"], "csv", cfg=cfg)

    df = pd.read_parquet(cfg["ingest"]["output_path"])
    state = collect_signals(df, cfg, raw)
    state["df"] = df
    state["stacker"] = incremental.load_stacker(cfg)
    state["alerts_frame"] = build_alerts(state, state["stacker"], cfg)

    committed: dict = {}
    return {"cfg": cfg, "state": state, "committed": committed, "tmp": tmp_path,
            "provider": lambda: state, "commit": committed.update}


def arrival(console, **kwargs) -> Path:
    return monitor.make_batch(console["cfg"], **kwargs)


def handle(console, path: Path) -> dict:
    return monitor.process(path, console["provider"], console["commit"], console["cfg"])


def test_an_arriving_file_is_ingested_scored_and_published(console):
    before = len(console["state"]["df"])
    result = handle(console, arrival(console, transactions=30, actors=10, seed=101))

    assert result["new_rows"] > 0 and result["transactions"] > 0
    assert result["duplicates"] == 0
    # The bundle the console reads was replaced, not just computed.
    assert console["committed"], "the updated bundle was never committed"
    assert len(console["committed"]["df"]) == before + result["new_rows"]
    # And what a restart would read agrees with what is in memory.
    assert len(pd.read_parquet(console["cfg"]["ingest"]["output_path"])) == before + result["new_rows"]


def test_the_same_file_twice_changes_nothing_the_second_time(console):
    path = arrival(console, transactions=30, actors=10, seed=202)
    copy = path.parent / f"copy-{path.name}"
    shutil.copy2(path, copy)

    first = handle(console, path)
    assert first["new_rows"] > 0

    rows_after_first = len(console["committed"]["df"])
    second = handle(console, copy)

    assert second["new_rows"] == 0, "the same transactions were folded in twice"
    assert second["transactions"] == 0
    assert second["duplicates"] == first["transactions"]
    assert len(console["committed"]["df"]) == rows_after_first


def test_alerts_are_reported_only_for_what_arrived(console):
    """A feed that repeats yesterday's alerts is noise, not monitoring."""
    result = handle(console, arrival(console, transactions=60, actors=16, seed=303))
    reported = {a["entity_id"] for a in result["alerts"]}
    everything = set(console["committed"]["alerts_frame"]["entity_id"])

    assert reported <= everything, "it reported an alert the system does not hold"
    # Every alert in the feed belongs to an entity this file actually touched.
    assert reported <= set(result["entities"]), (
        "the feed named an entity the arriving transactions never involved")


def test_a_file_with_the_wrong_schema_is_rejected_out_loud(console):
    """Rejected rows are quarantined, not silently counted as "nothing new".

    A feed whose upstream has changed format delivers files that produce no
    transactions. If the console draws that the same way it draws a replayed
    file, nobody notices for a day.
    """
    inbox = Path(console["cfg"]["monitor"]["inbox_dir"])
    inbox.mkdir(parents=True, exist_ok=True)
    broken = inbox / "capture-broken.csv"
    broken.write_text("this,is,not\nthe,expected,schema\n")

    result = handle(console, broken)
    assert result["new_rows"] == 0
    assert result["quarantined"] > 0, "rejected rows must be counted"
    assert "rejected" in result["reason"]


def test_the_watch_loop_survives_a_file_it_cannot_read(console):
    """The failure mode of a monitoring system must not be "it stopped"."""
    inbox = Path(console["cfg"]["monitor"]["inbox_dir"])
    inbox.mkdir(parents=True, exist_ok=True)
    (inbox / "capture-unreadable.csv").write_bytes(b"\x00\x01\x02 not a csv at all")

    monitor.WATCH.stop.clear()
    thread = threading.Thread(
        target=monitor.watch_loop,
        args=(console["provider"], console["commit"], console["cfg"]), daemon=True)
    thread.start()
    deadline = time.time() + 10
    while time.time() < deadline and list(inbox.glob("*.csv")):
        time.sleep(0.05)
    monitor.WATCH.stop.set()
    thread.join(timeout=10)

    assert not thread.is_alive(), "the watch loop did not stop when asked"
    # However it turned out, the file was handled and moved aside: a watcher
    # that leaves a file it cannot read in the inbox re-reads it forever.
    assert not list(inbox.glob("*.csv")), "the unreadable file was left in the inbox"
    archive = Path(console["cfg"]["monitor"]["archive_dir"])
    assert list(archive.rglob("*capture-unreadable.csv")), "it was not archived either"


def test_every_arrival_is_written_into_the_custody_ledger(console):
    result = handle(console, arrival(console, transactions=20, actors=8, seed=404))
    entries = custody.read(console["cfg"])
    arrivals = [e for e in entries if e["action"] == "monitor.arrival"]

    assert arrivals, "an arrival must be recorded"
    last = arrivals[-1]
    assert last["detail"]["transactions"] == result["transactions"]
    assert last["detail"]["files"][0]["sha256"], "the arriving file is hashed on arrival"
    assert custody.verify(console["cfg"])["chain_intact"]


def test_status_reports_what_it_is_watching(console):
    monitor.WATCH.inbox = console["cfg"]["monitor"]["inbox_dir"]
    status = monitor.WATCH.status()
    assert set(status) >= {"running", "files", "rows", "transactions", "duplicates",
                           "alerts", "errors", "inbox"}
