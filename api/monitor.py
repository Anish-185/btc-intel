"""Live monitoring: watch for traffic arriving and score it as it lands.

The rest of this system is a batch pipeline — point it at a dump, get a ranked
alert list. That answers "analysis". It does not answer *monitoring*, which is
the other half of the problem: metadata keeps arriving, and an analyst wants to
know within seconds if the new traffic touches something that matters.

So this watches a drop directory. A file appears — a collection run, an export
from an upstream capture, another agency's batch — and it is parsed, validated,
folded into the graph the API already holds, and scored. New alerts are pushed
to the console over the same server-sent-events channel the red-team page uses.

**It re-uses the incremental path rather than re-running the pipeline**
(`fusion/incremental.py`), which is what makes this cheap enough to do on every
arriving file: the stages that scale with the whole stored dataset are the only
ones recomputed, and nothing is retrained.

Three things worth knowing about how it behaves:

  * **Arrivals are idempotent.** A file re-dropped, or overlapping with one
    already seen, contributes only its unseen transactions. Re-processing a
    transaction would double every amount on it.
  * **A file is read only once it stops growing.** A writer still copying into
    the directory would otherwise be parsed half-written, and the second half
    would be quarantined as malformed.
  * **A bad file does not stop the watch.** It is recorded, reported to the
    console, and the watcher goes back to waiting — the failure mode of a
    monitoring system must not be "it stopped monitoring".

    python -m api.monitor feed --batches 6 --interval 4   # synthetic arrivals
"""

from __future__ import annotations

import json
import logging
import queue
import shutil
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

import config
import custody
from fusion import incremental
from graph.builder import TRANSACTION, WALLET, nodes_of_type
from ingest.pipeline import run as ingest_run

log = logging.getLogger(__name__)
router = APIRouter(prefix="/monitor", tags=["monitor"])

#: What the console is told, and what a reconnecting page replays.
FEED_LIMIT = 200


@dataclass
class Watch:
    """The state of the watcher. One per process — this is a console, not a
    multi-tenant service."""

    running: bool = False
    started_at: str | None = None
    inbox: str = ""
    files: int = 0
    rows: int = 0
    transactions: int = 0
    duplicates: int = 0
    alerts: int = 0
    errors: int = 0
    last_event: str | None = None
    feed: list[dict] = field(default_factory=list)
    subscribers: list["queue.Queue[dict]"] = field(default_factory=list)
    thread: threading.Thread | None = None
    stop: threading.Event = field(default_factory=threading.Event)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def emit(self, event: dict) -> None:
        event = {**event, "at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        with self.lock:
            self.feed.append(event)
            del self.feed[:-FEED_LIMIT]
            self.last_event = event["at"]
            for subscriber in list(self.subscribers):
                subscriber.put(event)

    def status(self) -> dict:
        return {"running": self.running, "started_at": self.started_at, "inbox": self.inbox,
                "files": self.files, "rows": self.rows, "transactions": self.transactions,
                "duplicates": self.duplicates, "alerts": self.alerts, "errors": self.errors,
                "last_event": self.last_event, "watchers": len(self.subscribers)}


WATCH = Watch()


def inbox_dir(cfg: dict) -> Path:
    return Path(cfg["monitor"]["inbox_dir"])


def archive_dir(cfg: dict) -> Path:
    return Path(cfg["monitor"]["archive_dir"])


def _settled(path: Path, cfg: dict) -> bool:
    """True once the file has stopped growing.

    A writer copying a hundred megabytes in is not finished because the file
    exists. Two reads of the same size, a moment apart, is the cheapest test
    that does not need the writer's cooperation.
    """
    try:
        first = path.stat().st_size
        time.sleep(cfg["monitor"]["settle_seconds"])
        return path.exists() and path.stat().st_size == first
    except OSError:
        return False


def pending(cfg: dict) -> list[Path]:
    """Files waiting in the inbox, oldest first — arrival order is evidence."""
    directory = inbox_dir(cfg)
    if not directory.exists():
        return []
    suffixes = {".csv", ".json", ".xml"}
    return sorted((p for p in directory.iterdir()
                   if p.is_file() and p.suffix.lower() in suffixes),
                  key=lambda p: p.stat().st_mtime)


def known_txids(state: dict) -> set[str]:
    """Which transactions the graph already holds."""
    return set(nodes_of_type(state["graph"], TRANSACTION))


def ingest_file(path: Path, cfg: dict) -> pd.DataFrame:
    """Parse, validate and enrich one arriving file, in a scratch location.

    The main parquet is not touched here: nothing is committed until the rows
    have been scored, so a file that fails mid-way leaves no half-ingested
    dataset behind.
    """
    scratch = Path(cfg["monitor"]["scratch_dir"])
    scratch.mkdir(parents=True, exist_ok=True)
    summary = ingest_run(path, output=scratch / "arrival.parquet",
                         quarantine=scratch / "arrival_quarantine.parquet",
                         fmt=path.suffix.lstrip(".").lower(), cfg=cfg,
                         record_custody=False)   # the arrival entry covers this
    frame = pd.read_parquet(scratch / "arrival.parquet")
    frame.attrs["summary"] = summary
    return frame


def process(path: Path, state_provider, commit, cfg: dict, archive: bool = True) -> dict:
    """One arriving file: ingest, fold in, score, publish, file away.

    Archiving is part of handling the file rather than a step the caller takes
    afterwards, because the custody entry has to name where the file *is*. A
    record pointing at an inbox the file has already left reads as a missing
    exhibit at exactly the moment somebody is checking.
    """
    started = time.perf_counter()
    rows = ingest_file(path, cfg)
    summary = rows.attrs.get("summary", {})

    # Everything that touches the shared graph happens under one lock: a
    # red-team injection and an arriving file must not fold rows into the same
    # structure at the same time.
    with incremental.LOCK:
        state = state_provider()
        seen = known_txids(state)
        fresh = rows[~rows["txid"].isin(seen)].reset_index(drop=True)
        duplicates = int(rows["txid"].nunique() - fresh["txid"].nunique()) if len(rows) else 0
        if fresh.empty:
            filed = _archive(path, cfg, "done") if archive else path
            # Nothing to fold in — but *why* matters to whoever is watching.
            # A file every row of which was rejected is not the same event as a
            # file that was simply a replay, and a feed that shows both as
            # "0 new" hides a broken upstream feed until someone goes looking.
            custody.record("monitor.arrival", {
                "files": [custody.seal(filed)] if filed.exists() else [],
                "rows": 0, "transactions": 0, "duplicates": duplicates,
                "quarantined": summary.get("quarantined", 0), "alerts": 0}, cfg=cfg)
            return {"file": path.name, "rows": len(rows), "new_rows": 0,
                    "transactions": 0, "duplicates": duplicates,
                    "quarantined": summary.get("quarantined", 0),
                    "entities": [], "alerts": [],
                    "reason": ("every row was rejected — wrong schema?"
                               if summary.get("quarantined") and not len(rows)
                               else "already seen"),
                    "seconds": round(time.perf_counter() - started, 2)}

        before = set(state.get("alerts_frame", pd.DataFrame(columns=["entity_id"]))["entity_id"]) \
            if state.get("alerts_frame") is not None else set()
        bundle = incremental.update(state, fresh, cfg)
        # The parquet the console reads on a cold start has to agree with the
        # graph in memory, or a restart would silently lose the arrivals.
        bundle["df"].to_parquet(cfg["ingest"]["output_path"], index=False)
        commit(bundle)

    alerts = bundle["alerts_frame"]
    raised = alerts[~alerts["entity_id"].isin(before)] if before else alerts
    # Only the alerts this file is responsible for: an entity that was already
    # alerting is not news, and a monitoring feed that repeats itself is noise.
    touched = set(fresh["txid"])
    entity_of = bundle["features"].entity_of
    involved = {entity_of(w) for w in _wallets_of(bundle, touched)} - {None}
    raised = raised[raised["entity_id"].isin(involved)]

    # Seal the arriving file where it now lives, plus everything this arrival
    # rewrote: the stored dataset and the alert list the console reads.
    filed = _archive(path, cfg, "done") if archive else path
    sealed = [p for p in (filed, Path(cfg["ingest"]["output_path"]),
                          Path(cfg["fusion"]["alerts_parquet"]),
                          Path(cfg["fusion"]["alerts_json"])) if p.exists()]
    custody.record("monitor.arrival", {
        "files": [custody.seal(p) for p in sealed],
        "rows": len(fresh), "transactions": int(fresh["txid"].nunique()),
        "duplicates": duplicates, "alerts": int(len(raised))}, cfg=cfg)

    return {"file": path.name, "rows": len(rows), "new_rows": len(fresh),
            "transactions": int(fresh["txid"].nunique()), "duplicates": duplicates,
            "quarantined": summary.get("quarantined", 0),
            "entities": sorted(involved),
            "alerts": json.loads(raised.to_json(orient="records")) if len(raised) else [],
            "seconds": round(time.perf_counter() - started, 2)}


def _wallets_of(bundle: dict, txids: set[str]) -> set[str]:
    """The wallets that the arriving transactions actually moved value between."""
    graph = bundle["graph"]
    wallets = set()
    for txid in txids:
        if txid in graph:
            wallets.update(graph.predecessors(txid))
            wallets.update(graph.successors(txid))
    return {w for w in wallets if graph.nodes[w].get("node_type") == WALLET}


def watch_loop(state_provider, commit, cfg: dict) -> None:
    """Poll the inbox until asked to stop.

    Polling rather than inotify: one dependency fewer, and a directory that an
    air-gapped operator drops files into by hand does not need millisecond
    latency. The interval is in config.
    """
    WATCH.emit({"type": "started", "inbox": str(inbox_dir(cfg))})
    while not WATCH.stop.is_set():
        try:
            for path in pending(cfg):
                if WATCH.stop.is_set():
                    break
                if not _settled(path, cfg):
                    continue                      # still being written
                WATCH.emit({"type": "file", "name": path.name,
                            "bytes": path.stat().st_size})
                try:
                    result = process(path, state_provider, commit, cfg)
                except Exception as exc:          # one bad file, not a dead watch
                    log.exception("monitor: %s failed", path.name)
                    WATCH.errors += 1
                    WATCH.emit({"type": "error", "name": path.name,
                                "error": f"{type(exc).__name__}: {exc}"})
                    _archive(path, cfg, "failed")
                    continue

                WATCH.files += 1
                WATCH.rows += result["new_rows"]
                WATCH.transactions += result["transactions"]
                WATCH.duplicates += result["duplicates"]
                WATCH.alerts += len(result["alerts"])
                WATCH.emit({"type": "processed", **result})
        except Exception:                          # the loop itself must survive
            log.exception("monitor: poll failed")
            WATCH.errors += 1
        WATCH.stop.wait(cfg["monitor"]["poll_seconds"])
    WATCH.running = False
    WATCH.emit({"type": "stopped"})


def _archive(path: Path, cfg: dict, outcome: str) -> Path:
    """Move a handled file aside, keeping the original name and the outcome.

    Deleting it would destroy the thing the custody entry points at, so it is
    moved, never removed. Returns where it ended up — the path the ledger then
    records — or the original path if it could not be moved, so the record
    always names somewhere the file actually is.
    """
    target = archive_dir(cfg) / outcome
    target.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    destination = target / f"{stamp}-{path.name}"
    try:
        shutil.move(str(path), destination)
        return destination
    except OSError as exc:
        log.warning("could not archive %s: %s", path, exc)
        return path


def register(app, state_provider, commit) -> None:
    router.state_provider = state_provider          # type: ignore[attr-defined]
    router.commit = commit                          # type: ignore[attr-defined]
    app.include_router(router)


# --- endpoints -------------------------------------------------------------
@router.post("/start")
def start() -> dict:
    """Begin watching. Idempotent: starting a running watch changes nothing."""
    cfg = config.load()
    if WATCH.running:
        return {"already_running": True, **WATCH.status()}
    inbox_dir(cfg).mkdir(parents=True, exist_ok=True)
    WATCH.stop.clear()
    WATCH.running = True
    WATCH.started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    WATCH.inbox = str(inbox_dir(cfg))
    WATCH.thread = threading.Thread(
        target=watch_loop,
        args=(router.state_provider, router.commit, cfg),   # type: ignore[attr-defined]
        daemon=True, name="monitor")
    WATCH.thread.start()
    return {"already_running": False, **WATCH.status()}


@router.post("/stop")
def stop() -> dict:
    WATCH.stop.set()
    WATCH.running = False
    return WATCH.status()


@router.get("/status")
def status() -> dict:
    cfg = config.load()
    return {**WATCH.status(), "pending": [p.name for p in pending(cfg)],
            "poll_seconds": cfg["monitor"]["poll_seconds"]}


@router.get("/feed")
def feed(limit: int = 50) -> dict:
    """What has happened recently — what a page draws before it subscribes."""
    with WATCH.lock:
        return {"events": WATCH.feed[-limit:], "status": WATCH.status()}


@router.get("/events")
def events() -> StreamingResponse:
    """Server-sent events: every arrival, and every alert it raised."""
    subscriber: "queue.Queue[dict]" = queue.Queue()
    with WATCH.lock:
        backlog = list(WATCH.feed[-20:])
        WATCH.subscribers.append(subscriber)

    def stream():
        try:
            for event in backlog:
                yield f"data: {json.dumps(event)}\n\n"
            while True:
                try:
                    event = subscriber.get(timeout=20)
                except queue.Empty:
                    yield ": keep-alive\n\n"       # proxies drop a silent stream
                    continue
                yield f"data: {json.dumps(event)}\n\n"
        finally:
            with WATCH.lock:
                if subscriber in WATCH.subscribers:
                    WATCH.subscribers.remove(subscriber)

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"cache-control": "no-cache",
                                      "x-accel-buffering": "no"})


@router.post("/simulate")
def simulate(transactions: int = 40, actors: int = 12, seed: int | None = None) -> dict:
    """Drop one batch of fresh synthetic traffic into the inbox.

    For demonstrating the watch without a second terminal. It writes a file and
    returns; the watcher picks it up on its next poll exactly as it would pick
    up a real collection run.
    """
    return {"file": str(make_batch(config.load(), transactions, actors, seed))}


def make_batch(cfg: dict, transactions: int = 40, actors: int = 12,
               seed: int | None = None) -> Path:
    """Generate a small dataset and put its CSV in the inbox.

    Fresh wallets every time — the generator mints them from the seed — so the
    arrivals are new traffic rather than a replay of what is already stored.
    """
    import random
    import tempfile
    from argparse import Namespace

    from generator.main import build_parser, generate

    seed = seed if seed is not None else random.randrange(2**31)
    staging = Path(tempfile.mkdtemp(prefix="btc-intel-arrival-"))
    args: Namespace = build_parser().parse_args(
        ["--n-actors", str(actors), "--n-transactions", str(transactions),
         "--output", str(staging), "--seed", str(seed), "--formats", "csv"])
    generate(args, cfg)

    inbox = inbox_dir(cfg)
    inbox.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    target = inbox / f"capture-{stamp}-{seed}.csv"
    shutil.copy2(staging / "transactions.csv", target)
    shutil.rmtree(staging, ignore_errors=True)
    return target


def main(argv=None) -> None:
    """`python -m api.monitor feed` — drop batches in, on an interval."""
    import argparse

    ap = argparse.ArgumentParser(prog="api.monitor", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["feed"])
    ap.add_argument("--batches", type=int, default=5)
    ap.add_argument("--interval", type=float, default=5.0)
    ap.add_argument("--transactions", type=int, default=40)
    args = ap.parse_args(argv)

    cfg = config.load()
    for n in range(args.batches):
        path = make_batch(cfg, args.transactions)
        print(f"{n + 1}/{args.batches}  {path}")
        if n + 1 < args.batches:
            time.sleep(args.interval)


if __name__ == "__main__":
    main()
