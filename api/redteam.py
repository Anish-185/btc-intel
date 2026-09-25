"""Red team: let someone attack the system while it is being demonstrated.

A judge picks a laundering typology, sets its parameters, and injects it into
the dataset the detectors have already been run over. The stack re-runs over
the new transactions and reports what it found — and, when it found nothing,
every engine's score against the threshold it did not clear.

Two things this endpoint refuses to do:

  * **Retrain.** The GNN and the stacker are loaded and used for inference. A
    detector refitted around the attack it is being asked to find has not been
    tested, it has been told the answer.
  * **Hide a miss.** A run that detects nothing returns the same detail as one
    that succeeds. The interesting demo is the one where an attack gets
    through and the room can see exactly how close it came.

State lives for the life of the process: this is a demo surface, not a case
management system. `POST /redteam/reset` puts the dataset back to the snapshot
taken before the first injection.
"""

from __future__ import annotations

import hashlib
import json
import queue
import random
import shutil
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import pandas as pd
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

import config
import custody
from engines.propagation.estimators import CALIBRATION_BASIS, estimate_origin
from engines.propagation.tree import build_trees
from fusion import incremental
from generator.inject import inject_pattern
from generator.main import GROUND_TRUTH
from ingest.pipeline import run as ingest_run

router = APIRouter(prefix="/redteam", tags=["redteam"])

TYPOLOGIES = ("ransomware_collector", "peel_chain", "layering", "coinjoin",
              "same_actor_cluster")

#: Typologies that are crimes, and whose injection the detector is expected to
#: alert on. The other two are not, and that is pre-registered rather than
#: decided here: `docs/detection_unit_protocol.md` states that CoinJoin is
#: mixing — suspicious, not by itself illegal — and that `same_actor_cluster`
#: is a test of the clustering rather than an offence. Neither is an actor, so
#: neither is scored as a detection.
CRIME_TYPOLOGIES = ("ransomware_collector", "peel_chain", "layering")
NON_ACTOR_TYPOLOGIES = ("coinjoin", "same_actor_cluster")

#: Files that make up "the dataset", for snapshot and reset.
SNAPSHOT_GLOBS = ("transactions.csv", "transactions.json", "transactions.xml",
                  GROUND_TRUTH, "synthetic_watchlist.json", "node_intel.json")


# --- request and run state -------------------------------------------------
class Injection(BaseModel):
    """What the judge chose. Everything has a default, so "surprise me" on the
    front end only has to fill in what it wants to vary."""

    typology: Literal["ransomware_collector", "peel_chain", "layering", "coinjoin",
                      "same_actor_cluster"] = "ransomware_collector"
    hops: int = Field(4, ge=2, le=8, description="chain depth / layering depth")
    total_btc: float = Field(2.0, gt=0, le=10_000)
    window_hours: float = Field(24.0, gt=0, le=24 * 30)
    wallets: int = Field(8, ge=2, le=60, description="wallets the pattern spans")
    broadcast: Literal["residential", "tor_exit", "hosting", "relay_heavy"] = "residential"
    seed: int | None = None


@dataclass
class Run:
    id: str
    request: Injection
    status: str = "running"           # running | done | failed
    started_at: str = ""
    started: float = 0.0
    stages: list[dict] = field(default_factory=list)
    result: dict | None = None
    error: str | None = None
    seq: int = 0
    events: "queue.Queue[dict]" = field(default_factory=queue.Queue)

    def emit(self, event: dict) -> None:
        # The sequence number is what stops a late subscriber seeing a stage
        # twice: the stream replays what already happened, then skips the
        # queued copies of those same events.
        self.seq += 1
        event = {**event, "seq": self.seq,
                 "elapsed": round(time.perf_counter() - self.started, 2)}
        if event.get("type") == "stage":
            self.stages.append(event)
        self.events.put(event)

    def summary(self) -> dict:
        result = self.result or {}
        return {
            "run_id": self.id,
            "status": self.status,
            "started_at": self.started_at,
            "typology": self.request.typology,
            "params": self.request.model_dump(),
            "detected": result.get("detected"),
            "time_to_detect": result.get("time_to_detect"),
            "origin_rank": result.get("origin", {}).get("best_rank"),
            "error": self.error,
        }


RUNS: dict[str, Run] = {}
ORDER: list[str] = []
LOCK = threading.Lock()


# --- the dataset the demo runs on -----------------------------------------
def dataset_dir(cfg: dict) -> Path:
    return Path(cfg["ingest"]["input_dir"])


def snapshot_dir(cfg: dict) -> Path:
    return Path(cfg["redteam"]["snapshot_dir"])


def _require_dataset(cfg: dict) -> Path:
    directory = dataset_dir(cfg)
    if not (directory / GROUND_TRUTH).exists():
        raise HTTPException(
            409,
            f"no generated dataset at {directory} — red team injects into the dataset the "
            "pipeline was run on, so it needs the generator's raw output (transactions.csv "
            f"and {GROUND_TRUTH}) there. Generate one with `python -m generator.main "
            f"--output {directory}` and re-run the pipeline.",
        )
    return directory


def artefacts(cfg: dict) -> list[Path]:
    """What the pipeline derives from the dataset.

    Restored alongside it, because a reset that puts the transactions back but
    leaves the alert list alone shows the console an attack that is no longer
    in the data — and the judge is looking at the console, not at the CSV.
    """
    return [Path(cfg["ingest"]["output_path"]),
            Path(cfg["fusion"]["alerts_parquet"]),
            Path(cfg["fusion"]["alerts_json"])]


def file_hashes(directory: Path) -> dict[str, str]:
    """Content hashes of the dataset's files — what `reset` is checked against."""
    out = {}
    for name in SNAPSHOT_GLOBS:
        path = directory / name
        if path.exists():
            out[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return out


def take_snapshot(cfg: dict, force: bool = False) -> dict:
    """Copy the dataset aside, once, before the first injection of the session."""
    source = _require_dataset(cfg)
    target = snapshot_dir(cfg)
    if target.exists() and not force:
        return {"snapshot": str(target), "created": False, "files": sorted(file_hashes(target))}
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True, exist_ok=True)
    for name in SNAPSHOT_GLOBS:
        path = source / name
        if path.exists():
            shutil.copy2(path, target / name)
    for path in artefacts(cfg):
        if path.exists():
            shutil.copy2(path, target / path.name)
    return {"snapshot": str(target), "created": True, "files": sorted(file_hashes(target))}


# --- the run ---------------------------------------------------------------
def _params_for(request: Injection) -> tuple[str, dict]:
    """Translate the judge's controls into the generator's own parameters.

    The form speaks in what an investigator cares about — depth, amount, how
    many wallets, over how long — and each typology reads those differently.
    """
    hops, btc, wallets = request.hops, request.total_btc, request.wallets
    window = request.window_hours

    if request.typology == "ransomware_collector":
        # Many victims paying one collector is the shape that matters here, so
        # `wallets` is the victim count and the pot is split between them.
        return "ransomware_collector", {
            "victims": [max(wallets, 3), max(wallets, 3) + 4],
            "peel_hops": [hops, hops],
            "ransom_btc": [btc / max(wallets, 3) * 0.8, btc / max(wallets, 3) * 1.2],
        }
    if request.typology == "peel_chain":
        # The same generator, used for its other half: one payment in, then a
        # long chain that peels a slice at every hop. Asking for a peel chain
        # and getting a collector with twelve victims would be a different
        # attack under the name the judge chose.
        return "ransomware_collector", {
            "victims": [1, 2],
            "peel_hops": [hops, hops],
            "ransom_btc": [btc * 0.9, btc * 1.1],
        }
    if request.typology == "layering":
        fan = max(2, min(wallets // max(hops, 1), 10))
        return "layering", {"fan": [fan, fan + 1], "depth": [hops, hops],
                            "amount_btc": [btc * 0.9, btc * 1.1]}
    if request.typology == "coinjoin":
        return "coinjoin", {"participants": [wallets, wallets + 2],
                            "denomination_btc": [round(btc / max(wallets, 2), 6)]}
    return "same_actor_cluster", {
        "wallets": [wallets, wallets + 2],
        "window_seconds": int(window * 3600),
        "amount_btc": [btc / max(wallets, 2) * 0.8, btc / max(wallets, 2) * 1.2],
    }


def _broadcast_overrides(cfg: dict, choice: str) -> dict:
    """How the injected traffic reaches the network.

    The generator decides per broadcast whether it is masked; forcing the rate
    to 0 or 1 is how a judge says "send this over Tor" or "straight from a
    home connection".
    """
    cfg = json.loads(json.dumps(cfg))
    broadcast = cfg["generator"]["broadcast"]
    if choice == "residential":
        broadcast.update({"tor_rate": 0.0, "hosting_rate": 0.0})
    elif choice == "tor_exit":
        broadcast.update({"tor_rate": 1.0, "hosting_rate": 0.0})
    elif choice == "hosting":
        broadcast.update({"tor_rate": 0.0, "hosting_rate": 1.0})
    elif choice == "relay_heavy":
        # Every hop observed: the tree is full of relays, which is the hardest
        # case for origin estimation and the most honest one to demonstrate.
        broadcast.update({"tor_rate": 0.0, "hosting_rate": 0.0})
        cfg["gossip"]["relay_observation_rate"] = 0.9
    return cfg


def _origin_report(new_rows: pd.DataFrame, txids: list[str], truth: dict,
                   intel, cfg: dict) -> dict:
    """Where the estimator thought the injected broadcasts came from.

    Rank is the position of the *true* origin IP in the estimator's ranked
    candidates — 1 is "named it", `null` is "it was not in the observed tree
    at all", which is a property of the evidence rather than of the estimator.
    """
    trees = build_trees(new_rows)
    ranks, details = [], []
    for txid in txids:
        tree = trees.get(txid)
        meta = truth.get(txid) or {}
        true_ip = meta.get("true_origin_ip")
        if tree is None or not true_ip:
            continue
        estimate = estimate_origin(tree, intel, cfg)
        ordered = [ip for ip, _ in estimate.ranked]
        rank = ordered.index(true_ip) + 1 if true_ip in ordered else None
        if rank:
            ranks.append(rank)
        details.append({
            "txid": txid,
            "true_origin_ip": true_ip,
            "estimated_origin_ip": estimate.ip,
            "ip_class": estimate.ip_class,
            "confidence": estimate.confidence,
            "low_confidence_origin": estimate.low_confidence,
            "probability": estimate.confidence,
            "calibration_basis": CALIBRATION_BASIS,
            "validity": estimate.validity.as_dict(),
            "rank": rank,
            "observed": true_ip in tree.ips,
        })
    return {
        "transactions": len(details),
        "named_exactly": sum(1 for d in details if d["rank"] == 1),
        "in_candidates": len(ranks),
        "best_rank": min(ranks) if ranks else None,
        "detail": details[:25],
        "caveat": ("rank is over the estimator's ranked candidates; a null rank means the "
                   "true origin never appeared in the observed hops, which no estimator "
                   "can fix"),
    }


def execute(run: Run, state_provider, cfg: dict) -> None:
    """One red-team run, start to finish. Runs on its own thread."""
    try:
        directory = _require_dataset(cfg)
        run.emit({"type": "stage", "name": "snapshot", "detail": "keeping a copy to reset to"})
        take_snapshot(cfg)

        # Read the current state BEFORE anything is injected. Built afterwards
        # it would already contain the injected rows, and folding them in again
        # would look like a wallet collision — which is exactly how this was
        # found. On a cold process this is where the first three seconds go.
        run.emit({"type": "stage", "name": "baseline", "detail": "reading the current case"})
        state = state_provider()

        typology, params = _params_for(run.request)
        # The seed decides every address the injection mints. A clock-derived
        # one wraps and re-mints addresses that already exist, which the
        # incremental path then refuses; a wide random one does not.
        seed = run.request.seed if run.request.seed is not None else random.randrange(2**31)
        inject_cfg = _broadcast_overrides(cfg, run.request.broadcast)

        detail = (f"{run.request.typology}, seed {seed}" if typology == run.request.typology
                  else f"{run.request.typology} (generator: {typology}), seed {seed}")
        run.emit({"type": "stage", "name": "inject", "detail": detail})
        injection = inject_pattern(directory, typology, params, seed=seed, cfg=inject_cfg)

        run.emit({"type": "stage", "name": "ingest", "detail": f"{injection['rows']} new rows"})
        parsed = ingest_run(directory, fmt=cfg["ingest"]["format"], cfg=cfg)
        full = pd.read_parquet(cfg["ingest"]["output_path"])
        injected_txids = set(injection["txids"])
        new_rows = full[full["txid"].isin(injected_txids)].reset_index(drop=True)
        if new_rows.empty:
            raise RuntimeError("the injected transactions did not survive ingest")

        timing = incremental.Timing(
            on_stage=lambda name, seconds: run.emit(
                {"type": "stage", "name": name, "seconds": round(seconds, 3)}))
        with incremental.LOCK:      # the live monitor folds into the same graph
            bundle = incremental.update(state, new_rows, cfg, directory, timing)

        run.emit({"type": "stage", "name": "assess", "detail": "comparing against the threshold"})
        gt = json.loads((directory / GROUND_TRUTH).read_text())
        injected_clusters = set(injection["clusters"])
        injected_wallets = sorted(
            {w for c in injected_clusters for w in gt["clusters"].get(c, {}).get("wallets", [])})

        # The generator names an actor C000123; our clustering names an entity
        # after one of its wallets. The detector never sees the former, so the
        # question "did we catch it" has to be asked in the latter.
        #
        # Only wallets that actually transacted have an entity: an injection
        # also mints counterparties it never ends up paying, and counting those
        # as undetected entities would understate the detector for no reason.
        cluster_of = bundle["features"].clustering.cluster_of
        injected_entities = {cluster_of(w) for w in injected_wallets} - {None}
        active_wallets = [w for w in injected_wallets if cluster_of(w)]

        alerts = bundle["alerts_frame"]
        hit = alerts[alerts["entity_id"].isin(injected_entities)]
        scores = incremental.entity_scores(bundle, injected_entities)
        threshold = cfg["fusion"]["alert_threshold"]

        result = {
            "typology": typology,
            "requested_typology": run.request.typology,
            "requested": run.request.model_dump(),
            "seed": seed,
            "transactions": injection["transactions"],
            "rows": injection["rows"],
            "ground_truth_clusters": sorted(injected_clusters),
            "entities": sorted(injected_entities),
            "wallets": active_wallets[:200],
            "wallet_count": len(active_wallets),
            "minted_wallets": len(injected_wallets),
            "txids": injection["txids"][:50],
            "threshold": threshold,
            "detected": bool(len(hit)),
            "alerts": json.loads(hit.to_json(orient="records")) if len(hit) else [],
            "entity_scores": json.loads(scores.to_json(orient="records")) if len(scores) else [],
            "origin": _origin_report(new_rows, injection["txids"], gt["transactions"],
                                     bundle["intel"], cfg),
            "timing": timing.as_dict(),
            "ingested": parsed,
            "graph": {"nodes": bundle["graph"].number_of_nodes(),
                      "entities": len(bundle["signals"])},
            "entity_count": len(injected_entities),
        }
        # An injection is a deliberate modification of the dataset. It goes in
        # the ledger so the file hash that no longer matches has an explanation
        # sitting next to it, signed into the same chain.
        custody.record("redteam.inject", {
            "files": [custody.seal(directory / "transactions.csv")]
            if (directory / "transactions.csv").exists() else [],
            "run_id": run.id, "typology": run.request.typology, "generator": typology,
            "seed": seed, "transactions": injection["transactions"],
            "detected": result["detected"]}, cfg=cfg)

        run.emit({"type": "stage", "name": "publish", "detail": "updating the console's view"})
        router.commit(bundle)                       # type: ignore[attr-defined]

        if run.request.typology in NON_ACTOR_TYPOLOGIES:
            result["non_actor"] = non_actor_outcome(
                run.request.typology, active_wallets, cluster_of, bool(len(hit)),
                bundle["links"])

        result["time_to_detect"] = round(time.perf_counter() - run.started, 2)
        run.result = result
        run.status = "done"
        run.emit({"type": "done", "detected": result["detected"],
                  "time_to_detect": result["time_to_detect"]})
    except Exception as exc:                                   # a demo must fail visibly
        run.status = "failed"
        run.error = f"{type(exc).__name__}: {exc}"
        run.emit({"type": "failed", "error": run.error})
    finally:
        run.events.put({"type": "close"})


def non_actor_outcome(typology: str, wallets: list[str], cluster_of,
                      alerted: bool, links: pd.DataFrame) -> dict:
    """What "handled correctly" means for a pattern that is not a crime.

    Silence alone is a weak claim — a detector that ignored the injection
    entirely would also be silent. So something positive is checked as well, and
    the two patterns are testing different engines:

      * **CoinJoin** participants are unrelated people whose inputs happen to
        share one transaction. Merging them is the classic common-input-heuristic
        failure, and `graph/clustering.py` skips CoinJoin-shaped transactions
        precisely to avoid it. Staying apart is the right answer.
      * **same-actor cluster** is *not* a clustering test in the co-spend sense,
        whatever the generator's docstring suggests: it mints one
        single-input transaction per wallet, so there is no shared input and
        common-input ownership cannot link them — nor should it. The only
        evidence tying those wallets together is the IP they all broadcast
        from, which is the correlation engine's job. So that is what is
        checked: did correlation put these entities behind one address.
    """
    entities = [cluster_of(w) for w in wallets]
    distinct = {e for e in entities if e}
    if typology == "coinjoin":
        correct = len(distinct) == len(wallets) and not alerted
        did = (f"{len(wallets)} participant wallets stayed in {len(distinct)} separate "
               "entities — the common-input heuristic was not fooled into merging "
               "unrelated people")
        wrong = (f"{len(wallets)} participant wallets collapsed into {len(distinct)} "
                 "entities — unrelated people were merged")
    else:
        shared, covered = _shared_ip(links, distinct)
        correct = covered >= 2 and not alerted
        did = (f"correlation tied {covered} of the {len(distinct)} entities to one "
               f"address ({shared}) — the shared broadcast IP was recovered, which is "
               "the only evidence linking these wallets")
        wrong = (f"no address links more than {max(covered, 1)} of the "
                 f"{len(distinct)} entities — the shared broadcast IP was not recovered")
    return {
        "typology": typology,
        "expected_alert": False,
        "reason": ("not an actor under docs/detection_unit_protocol.md — "
                   + ("mixing is suspicious but not by itself a crime"
                      if typology == "coinjoin"
                      else "a clustering and correlation test, not an offence")),
        "checked": ("participants were not merged" if typology == "coinjoin"
                    else "the shared broadcast IP was recovered"),
        "alerted": alerted,
        "wallets": len(wallets),
        "entities": len(distinct),
        "clustering_correct": correct,
        "clustering": did if correct else wrong,
        # An alert here is a false positive, not a catch. Said explicitly so
        # nobody reads a fired alert on a CoinJoin as a success.
        "outcome": ("handled correctly" if correct and not alerted
                    else "alerted — a false positive on a non-crime" if alerted
                    else "no alert, but the clustering was wrong"),
    }


def _shared_ip(links: pd.DataFrame, entities: set[str]) -> tuple[str | None, int]:
    """The address the most of these entities were linked to, and how many."""
    if links is None or links.empty or not entities:
        return None, 0
    ours = links[links["entity_id"].isin(entities)]
    if ours.empty:
        return None, 0
    counts = ours.groupby("ip")["entity_id"].nunique().sort_values(ascending=False)
    return str(counts.index[0]), int(counts.iloc[0])


def register(app, state_provider, commit, invalidate) -> None:
    """Mount the router.

    `state_provider()` returns the API's cached signal bundle; `commit(bundle)`
    hands the updated one back, so the alert queue, the case pages and the
    investigation graph all show the injected pattern immediately — which is
    the whole point of injecting it during a demo.

    `invalidate()` throws that cache away. Reset needs it: putting the files
    back while the server still holds a graph containing the injected
    transactions would leave the console showing an attack that is no longer
    in the dataset, and the next injection folding those rows in twice.
    """
    router.state_provider = state_provider          # type: ignore[attr-defined]
    router.commit = commit                          # type: ignore[attr-defined]
    router.invalidate = invalidate                  # type: ignore[attr-defined]
    app.include_router(router)


# --- endpoints -------------------------------------------------------------
@router.get("/typologies")
def typologies() -> dict:
    """What can be injected, and what each control means for it."""
    return {
        "typologies": [
            {"id": "ransomware_collector", "is_actor": True,
             "label": "ransomware collector",
             "about": "many victims pay one address, which peels off small cash-outs",
             "uses": ["hops", "total_btc", "wallets"]},
            {"id": "peel_chain", "is_actor": True, "label": "peel chain",
             "about": "a long chain that keeps most of the value and peels a little at each hop",
             "uses": ["hops", "total_btc"]},
            {"id": "layering", "is_actor": True, "label": "layering",
             "about": "fan out into intermediates, several hops, then fan back in",
             "uses": ["hops", "total_btc", "wallets"]},
            {"id": "coinjoin", "label": "coinjoin",
             "about": "equal-value inputs and outputs from unrelated wallets — mixing, "
                      "which is suspicious but not by itself a crime",
             "is_actor": False,
             "expectation": "no alert expected; the test is that the participants are "
                            "not merged into one entity",
             "uses": ["total_btc", "wallets"]},
            {"id": "same_actor_cluster", "label": "same-actor cluster",
             "about": "one actor, several wallets, one IP, one short window",
             "is_actor": False,
             "expectation": "no alert expected; the test is that correlation recovers "
                            "the shared broadcast IP behind the wallets",
             "uses": ["wallets", "window_hours", "total_btc"]},
        ],
        "broadcast": [
            {"id": "residential", "label": "residential IP",
             "about": "straight from a home connection — the easiest to attribute"},
            {"id": "tor_exit", "label": "Tor exit",
             "about": "the exit node is where it entered the network, not who sent it"},
            {"id": "hosting", "label": "hosting / VPN ASN", "about": "shared infrastructure"},
            {"id": "relay_heavy", "label": "relay-heavy path",
             "about": "almost every hop observed, so the tree is full of public relays"},
        ],
    }


@router.post("/runs", status_code=202)
def start_run(body: Injection) -> dict:
    """Start a run and return immediately; watch it on the events stream."""
    cfg = config.load()
    _require_dataset(cfg)
    run = Run(id=uuid.uuid4().hex[:12], request=body,
              started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
              started=time.perf_counter())
    with LOCK:
        RUNS[run.id] = run
        ORDER.append(run.id)
    thread = threading.Thread(
        target=execute, args=(run, router.state_provider, cfg),  # type: ignore[attr-defined]
        daemon=True, name=f"redteam-{run.id}")
    thread.start()
    return {"run_id": run.id, "status": run.status, "events": f"/redteam/runs/{run.id}/events"}


@router.get("/runs/{run_id}/events")
def run_events(run_id: str) -> StreamingResponse:
    """Server-sent events: one per stage, then `done` or `failed`.

    A red-team run is the one moment in the demo where somebody is waiting, so
    it says what it is doing while it does it.
    """
    run = RUNS.get(run_id)
    if run is None:
        raise HTTPException(404, f"unknown run {run_id}")

    def stream():
        # Anything that already happened before the browser connected.
        replayed = 0
        for stage in list(run.stages):
            replayed = max(replayed, stage.get("seq", 0))
            yield f"data: {json.dumps(stage)}\n\n"
        if run.status != "running":
            yield f"data: {json.dumps({'type': run.status, 'error': run.error})}\n\n"
            return
        while True:
            try:
                event = run.events.get(timeout=30)
            except queue.Empty:
                yield ": keep-alive\n\n"
                continue
            if event.get("type") == "close":
                break
            if event.get("seq", 0) <= replayed:
                continue                      # already replayed above
            yield f"data: {json.dumps(event)}\n\n"

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"cache-control": "no-cache",
                                      "x-accel-buffering": "no"})


@router.get("/runs")
def list_runs() -> dict:
    """The scoreboard: every run this session, and the rate per typology."""
    with LOCK:
        runs = [RUNS[i].summary() for i in ORDER]
    by_typology: dict[str, dict[str, Any]] = {}
    for run in runs:
        if run["status"] != "done":
            continue
        row = by_typology.setdefault(run["typology"], {"runs": 0, "detected": 0})
        row["runs"] += 1
        row["detected"] += 1 if run["detected"] else 0
    for row in by_typology.values():
        row["detection_rate"] = round(row["detected"] / row["runs"], 3) if row["runs"] else None
    finished = [r for r in runs if r["status"] == "done"]
    return {
        "runs": list(reversed(runs)),
        "by_typology": by_typology,
        "total": len(runs),
        "detected": sum(1 for r in finished if r["detected"]),
        "detection_rate": round(sum(1 for r in finished if r["detected"]) / len(finished), 3)
        if finished else None,
    }


@router.get("/runs/{run_id}")
def get_run(run_id: str) -> dict:
    run = RUNS.get(run_id)
    if run is None:
        raise HTTPException(404, f"unknown run {run_id}")
    return {**run.summary(), "stages": run.stages, "result": run.result}


@router.post("/snapshot")
def snapshot() -> dict:
    """Take the reset point explicitly, before anyone starts injecting."""
    return take_snapshot(config.load(), force=True)


@router.post("/reset")
def reset() -> dict:
    """Put the dataset back to the snapshot and forget the runs.

    Restores file for file, then re-ingests, so the parquet the console reads
    matches the raw data again. The caller is expected to reload the page: the
    API's cached graph is rebuilt on the next request.
    """
    cfg = config.load()
    source = snapshot_dir(cfg)
    if not source.exists():
        raise HTTPException(409, "no snapshot to reset to — nothing has been injected yet")
    target = dataset_dir(cfg)
    restored, written = [], []
    for name in SNAPSHOT_GLOBS:
        path = source / name
        if path.exists():
            shutil.copy2(path, target / name)
            restored.append(name)
            written.append(target / name)
    for path in artefacts(cfg):
        kept = source / path.name
        if kept.exists():
            shutil.copy2(kept, path)
            restored.append(path.name)
            written.append(path)
        elif path == Path(cfg["ingest"]["output_path"]):
            ingest_run(target, fmt=cfg["ingest"]["format"], cfg=cfg)

    # Restoring is a modification too. Recording it is what lets the next
    # verification say "these files are back to their acquisition hashes"
    # rather than "these files changed twice and nobody wrote down why".
    custody.record("redteam.reset", {
        "files": [custody.seal(p) for p in written if p.exists()],
        "restored": restored}, cfg=cfg)

    # The files are back; the state built from the injected ones must go too.
    router.invalidate()                             # type: ignore[attr-defined]
    with LOCK:
        RUNS.clear()
        ORDER.clear()
    return {"restored": restored, "dataset": str(target),
            "hashes_match": file_hashes(target) == file_hashes(source)}
