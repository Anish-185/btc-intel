"""Fifty injections, through the code path the endpoint uses.

`POST /redteam/runs` lets a judge plant one laundering pattern and watch the
stack try to catch it. That is a demonstration; this is the measurement. The
same function — `api.redteam.execute` — is driven `eval.redteam_runs` times
across the typologies, broadcast modes and parameter ranges the form exposes,
and the detection rate falls out of it.

Driving `execute` rather than re-implementing it is the point: an evaluation
that measured its own private copy of the injection path would be measuring
something nobody demonstrates and nobody ships.

**Every miss is reported with its numbers.** For an injection that raised no
alert, the report shows each engine's score for the injected entities against
the threshold they failed to clear. A detection rate on its own says how often
the system won; the misses say how close it came and which signal was silent.
"""

from __future__ import annotations

import json
import random
import statistics
import time
from pathlib import Path

import pandas as pd

from api import redteam
from api.redteam import Injection, Run, execute
from fusion import incremental
from fusion.pipeline import collect_signals

from .datasets import Dataset

TYPOLOGIES = ("ransomware_collector", "peel_chain", "layering", "coinjoin",
              "same_actor_cluster")
BROADCASTS = ("residential", "tor_exit", "hosting", "relay_heavy")


def plan(n: int, seed: int) -> list[Injection]:
    """The batch: every typology equally often, parameters spread across the
    ranges the form allows, so the rate is not an average over one corner."""
    rng = random.Random(seed)
    out = []
    for i in range(n):
        typology = TYPOLOGIES[i % len(TYPOLOGIES)]
        out.append(Injection(
            typology=typology,
            hops=rng.randint(2, 8),
            total_btc=round(rng.uniform(0.5, 20.0), 3),
            window_hours=round(rng.uniform(1, 72), 1),
            wallets=rng.randint(4, 30),
            broadcast=BROADCASTS[(i // len(TYPOLOGIES)) % len(BROADCASTS)],
            # Fixed per run, so the whole batch is reproducible from `seed`.
            seed=rng.randrange(2**31),
        ))
    return out


def run_batch(dataset: Dataset, cfg: dict, n: int | None = None) -> dict:
    """Inject `n` patterns into a scratch copy of the dataset, one after another.

    The dataset is copied first: injection appends to `transactions.csv` and
    `ground_truth.json`, and an evaluation that ate the canonical dataset would
    make every other number in the report irreproducible.
    """
    e = cfg["eval"]
    n = n or e["redteam_runs"]
    work = Path(e["work_dir"]) / f"redteam-batch-{dataset.name}"
    scratch = _fresh_copy(dataset, work)

    cfg = json.loads(json.dumps(cfg))
    cfg["ingest"]["input_dir"] = str(scratch)
    cfg["ingest"]["output_path"] = str(work / "transactions.parquet")
    cfg["ingest"]["quarantine_path"] = str(work / "quarantine.parquet")
    cfg["redteam"]["snapshot_dir"] = str(work / "snapshot")
    cfg["fusion"]["alerts_parquet"] = str(work / "final_alerts.parquet")
    cfg["fusion"]["alerts_json"] = str(work / "final_alerts.json")
    cfg["custody"]["ledger_path"] = str(work / "custody.jsonl")

    from ingest.pipeline import run as ingest_run
    ingest_run(scratch, cfg["ingest"]["output_path"], cfg["ingest"]["quarantine_path"],
               "csv", cfg=cfg)
    frame = pd.read_parquet(cfg["ingest"]["output_path"])
    state = collect_signals(frame, cfg, scratch)
    state["df"] = frame
    state["stacker"] = incremental.load_stacker(cfg)

    # The endpoint hands `execute` a provider for the current state and a sink
    # for the updated one; in the server those are the API's cache. Here the
    # state is threaded from one injection to the next, which is what makes
    # this a batch rather than fifty independent first-runs.
    committed: dict = {}
    redteam.router.state_provider = lambda: state            # type: ignore[attr-defined]
    redteam.router.commit = committed.update                 # type: ignore[attr-defined]
    redteam.router.invalidate = lambda: None                 # type: ignore[attr-defined]

    rows, misses = [], []
    for i, request in enumerate(plan(n, cfg["eval"]["seed"]), 1):
        run = Run(id=f"batch{i:03d}", request=request, started_at="eval",
                  started=time.perf_counter())
        execute(run, lambda: state, cfg)
        rows.append(_row(run))
        if run.status == "done" and not run.result["detected"]:
            misses.extend(_miss_rows(run))
        if committed:
            state.update(committed)      # the next injection sees this one
            committed.clear()

    return summarise(pd.DataFrame(rows), pd.DataFrame(misses), cfg)


def _fresh_copy(dataset: Dataset, work: Path) -> Path:
    import shutil
    scratch = work / "raw"
    if scratch.exists():
        shutil.rmtree(scratch)
    scratch.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(dataset.raw, scratch)
    return scratch


def _row(run: Run) -> dict:
    result = run.result or {}
    origin = result.get("origin", {})
    return {
        "run": run.id,
        "typology": run.request.typology,
        "broadcast": run.request.broadcast,
        "hops": run.request.hops,
        "wallets": run.request.wallets,
        "total_btc": run.request.total_btc,
        "status": run.status,
        "detected": result.get("detected"),
        "time_to_detect": result.get("time_to_detect"),
        "entities": result.get("entity_count"),
        "origin_rank": origin.get("best_rank"),
        "error": run.error,
    }


def _miss_rows(run: Run) -> list[dict]:
    """Every engine's score for an injection nothing fired on."""
    result = run.result
    threshold = result["threshold"]
    out = []
    for score in result["entity_scores"][:3]:        # the closest few, not all
        out.append({
            "run": run.id, "typology": run.request.typology,
            "broadcast": run.request.broadcast,
            "rule": round(score["rule_score"], 3),
            "anomaly": round(score["anomaly_score"], 3),
            "gnn": round(score["gnn_score"], 3),
            "taint": round(score["taint_score"], 3),
            "fused": round(score["risk_score"], 3),
            "threshold": threshold,
            "short by": round(threshold - score["risk_score"], 3),
        })
    return out


def summarise(runs: pd.DataFrame, misses: pd.DataFrame, cfg: dict) -> dict:
    done = runs[runs["status"] == "done"]
    per_typology = []
    for typology, group in done.groupby("typology"):
        detected = group[group["detected"]]
        times = [t for t in detected["time_to_detect"] if t is not None]
        ranks = [r for r in group["origin_rank"] if r is not None and not pd.isna(r)]
        per_typology.append({
            "typology": typology,
            "runs": len(group),
            "detected": int(group["detected"].sum()),
            "detection rate": round(float(group["detected"].mean()), 3),
            "median time-to-detect (s)": round(statistics.median(times), 2) if times else None,
            "origin named (rank 1)": int(sum(1 for r in ranks if r == 1)),
            "true origin in candidates": len(ranks),
        })

    by_broadcast = []
    for broadcast, group in done.groupby("broadcast"):
        ranks = [r for r in group["origin_rank"] if r is not None and not pd.isna(r)]
        by_broadcast.append({
            "broadcast": broadcast, "runs": len(group),
            "detection rate": round(float(group["detected"].mean()), 3),
            "true origin in candidates": round(len(ranks) / len(group), 3) if len(group) else 0.0,
            "named outright": round(sum(1 for r in ranks if r == 1) / len(group), 3)
            if len(group) else 0.0,
        })

    times = [t for t in done[done["detected"]]["time_to_detect"] if t is not None]
    return {
        "runs": len(runs),
        "completed": len(done),
        "failed": int((runs["status"] != "done").sum()),
        "detected": int(done["detected"].sum()) if len(done) else 0,
        "detection_rate": round(float(done["detected"].mean()), 3) if len(done) else None,
        "median_time_to_detect": round(statistics.median(times), 2) if times else None,
        "threshold": cfg["fusion"]["alert_threshold"],
        "per_typology": pd.DataFrame(per_typology),
        "by_broadcast": pd.DataFrame(by_broadcast),
        "misses": misses,
        "errors": runs[runs["status"] != "done"][["run", "typology", "error"]],
    }
