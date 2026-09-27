"""Red-team detection with and without the attribution store: an upper bound.

The red-team batch (eval.redteam_batch) is run twice on the same dataset with
the same seeded injections:

1. **without tags**: a stacker fitted on the dataset with the tag signal empty;
2. **with tags**: the demo bundle (intel.importers.demo) built from the ground
   truth the first pass left behind, which by then includes every injection,
   sealed, imported into a scratch store, and a stacker refitted with it.

Both stackers are fitted the same way (the actor-level label, as
eval.fusion_eval does), so the only difference is the tag signal. The demo
bundle tags **every** illicit operation from ground truth, including the
injected ones. Real lists tag a fraction of real crime, late, so the second
number is an upper bound on what tags can add, not an estimate of it.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from fusion.pipeline import collect_signals
from fusion.stacker import save, train
from intel import bundle as tag_bundle
from intel import importers

from . import redteam_batch
from .actors import actors_of, illicit_entities
from .datasets import Dataset


def _fitted(dataset: Dataset, cfg: dict, path: Path) -> dict:
    """Fit on the base dataset (before any injection) and save where the
    batch's incremental path loads its model from."""
    bundle = collect_signals(dataset.frame(), cfg, dataset.raw)
    bad = illicit_entities(actors_of(dataset), bundle["features"].entity_of)
    stacker = train(bundle["signals"], bundle["signals"]["entity_id"].isin(bad).astype(int), cfg)
    save(stacker, path)
    tagged = int((bundle["signals"]["tag_score"] > 0).sum())
    return {"auc": stacker.metrics.get("auc"),
            "coefficients": stacker.metrics.get("coefficients", {}),
            "entities with a tag score": tagged}


def evaluate(dataset: Dataset, cfg: dict, n: int | None = None) -> dict:
    cfg = json.loads(json.dumps(cfg))
    work = Path(cfg["eval"]["work_dir"]) / f"tags-{dataset.name}"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    cfg["custody"]["ledger_path"] = str(work / "custody.jsonl")
    cfg["ingest"]["input_dir"] = str(dataset.raw)

    off = json.loads(json.dumps(cfg))
    off["tags"]["store_dir"] = None
    off["fusion"]["model_path"] = str(work / "stacker-without-tags.joblib")
    fit_off = _fitted(dataset, off, Path(off["fusion"]["model_path"]))
    without = redteam_batch.run_batch(dataset, off, n)
    batch_raw = Path(cfg["eval"]["work_dir"]) / f"redteam-batch-{dataset.name}" / "raw"
    truth_after = json.loads((batch_raw / "ground_truth.json").read_text())

    tags = importers.demo(batch_raw)
    tag_bundle.write_bundle(tags, work / "bundle", "demo-upper-bound",
                            "SIMULATED: every operation in ground truth, injections included")
    on = json.loads(json.dumps(cfg))
    on["tags"]["store_dir"] = str(work / "store")
    imported = tag_bundle.import_bundle(work / "bundle", on)
    on["fusion"]["model_path"] = str(work / "stacker-with-tags.joblib")
    fit_on = _fitted(dataset, on, Path(on["fusion"]["model_path"]))
    with_tags = redteam_batch.run_batch(dataset, on, n)

    # Same seeds, same injections: the second batch must have minted exactly
    # the clusters the first did, or the comparison is between two batches.
    truth_again = json.loads((batch_raw / "ground_truth.json").read_text())
    same = set(truth_after["clusters"]) == set(truth_again["clusters"])
    return {"without": without, "with": with_tags, "fit_without": fit_off,
            "fit_with": fit_on, "bundle": imported, "tags": len(tags),
            "categories": sorted({t.category for t in tags}),
            "same_injections": same}
