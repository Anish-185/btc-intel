# Red-team run performance

**Target: a full inject + incremental re-run under 30 seconds on a CPU-only
laptop.**
**Measured: 3.45 seconds median.** The interesting part of this document is not
that the target is met with an order of magnitude to spare — it is which stage
dominates, and which "obvious" optimisation made things worse.

Measured on the demo dataset (1,200 transactions, 4,382 relay rows, 1,780
entities) on a CPU-only laptop, Python 3.14, no GPU, `n_estimators: 200`. One
run per typology, each injected into the *same* clean dataset: `reset` runs
between them, so a later typology is not paying for the transactions an earlier
one added.

## End to end

| Typology | Run (s) | Pipeline (s) | Detected | Origin rank |
| --- | --- | --- | --- | --- |
| ransomware_collector | 3.45 | 3.07 | yes | 1 |
| peel_chain | 3.56 | 3.26 | yes | 1 |
| layering | 3.38 | 3.07 | no | 1 |
| coinjoin | 3.33 | 3.05 | no | 1 |
| same_actor_cluster | 3.58 | 3.08 | no | 1 |
| **median** | **3.45** | **3.07** | | |

"Run" is what the judge waits for: snapshot, inject, ingest, re-run, assess,
publish. "Pipeline" is the re-run alone.

**A full rebuild from the parquet takes 5.31 s** (median of three) — the same
work the incremental path replaces, so **it saves about 42%** today. The gap
widens with the dataset: the two stages it skips are the ones that scale with
the number of transactions already stored, and they are flat here.

One cost is not in the table: **the first run of a process pays about 5.4 s** to
build the baseline state — every engine over the whole dataset, once. It happens
once per server, before the first injection, and the UI shows it as the
`baseline` stage. Injecting once before the demo starts hides it entirely.

## Stage by stage

Medians across the five runs:

| Stage | Seconds | Share | Incremental? |
| --- | --- | --- | --- |
| anomaly: refit over the population | 2.178 | 71% | no — global by necessity |
| correlation: recomputed globally | 0.568 | 18% | no — global by necessity |
| rules: whole graph | 0.098 | 3% | no — cheap, and skipping it would miss patterns that span old and new |
| cluster + features: whole dataset | 0.096 | 3% | no — see below |
| fuse: score with the saved model | 0.056 | 2% | — |
| taint: from the watchlist | 0.048 | 2% | — |
| origins: new transactions only | 0.013 | <1% | **yes** |
| graph: add new transactions | 0.007 | <1% | **yes** |
| gnn: inference, never training | 0.001 | <1% | inference over the new rows |

### Why clustering is not incremental, although it looks like it should be

The first version clustered the injected transactions on their own and merged
the result, on the reasoning that injected wallets are fresh and therefore
disjoint. `test_incremental_matches_a_full_rerun` failed: the change-address
heuristics read the surrounding transaction history, so the same transactions
clustered in isolation can land in different entities from the same
transactions clustered in context. Being wrong in 4 ms instead of right in
96 ms is not a trade worth making, so both stages now run over the whole
dataset and the test passes.

### Why the GNN and the stacker are never trained here

A detector refitted around the attack it is being asked to find has not been
tested. Both are loaded and used for inference; the stacker comes from the last
full pipeline run (`models/stacker.joblib`). If the file is missing, the run
falls back to the configured risk weights and says so in its metrics rather
than training something on the spot.

## What was optimised

### 1. Correlation was quadratic

`engines/correlation/scorer.py` looked up each observation's ASN with
`df.loc[df["src_ip"] == ip]` — a full scan of every relay row, inside the loop
over observations. On this dataset that is 1,200 × 4,382 ≈ 5.3 million
comparisons; on a dataset ten times the size it is a hundred times the work.
It is now one `groupby` into a dict, built once per call (`asn_index`). The
result is identical: first non-null ASN wins, exactly as before. Worth little
here (tenths of a second) and a great deal on anything real, which is the point
— the stage is now linear in transactions rather than quadratic.

### 2. The forest: the obvious optimisation was the wrong one

The slowest stage is the IsolationForest refit, so the first thing tried was
`n_jobs`. Measured on 1,780 entities, three repeats, median:

| `n_jobs` | Seconds | Score checksum |
| --- | --- | --- |
| **1** | **2.131** | 444.335212 |
| 2 | 2.733 | 444.335212 |
| 4 | 3.039 | 444.335212 |
| -1 (all cores) | 3.226 | 444.335212 |

Every setting produces **identical scores** — `random_state` is fixed — and
every parallel setting is **slower**. The work is split into a few peer groups
of a few hundred rows each, and joblib's per-group dispatch costs more than the
trees it saves.

`config.yaml` keeps the knob (`engines.anomaly.n_jobs: 1`) with the numbers in
a comment, so the next person to reach for it has the measurement rather than
the intuition.

### 3. What was deliberately not done

* **Fewer trees.** `n_estimators: 200` → 50 would cut the stage to well under a
  second and change every anomaly score in the product. Speeding up a demo by
  quietly making the detector different is not a performance improvement.
* **Refitting only the peer groups that gained members.** Exact-looking and
  actually wrong: peer groups are quantile bands over the whole population, so
  adding entities moves the boundaries and can move existing entities between
  groups. Almost every group changes, so there would be little to win even if
  it were safe.

## Reproducing

From the repository root, with the demo dataset in `data/raw` and the pipeline
already run over it:

```sh
PYTHONPATH=. python - <<'PY'
import json, statistics, time
import pandas as pd
import config, api.app as app_module
from api import redteam
from api.redteam import Injection, Run, execute, take_snapshot
from fusion.pipeline import collect_signals

cfg = config.load()
redteam.router.state_provider = app_module.bundle
redteam.router.commit = app_module.commit_bundle
redteam.router.invalidate = app_module.invalidate
take_snapshot(cfg, force=True)          # the clean dataset is the reset point

for typology in ["ransomware_collector", "peel_chain", "layering",
                 "coinjoin", "same_actor_cluster"]:
    t0 = time.perf_counter(); app_module.bundle()
    baseline = time.perf_counter() - t0
    run = Run(id=typology, started_at="x", started=time.perf_counter(),
              request=Injection(typology=typology, hops=4, total_btc=3.0, wallets=10))
    execute(run, app_module.bundle, cfg)
    assert run.status == "done", run.error
    print(typology, "baseline", round(baseline, 2),
          "run", run.result["time_to_detect"], run.result["timing"])
    redteam.reset()                     # every typology starts from the same dataset
PY
```

The dataset is left as it started: the loop resets after each run.

## When this stops being true

The numbers above are for a 1,200-transaction dataset. Two stages are linear in
the size of the *whole* dataset and will dominate first:

* **anomaly** — linear in entities. At 100× it is roughly three and a half
  minutes, which is past the target. The fix at that point is to score new
  entities against a persisted fit and accept that the scores of existing
  entities drift until the model is refitted on a schedule — a real change in
  behaviour, so it should be made deliberately rather than for a demo.
* **correlation** — linear in transactions, now that the quadratic scan is
  gone.

The two stages that are already incremental (graph, origins) stay flat no
matter how large the stored dataset becomes, which is the point of them.
