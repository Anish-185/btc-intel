"""The actor queue against the entity queue, on generator ground truth: triage.

Both queues come from one dataset, one fusion bundle and one fitted stacker, so
the only difference is the unit: an entity (address cluster) or an actor
(clusters joined through peer identities, fusion/actors.py). Ground truth is
`eval.actors.actors_of`: the illicit operations pre-registered in
docs/detection_unit_protocol.md.

A queue item *finds* an operation when it holds any of the operation's
wallets. A wallet's true controller, for purity, is its operation if it has
one, else its generator actor.
"""

from __future__ import annotations

import json
import tempfile
from collections import Counter
from pathlib import Path

import pandas as pd

from engines.correlation.profile import build_sources
from features import relay
from fusion import actors as A
from fusion.pipeline import build_alerts, collect_signals
from ingest.ip_intel import load_intel
from p2p import demo_capture

from .actors import actors_of
from .datasets import Dataset

KS = (10, 25, 50)


def dataset_actors(dataset: Dataset, stacker, cfg: dict) -> dict:
    """The fusion bundle, the entity alerts and the actors of one dataset.
    Its relay matrix is built the way the served one is (p2p.demo_capture,
    then features.relay), in a scratch directory. `stacker=None` fits one on
    this dataset's own labels, as eval.fusion_eval does: entities holding an
    illicit operation's wallet."""
    cfg = json.loads(json.dumps(cfg))
    cfg["ingest"]["input_dir"] = str(dataset.raw)       # this dataset's node intel
    df = dataset.frame()
    bundle = collect_signals(df, cfg, dataset.raw)
    if stacker is None:
        from fusion.stacker import train

        from .actors import illicit_entities
        bad = illicit_entities(actors_of(dataset), bundle["features"].entity_of)
        stacker = train(bundle["signals"], bundle["signals"]["entity_id"].isin(bad).astype(int), cfg)
    alerts = build_alerts(bundle, stacker, cfg)
    with tempfile.TemporaryDirectory() as tmp:
        capture = Path(tmp) / "demo_capture"
        demo_capture.write(df, capture)
        matrix, _, _ = relay.build(capture, [demo_capture.COLLECTOR], cfg)
    src = build_sources(cfg, transactions=df, matrix=matrix, features=bundle["features"],
                        intel=load_intel(None, dataset.raw, cfg))
    links = A.peer_links(src, cfg)
    actors = A.build(bundle["signals"], stacker, links, cfg, set(alerts["entity_id"]))
    return {"bundle": bundle, "alerts": alerts, "actors": actors, "links": links}


def _wallets(entity: str, clusters: dict) -> set[str]:
    return set(clusters.get(entity, {entity}))


def triage(dataset: Dataset, built: dict) -> dict:
    gt = dataset.ground_truth()
    operations = actors_of(dataset)
    clusters = built["bundle"]["features"].clustering.clusters
    op_of = {w: op.actor_id for op in operations for w in op.wallets}
    controller = lambda w: op_of.get(w) or gt["wallets"].get(w, w)
    present = {op.actor_id for op in operations
               if any(built["bundle"]["features"].entity_of(w) for w in op.wallets)}

    entity_items = [_wallets(e, clusters) for e in built["alerts"]["entity_id"]]
    queue = A.queue(built["actors"])
    actor_items = [set().union(*(_wallets(m, clusters) for m in members))
                   for members in queue["members"]]

    def found(items):
        return [{op_of[w] for w in wallets if w in op_of} for wallets in items]

    def rows(name, items):
        hits = found(items)
        out = {"queue": name, "items": len(items)}
        for k in KS:
            top = hits[:k]
            seen = set().union(*top) if top else set()
            out[f"precision@{k}"] = round(sum(bool(h) for h in top) / len(top), 3) if top else None
            out[f"recall@{k}"] = round(len(seen) / len(present), 3) if present else None
        # "Items reviewed before finding N", for N = 1, 3, 10, 20 and all of the
        # operations present, whichever of those the dataset holds.
        for n in sorted({k for k in (1, 3, 10, 20) if k <= len(present)} | {len(present)} - {0}):
            reviewed = None
            seen = set()
            for i, h in enumerate(hits, 1):
                seen |= h
                if len(seen) >= n:
                    reviewed = i
                    break
            label = "all" if n == len(present) else str(n)
            out[f"reviewed to find {label}"] = reviewed if reviewed is not None else "not reached"
        return out

    table = [rows("entity queue (before)", entity_items), rows("actor queue", actor_items)]

    def purity(wallets):
        c = Counter(controller(w) for w in wallets)
        return c.most_common(1)[0][1] / sum(c.values())

    multi = queue[queue["members"].map(len) > 1]
    majority = lambda m: Counter(controller(w) for w in _wallets(m, clusters)).most_common(1)[0][0]
    wrong = [len({majority(m) for m in members}) > 1 for members in multi["members"]]
    all_multi = built["actors"][built["actors"]["members"].map(len) > 1]
    wrong_all = [len({majority(m) for m in members}) > 1 for members in all_multi["members"]]
    quality = {
        "entity alerts": len(entity_items), "actor alerts": len(actor_items),
        "alert count reduction": round(1 - len(actor_items) / len(entity_items), 3)
        if entity_items else None,
        "illicit operations present": len(present),
        "actor purity (alerted, mean)": round(sum(map(purity, actor_items)) / len(actor_items), 3)
        if actor_items else None,
        "entity purity (alerted, mean)": round(sum(map(purity, entity_items)) / len(entity_items), 3)
        if entity_items else None,
        "alerted actors joining 2+ clusters": len(multi),
        "wrong-merge rate (alerted multi-cluster actors)": round(sum(wrong) / len(wrong), 3)
        if wrong else None,
        "actors joining 2+ clusters (all)": len(all_multi),
        "wrong-merge rate (all multi-cluster actors)": round(sum(wrong_all) / len(wrong_all), 3)
        if wrong_all else None,
        "links": len(built["links"]),
        "joining links": sum(A.may_join(lk) for lk in built["links"]),
    }
    return {"table": pd.DataFrame(table), "quality": quality}


def evaluate(datasets: dict[str, Dataset], stackers: dict, cfg: dict) -> dict:
    out = {}
    for name, dataset in datasets.items():
        built = dataset_actors(dataset, stackers[name], cfg)
        out[name] = triage(dataset, built)
    return out


# --- power: many seeds, larger datasets ----------------------------------------------
#: Sizes chosen so each dataset holds about thirty illicit operations (shifted
#: instances are larger, so it needs more transactions). Actors scale with size.
POWER_SIZES = {"standard": 9600, "shifted": 18000}
POWER_SEEDS = (101, 102, 103, 104, 105)
T_975 = {2: 12.706, 3: 4.303, 4: 3.182, 5: 2.776, 6: 2.571, 7: 2.447, 8: 2.365, 9: 2.306}


def power_datasets(cfg: dict, seeds=POWER_SEEDS, sizes=None) -> dict[tuple[str, int], Dataset]:
    from .datasets import build
    out = {}
    for condition, n in (sizes or POWER_SIZES).items():
        c = json.loads(json.dumps(cfg))
        c["eval"]["n_actors"], c["eval"]["n_transactions"] = n // 6, n
        for seed in seeds:
            out[(condition, seed)] = build(cfg["eval"]["default_rate"], condition == "shifted",
                                           seed, c, name_prefix=f"power-{condition}-n{n}")
    return out


def _interval(values: list[float]) -> str:
    """Mean and a 95% t-interval across seeds."""
    import statistics
    v = [float(x) for x in values if x is not None and not isinstance(x, str)]
    if not v:
        return "—"
    if len(v) == 1:
        return f"{v[0]:.3f} (one seed)"
    half = T_975.get(len(v), 2.0) * statistics.stdev(v) / len(v) ** 0.5
    return f"{statistics.mean(v):.3f} [{statistics.mean(v) - half:.3f}, {statistics.mean(v) + half:.3f}]"


def power(cfg: dict, seeds=POWER_SEEDS, sizes=None) -> dict:
    """The P9 comparison on every (condition, seed) dataset, each with its own
    fitted stacker, and the spread across seeds. The join rule is fusion/actors.py's,
    unchanged."""
    per = []
    for (condition, seed), dataset in power_datasets(cfg, seeds, sizes).items():
        result = triage(dataset, dataset_actors(dataset, None, cfg))
        table = result["table"].set_index("queue")
        per.append({"condition": condition, "seed": seed, "table": table,
                    "quality": result["quality"]})
    return {"per_seed": per, "summary": summarise_power(per)}


def summarise_power(per: list[dict]) -> dict:
    rows, diffs, merges, sizes = [], [], [], []
    for condition in sorted({p["condition"] for p in per}):
        runs = [p for p in per if p["condition"] == condition]
        metrics = [c for c in runs[0]["table"].columns if c != "items"]
        common = [m for m in metrics if all(m in r["table"].columns for r in runs)]
        for queue in runs[0]["table"].index:
            rows.append({"condition": condition, "queue": queue, "seeds": len(runs),
                         "items": _interval([r["table"].loc[queue, "items"] for r in runs]),
                         **{m: _interval([r["table"].loc[queue, m] for r in runs]) for m in common}})
        before, after = runs[0]["table"].index
        for m in ["items", *common]:
            pairs = [(r["table"].loc[before, m], r["table"].loc[after, m]) for r in runs]
            pairs = [(a, b) for a, b in pairs if not isinstance(a, str) and not isinstance(b, str)]
            diffs.append({"condition": condition, "measure": m,
                          "seeds with both": len(pairs),
                          "actor − entity": _interval([b - a for a, b in pairs])})
        q = [r["quality"] for r in runs]
        merges.append({"condition": condition,
                       **{k: _interval([x[k] for x in q]) for k in (
                           "illicit operations present", "alert count reduction",
                           "actor purity (alerted, mean)",
                           "wrong-merge rate (alerted multi-cluster actors)",
                           "wrong-merge rate (all multi-cluster actors)")},
                       "alerted multi-cluster actors (total)":
                           sum(x["alerted actors joining 2+ clusters"] for x in q)})
        sizes += [{"condition": condition, "seed": r["seed"],
                   "operations": r["quality"]["illicit operations present"],
                   "entity alerts": r["quality"]["entity alerts"],
                   "actor alerts": r["quality"]["actor alerts"],
                   **{f"reviewed to find all ({q.split()[0]})": r["table"].loc[q].get(
                       "reviewed to find all", "—") for q in r["table"].index}}
                  for r in runs]
    return {"queues": pd.DataFrame(rows), "paired": pd.DataFrame(diffs),
            "quality": pd.DataFrame(merges), "datasets": pd.DataFrame(sizes)}

