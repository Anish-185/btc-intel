"""Exit points against generator ground truth: an upper bound, simulated.

For every illicit operation, trace from its origin cluster (the collector, or
the layering source) and ask whether a true cash-out cluster is ranked first,
or in the top three, under each taint model:

* ransomware: every peel's `cashout` recipient;
* layering: the merge's sink.

**The tags come from ground truth.** The generator never pays an exchange with
illicit money: its cash-outs are fresh wallets. So the store used here is
built in memory from ground truth. Every true cash-out cluster is tagged
exchange/VASP, beside the generator's real exchanges as decoys. Nothing is
read from data/tags. The ranking is told which clusters are services, so this
measures tracing reach and ranking among the tagged, an upper bound on what
tags from real lists could support.

CoinJoins: for every generator CoinJoin, trace from each participant's input
cluster and ask whether tracing stopped at the mix (it is recorded in `mixes`)
rather than producing a candidate through it (a candidate path using the
CoinJoin's txid). Split by whether clustering detected the CoinJoin.
"""

from __future__ import annotations

import json

import pandas as pd

from analysis.exit_point import VASP, trace_entity
from engines.rules.detectors import FeatureSet
from fusion.taint import TRACE_MODELS
from graph.builder import build_graph, graph_transactions
from graph.entity_graph import build_entity_graph
from intel.importers import cashouts
from intel.importers import demo as demo_tags
from intel.store import TagStore
from intel.tags import SIMULATED, Tag

from .actors import OPERATION_TX_PATTERNS
from .datasets import Dataset


def operations(gt: dict, txs: dict) -> dict[str, dict]:
    """Operation -> typology, origin wallet and true cash-out wallets."""
    ops: dict[str, dict] = {}
    ordered = sorted(gt["transactions"].items(), key=lambda kv: kv[1].get("timestamp") or "")
    for txid, meta in ordered:
        if meta["pattern"] not in OPERATION_TX_PATTERNS or txid not in txs:
            continue
        tx = txs[txid]
        op = ops.setdefault(meta["cluster_id"], {"typology": meta["typology"], "origin": None,
                                                 "cashouts": set()})
        if op["origin"] is None:
            op["origin"] = tx.inputs[0][0]
        op["cashouts"] |= cashouts(meta, [a for a, _ in tx.outputs], gt)
    return {cid: op for cid, op in ops.items() if op["cashouts"]}


def tag_store(gt: dict, ops: dict, raw, cfg: dict) -> TagStore:
    """Ground truth, as tags: true cash-outs and the generator's exchanges."""
    store = TagStore(risk=dict(cfg["tags"]["risk"]))
    collected = gt["generated_at"][:10]
    tags = [Tag(subject=w, label=f"simulated cash-out point of operation {cid}",
                category=VASP, source=SIMULATED,
                reference=f"generator ground_truth.json, seed {gt['seed']}, operation {cid}",
                collected=collected, confidence=1.0, applies_to="cluster")
            for cid, op in ops.items() for w in sorted(op["cashouts"])]
    tags += [t for t in demo_tags(raw, with_cashouts=False) if t.category == VASP]
    store.add("ground-truth", tags)
    return store


def evaluate(dataset: Dataset, cfg: dict) -> dict:
    cfg = json.loads(json.dumps(cfg))
    cfg["tags"]["store_dir"] = None
    cfg["exit_point"]["candidates"] = 10_000        # rank everything reached
    frame = dataset.frame()
    graph = build_graph(frame, cfg)
    features = FeatureSet.from_graph(graph, cfg)
    money = build_entity_graph(graph, features.clustering, cfg)
    txs = {tx.txid: tx for tx in graph_transactions(graph)}
    gt = dataset.ground_truth()
    ops = operations(gt, txs)
    store = tag_store(gt, ops, dataset.raw, cfg)

    rows = []
    for cid, op in sorted(ops.items()):
        seed = features.entity_of(op["origin"])
        truth = {features.entity_of(w) for w in op["cashouts"]}
        result = trace_entity(seed, money, features, store, txs, cfg)
        for model in TRACE_MODELS:
            ranked = sorted(result["candidates"],
                            key=lambda c: (-c["models"][model]["score"], c["entity_id"]))
            ranked = [c for c in ranked if c["models"][model]["amount"] > 0]
            hits = [c["entity_id"] in truth for c in ranked]
            rows.append({"dataset": dataset.name, "operation": cid,
                         "typology": op["typology"], "model": model,
                         "top1": any(hits[:1]), "top3": any(hits[:3]),
                         "reached": any(hits), "candidates": len(ranked),
                         "seed_is_cashout": seed in truth})

    mixes = []
    for txid, meta in gt["transactions"].items():
        if meta["pattern"] != "coinjoin" or txid not in txs:
            continue
        detected = txid in features.clustering.coinjoins
        for seed in sorted({features.entity_of(a) for a, _ in txs[txid].inputs}):
            result = trace_entity(seed, money, features, store, txs, cfg)
            stopped = any(txid in m["txids"] for ms in result["mixes"].values() for m in ms)
            through = any(txid in h["txids"] for c in result["candidates"]
                          for m in c["models"].values() for p in m["paths"] for h in p["hops"])
            mixes.append({"dataset": dataset.name, "coinjoin": txid, "detected": detected,
                          "stopped": stopped, "candidate_through_mix": through})
    return {"operations": pd.DataFrame(rows), "coinjoins": pd.DataFrame(mixes)}


def summarise(results: list[dict]) -> dict:
    ops = pd.concat([r["operations"] for r in results], ignore_index=True)
    mix = pd.concat([r["coinjoins"] for r in results], ignore_index=True)
    ops["condition"] = ops["dataset"].str.split("-").str[1]
    ranking = (ops.groupby(["condition", "typology", "model"])
               .agg(operations=("operation", "size"), top1=("top1", "mean"),
                    top3=("top3", "mean"), reached=("reached", "mean"),
                    median_candidates=("candidates", "median"))
               .round(3).reset_index())
    if len(mix):
        coinjoins = (mix.groupby("detected")
                     .agg(seeds=("coinjoin", "size"), coinjoins=("coinjoin", "nunique"),
                          stopped_at_mix=("stopped", "mean"),
                          candidate_through_mix=("candidate_through_mix", "mean"))
                     .round(3).reset_index())
        coinjoins["detected"] = coinjoins["detected"].map(
            {True: "detected by clustering", False: "not detected"})
    else:
        coinjoins = pd.DataFrame()
    return {"ranking": ranking, "coinjoins": coinjoins, "operations": len(ops) // 2,
            "degenerate": int(ops[ops["model"] == "haircut"]["seed_is_cashout"].sum())}
