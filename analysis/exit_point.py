"""Exit points: where a seed's funds were cashed out (docs/EXIT_POINTS.md).

Given a seed (an address, an entity, or an actor), trace its outflow forward
with fusion.taint.trace under two taint models (haircut, poison), and rank the
clusters tagged exchange/VASP in the tag store (intel/) that the money reached.
Nothing here traces on its own: the walk, its CoinJoin termination and its
cycle rule are fusion/taint.py's; the clusters and merge confidences are
graph/'s; the tags are intel/'s.

* A candidate is a cluster with an exchange/VASP tag. It is ranked by traced
  flow share times path confidence (the product of merge confidences and taint
  fractions along the best path), and its k best paths are shown.
* An untagged cluster that keeps a large share of the flow is an "untagged
  sink", named by its cluster id only, never as a service.
* Where the money entered a CoinJoin the trace says so, and does not guess
  past it.
* An actor is traced from each member cluster separately. An actor join is
  evidence that two clusters share a peer, not a payment; it is never a flow.

This is an investigative lead. It says where traced value went, not who
controls the receiving cluster.
"""

from __future__ import annotations

import hashlib
import json

import config
from fusion.taint import TRACE_MODELS, trace

VASP = "exchange/VASP"
STATEMENT = ("An investigative lead, not proof of identity or ownership: it shows where "
             "traced value went under stated taint models, not who controls the receiving "
             "cluster.")


def seeds_of(kind: str, subject: str, features, actor: dict | None = None) -> list[str]:
    """The entities to trace from. An address traces from its cluster (the
    entity graph is cluster-level); an actor from each member, separately."""
    if kind == "address":
        return [features.entity_of(subject)]
    if kind == "entity":
        return [subject]
    if kind == "actor":
        if actor is None:
            raise KeyError(f"unknown actor {subject}")
        return list(actor["members"])
    raise ValueError("kind is one of address, entity, actor")


def service_entities(store, features) -> set[str]:
    """Entities an exchange/VASP tag applies to (cluster tags, or an address
    tag on a lone wallet: intel.store's propagation rules)."""
    touched = {features.entity_of(a) for a, tags in store.by_address.items()
               if any(t.category == VASP for _, t in tags)}
    return {e for e in touched
            if any(t["category"] == VASP for t in store.entity(e, features.clustering)["tags"])}


def _iso(ts) -> str | None:
    return None if ts is None else str(ts)


def _reason(hop: dict, model: str) -> str:
    text = (f"{hop['value']:.8f} BTC from {hop['from']} to {hop['to']} in "
            f"{len(hop['txids'])} transaction(s); {hop['fraction']:.1%} of the sender's "
            f"outflow" + (" (haircut share)" if model == "haircut" else
                          " (poison: all of it tainted)")
            + f"; receiving cluster merge confidence {hop['merge_confidence']:.2f}")
    if hop["mixed_txs"]:
        text += (f"; {hop['mixed_txs']} of these are CoinJoins, but the edge is not "
                 "only mixes, so it is followed")
    return text


def _receiving(candidate: str, paths: list[dict], txs: dict, features) -> list[str]:
    """Addresses of the candidate cluster paid by the last hop of its paths."""
    out = set()
    for path in paths:
        for txid in path["hops"][-1]["txids"]:
            tx = txs.get(txid)
            for address, _ in (tx.outputs if tx else []):
                if features.entity_of(address) == candidate:
                    out.add(address)
    return sorted(out)


def trace_entity(seed: str, entity_graph, features, store, txs: dict,
                 cfg: dict | None = None) -> dict:
    """Both taint models from one seed entity, candidates ranked."""
    cfg = cfg or config.load()
    x = cfg["exit_point"]
    services = service_entities(store, features)
    traced = {m: trace(entity_graph, seed, m, features.clustering.confidence,
                       stop=services, cfg=cfg) for m in TRACE_MODELS}
    seed_amount = traced["haircut"].seed_amount

    def per_model(entity: str) -> dict:
        out = {}
        for m, t in traced.items():
            paths = t.paths.get(entity, [])
            share = t.received.get(entity, 0.0) / seed_amount if seed_amount else 0.0
            best = paths[0]["confidence"] if paths else 0.0
            out[m] = {"amount": round(t.received.get(entity, 0.0), 8),
                      "share": round(share, 6), "path_confidence": best,
                      "score": round(share * best, 6),
                      "paths": [{**p, "hops": [{**h, "first_seen": _iso(h["first_seen"]),
                                                "last_seen": _iso(h["last_seen"]),
                                                "reason": _reason(h, m)}
                                               for h in p["hops"]]} for p in paths]}
        return out

    reached = set().union(*(t.received for t in traced.values()))
    candidates = []
    for entity in sorted(reached & services):
        models = per_model(entity)
        paths = [p for m in models.values() for p in m["paths"]]
        hops = [h for p in paths for h in p["hops"]]
        tags = store.entity(entity, features.clustering)
        candidates.append({
            "entity_id": entity, "tags": [t for t in tags["tags"] if t["category"] == VASP],
            "conflict": tags["conflict"], "other_tags": [t for t in tags["tags"]
                                                         if t["category"] != VASP],
            "receiving_addresses": _receiving(entity, paths, txs, features),
            "time_window": [min((h["first_seen"] for h in hops if h["first_seen"]), default=None),
                            max((h["last_seen"] for h in hops if h["last_seen"]), default=None)],
            "models": models})
    candidates.sort(key=lambda c: (-c["models"]["haircut"]["score"],
                                   -c["models"]["poison"]["score"], c["entity_id"]))
    candidates = candidates[:x["candidates"]]
    for rank, c in enumerate(candidates, 1):
        c["rank"] = rank
        c["evidence_sha256"] = hashlib.sha256(
            json.dumps(c, sort_keys=True, default=str).encode()).hexdigest()

    sinks = []
    for entity in sorted(reached - services):
        kept = {m: t.terminal.get(entity, 0.0) for m, t in traced.items()}
        if seed_amount and kept["haircut"] / seed_amount >= x["sink_min_share"]:
            tags = store.entity(entity, features.clustering)
            sinks.append({"entity_id": entity,
                          "label": "untagged sink" if not (tags["tags"] or tags["member_tags"])
                          else "sink (tagged, not a service)",
                          "tags": tags["tags"],
                          "kept": {m: round(v, 8) for m, v in kept.items()},
                          "share_kept": round(kept["haircut"] / seed_amount, 6)})
    sinks.sort(key=lambda s: -s["share_kept"])

    return {"seed": seed, "seed_amount": round(seed_amount, 8), "candidates": candidates,
            "sinks": sinks,
            "mixes": {m: t.mixes for m, t in traced.items()},
            "at_depth_limit": {m: round(t.at_depth_limit, 8) for m, t in traced.items()},
            "models": list(TRACE_MODELS)}


def exit_points(kind: str, subject: str, entity_graph, features, store, txs: dict,
                actor: dict | None = None, cfg: dict | None = None) -> dict:
    """Trace a seed to candidate cash-out points. An actor gives one trace per
    member cluster, each from that member alone."""
    cfg = cfg or config.load()
    traces = [trace_entity(seed, entity_graph, features, store, txs, cfg)
              for seed in seeds_of(kind, subject, features, actor)]
    header = store.header()
    return {"kind": kind, "subject": subject, "statement": STATEMENT,
            "traces": traces,
            "note": ("traced from the cluster holding this address; the entity graph is "
                     "cluster-level" if kind == "address" else
                     "each member cluster traced separately; an actor join is not a flow"
                     if kind == "actor" else None),
            "tag_bundles": [{k: b.get(k) for k in ("name", "ok", "simulated", "sources",
                                                   "manifest_hash", "created")}
                            for b in header["bundles"]],
            "simulated_tags": header["simulated"],
            "config": {k: cfg["exit_point"][k] for k in ("max_hops", "min_share",
                                                         "min_value_btc", "sink_min_share")}}
