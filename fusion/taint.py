"""Taint propagation: suspicion inherited by following the money.

Seeds are entities an analyst already knows are bad — a watchlist. Suspicion
flows outward along the entity graph, halving (by config) at every hop, and
stopping after a few hops because beyond that everything on a blockchain is
connected to everything.

Seeds are NEVER taken from our own rules engine. That was the original design
and it made taint worthless as an independent signal: the rules fire on the
same clusters the labels describe, so taint scored AUC 0.999 alone while
finding nothing the rules had not already flagged. Taint earns its place only
by finding accomplices the rules missed, which requires its seeds to come from
outside the system.

This is the "haircut" idea from conventional taint analysis, simplified: we
decay per hop rather than per proportion of value, because our goal is to rank
leads for a human, not to compute what fraction of a coin is dirty.

A CoinJoin terminates taint. Its inputs and outputs belong to many unrelated
participants, so following value through one reaches everybody who mixed that
round; an edge that exists only because of CoinJoins (`mix_count == count`,
set by graph.entity_graph from clustering.is_coinjoin — the same check
analysis.validity's COINJOIN verdict uses) is not crossed. Taint still reaches
the participant that fed the mix; it stops there.

A taint score is INHERITED suspicion, not evidence of wrongdoing. Receiving
money two hops from a ransomware collector is what happens to exchanges,
merchants and ordinary people every day. The taint_path exists so an
investigator can see exactly which chain produced the score and dismiss it.
"""

from __future__ import annotations

import heapq
import json
from dataclasses import dataclass, field
from pathlib import Path

import networkx as nx
import pandas as pd

import config

COLUMNS = ["entity_id", "taint_score", "taint_path", "taint_hops", "taint_seed"]


@dataclass
class Taint:
    entity_id: str
    score: float
    path: list[str] = field(default_factory=list)

    @property
    def hops(self) -> int:
        return max(len(self.path) - 1, 0)

    @property
    def seed(self) -> str | None:
        return self.path[0] if self.path else None


def seeds_from_watchlist(watchlist: dict, entity_of, cfg: dict | None = None) -> dict[str, float]:
    """Map an analyst's known-bad wallets onto the entities holding them."""
    cfg = cfg or config.load()
    weight = cfg["fusion"]["taint"]["watchlist_weight"]
    seeds: dict[str, float] = {}
    for item in (watchlist or {}).get("wallets", []):
        wallet = item["wallet"] if isinstance(item, dict) else str(item)
        entity = entity_of(wallet)
        if entity:
            seeds[entity] = max(seeds.get(entity, 0.0), float(weight))
    return seeds


def load_watchlist(path=None, cfg: dict | None = None) -> dict:
    """Look for the watchlist beside the dataset, then in data/intel/."""
    cfg = cfg or config.load()
    candidates = []
    if path:
        p = Path(path)
        candidates += [p / cfg["intel"]["synthetic_watchlist"]] if p.is_dir() else [p]
    candidates.append(Path(cfg["ingest"]["input_dir"]) / cfg["intel"]["synthetic_watchlist"])
    candidates.append(Path(cfg["intel"]["watchlist_path"]))
    for candidate in candidates:
        if candidate.exists():
            return json.loads(candidate.read_text())
    return {"wallets": []}


def propagate(entity_graph: nx.DiGraph, seeds: dict[str, float],
              cfg: dict | None = None) -> dict[str, Taint]:
    """Best-first search outward from the seeds, decaying per hop.

    Each entity keeps the strongest taint that reaches it, with the path that
    produced it — a weaker chain never overwrites a stronger one.
    """
    cfg = cfg or config.load()
    t = cfg["fusion"]["taint"]
    decay, max_hops, floor = t["decay_per_hop"], t["max_hops"], t["min_taint"]
    both = t["follow"] == "both"

    best: dict[str, Taint] = {}
    queue: list[tuple[float, int, str, tuple[str, ...]]] = []
    for seed, weight in seeds.items():
        if seed in entity_graph or True:      # a seed with no edges still stands alone
            heapq.heappush(queue, (-weight, 0, seed, (seed,)))

    while queue:
        negative, hops, node, path = heapq.heappop(queue)
        score = -negative
        if score < floor:
            continue
        current = best.get(node)
        if current is not None and current.score >= score:
            continue
        best[node] = Taint(node, score, list(path))
        if hops >= max_hops or node not in entity_graph:
            continue
        neighbours = set(entity_graph.successors(node))
        if both:
            neighbours |= set(entity_graph.predecessors(node))
        for nxt in neighbours:
            if nxt in path:                    # never loop back through a cycle
                continue
            if _through_mix_only(entity_graph, node, nxt, both):
                continue
            heapq.heappush(queue, (-(score * decay), hops + 1, nxt, path + (nxt,)))
    return best


def _through_mix_only(g: nx.DiGraph, node: str, nxt: str, both: bool) -> bool:
    """Every edge taint could follow from `node` to `nxt` is made of CoinJoins."""
    carrying = [g.edges[e] for e in [(node, nxt)] + ([(nxt, node)] if both else [])
                if g.has_edge(*e)]
    return bool(carrying) and all(e.get("mix_count", 0) >= e.get("count", 1) for e in carrying)


def taint_frame(taints: dict[str, Taint]) -> pd.DataFrame:
    rows = [{"entity_id": t.entity_id, "taint_score": t.score, "taint_path": t.path,
             "taint_hops": t.hops, "taint_seed": t.seed} for t in taints.values()]
    df = pd.DataFrame(rows, columns=COLUMNS)
    return df.sort_values("taint_score", ascending=False, ignore_index=True)


def compute_taint(entity_graph: nx.DiGraph, watchlist: dict | None = None,
                  entity_of=None, extra_seeds: dict[str, float] | None = None,
                  cfg: dict | None = None) -> pd.DataFrame:
    cfg = cfg or config.load()
    seeds: dict[str, float] = {}
    if watchlist and entity_of is not None:
        seeds = seeds_from_watchlist(watchlist, entity_of, cfg)
    for entity, weight in (extra_seeds or {}).items():
        seeds[entity] = max(seeds.get(entity, 0.0), float(weight))
    return taint_frame(propagate(entity_graph, seeds, cfg))


# --- value tracing, for exit points (analysis/exit_point.py) -------------------
#: Two ways of saying how much of an entity's outflow is the seed's money.
#: haircut: an entity that received `a` of tainted value out of everything it
#: received forwards that share on each output (proportional). poison: any
#: contact taints everything the entity sends (an upper envelope).
#: FIFO is not offered: it needs per-output ordering the entity graph does not
#: keep, and would have to be a second tracer over the wallet graph.
TRACE_MODELS = ("haircut", "poison")


@dataclass
class Traced:
    """What one trace found. Amounts are in BTC."""

    seed: str
    model: str
    seed_amount: float
    received: dict[str, float] = field(default_factory=dict)   # entity -> tainted value in
    terminal: dict[str, float] = field(default_factory=dict)   # ... that it did not pass on
    paths: dict[str, list[dict]] = field(default_factory=dict)  # entity -> k best paths
    mixes: list[dict] = field(default_factory=list)            # where taint met a CoinJoin
    at_depth_limit: float = 0.0


def _external(g: nx.DiGraph, node: str) -> tuple[float, float]:
    ext_in = sum(d["value"] for *_, d in g.in_edges(node, data=True))
    ext_out = sum(d["value"] for *_, d in g.out_edges(node, data=True))
    return ext_in, ext_out


def trace(entity_graph: nx.DiGraph, seed: str, model: str, merge_confidence: dict,
          stop: set[str] = frozenset(), cfg: dict | None = None) -> Traced:
    """Follow the seed entity's outflow forward over the entity graph.

    Uses the rules `propagate` uses: outgoing edges only, never back through a
    cycle, and never across an edge made only of CoinJoins. Instead of
    guessing past a mix, a CoinJoin edge is recorded in `mixes` with the value
    that entered it. `stop` entities (cash-out points: tagged exchanges) keep
    what they receive; their outflow is other customers' money.

    Value is propagated hop by hop to `exit_point.max_hops`. An entity whose
    summed tainted inflow at a hop is below `min_share` of the seed's outflow
    (haircut) or `min_value_btc` (poison) is not followed. Paths are kept best-first by path confidence, the product of
    the merge confidence of every entity on the path and, under haircut, the
    taint fraction of every hop. At most `paths_per_entity` per entity.
    """
    cfg = cfg or config.load()
    if model not in TRACE_MODELS:
        raise ValueError(f"model is one of {TRACE_MODELS}")
    x = cfg["exit_point"]
    max_hops, k = x["max_hops"], x["paths_per_entity"]
    g = entity_graph
    _, seed_out = _external(g, seed) if seed in g else (0.0, 0.0)
    out = Traced(seed, model, seed_out)
    if not seed_out:
        return out
    floor = x["min_share"] * seed_out if model == "haircut" else x["min_value_btc"]

    def forward(node: str) -> float:
        """The share of what `node` received that it passed on."""
        if node == seed:
            return 1.0
        ext_in, ext_out = _external(g, node)
        return ext_out / max(ext_in, ext_out) if ext_out else 0.0

    # Amounts, layer by layer.
    frontier, crossed = {seed: seed_out}, set()
    for depth in range(max_hops + 1):
        nxt_frontier: dict[str, float] = {}
        for node, amount in frontier.items():
            share = forward(node)
            if node != seed:
                expand = node not in stop and depth < max_hops and share > 0
                out.terminal[node] = out.terminal.get(node, 0.0) + (
                    amount * (1 - share) if expand else amount)
                if not expand:
                    if node not in stop and depth >= max_hops:
                        out.at_depth_limit += amount * share
                    continue
            _, ext_out = _external(g, node)
            for _, dst, d in g.out_edges(node, data=True):
                if dst == seed:
                    continue
                carried = (amount * share * d["value"] / ext_out if model == "haircut"
                           else d["value"])
                if _through_mix_only(g, node, dst, False):
                    if (node, dst) not in crossed:
                        crossed.add((node, dst))
                        out.mixes.append({"from": node, "to": dst, "txids": list(d["txids"]),
                                          "value": round(carried, 8), "depth": depth + 1})
                    continue
                if model == "poison":
                    if (node, dst) in crossed:
                        continue                   # poison counts each edge once
                    crossed.add((node, dst))
                nxt_frontier[dst] = nxt_frontier.get(dst, 0.0) + carried
        # Pruned per entity after summing, not per edge: layering fans out
        # into branches each too small to follow and merges them again, and
        # a per-edge floor never reaches the merge.
        frontier = {n: a for n, a in nxt_frontier.items() if a >= floor}
        for n, a in frontier.items():
            out.received[n] = out.received.get(n, 0.0) + a
        if not frontier:
            break

    # Paths, best-first by confidence, k per entity.
    counter, found = 0, {}
    queue: list = [(-1.0, counter, seed, (seed,), (), 1.0)]
    while queue:
        negative, _, node, path, hops, fraction = heapq.heappop(queue)
        if node != seed:
            bucket = found.setdefault(node, [])
            if len(bucket) >= k:
                continue
            bucket.append({"entities": list(path), "hops": list(hops),
                           "confidence": round(-negative, 6),
                           "taint_fraction": round(fraction, 6)})
            if node in stop or forward(node) == 0:
                continue
        if len(hops) >= max_hops:
            continue
        _, ext_out = _external(g, node)
        for _, dst, d in g.out_edges(node, data=True):
            if dst in path or _through_mix_only(g, node, dst, False):
                continue
            f = d["value"] / ext_out if model == "haircut" else 1.0
            if dst not in out.received:        # the amount pass did not follow it
                continue
            merge = float(merge_confidence.get(dst, 1.0))
            hop = {"from": node, "to": dst, "value": round(d["value"], 8),
                   "fraction": round(f, 6), "merge_confidence": merge,
                   "txids": list(d["txids"]), "first_seen": d.get("first_seen"),
                   "last_seen": d.get("last_seen"), "mixed_txs": int(d.get("mix_count", 0))}
            counter += 1
            heapq.heappush(queue, (negative * merge * f, counter, dst, path + (dst,),
                                   hops + (hop,), fraction * f))
    out.paths = found
    return out
