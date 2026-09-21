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
            heapq.heappush(queue, (-(score * decay), hops + 1, nxt, path + (nxt,)))
    return best


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
