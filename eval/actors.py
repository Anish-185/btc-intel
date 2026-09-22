"""The actor: one ground-truth illicit operation, and the metrics scored on it.

Pre-registered in docs/detection_unit_protocol.md. Everything here reads
`ground_truth.json` and nothing the pipeline produced.

Why this module exists at all: wallet-level recall answers "how many illicit
addresses did we enumerate", which is not the question an investigator asks. A
ransomware operation is one case with a collector address and a dozen peel
change addresses; a layering scheme is one case with a source, tens of hop
wallets and a sink. Scoring per wallet weights a case by how many near-identical
pass-through addresses it happens to contain. Scoring per actor asks whether the
operation was found, and once found, how much of it can be pulled in.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

import networkx as nx
import pandas as pd

from graph.builder import iter_transactions

from .datasets import Dataset

# Patterns whose clusters are the operation's own wallets. Victims are
# complainants, `cashout` counterparties receive the peel, `same_actor_cluster`
# is a clustering test and `coinjoin` is mixing — none of them is the actor.
# Matches engines.gnn.illicit_typologies.
ILLICIT_ACTOR_PATTERNS = {"ransomware_collector", "layering"}

# Transactions the operation itself broadcast. Their ground-truth cluster_id is
# the originating actor, which is what groups a layering instance's many hop
# actors back into the one launderer they represent.
OPERATION_TX_PATTERNS = {"ransomware_peel", "layering_split", "layering_merge"}

# The old broad label: every wallet the money passed through, hops included.
# Kept for wallet_recall_broad only, reported as secondary.
BROAD_PATTERNS = {"ransomware_collector", "layering", "cashout"}


@dataclass(frozen=True)
class Actor:
    """One illicit operation and the wallets it controls."""

    actor_id: str
    typology: str
    wallets: frozenset[str]


def _cluster_patterns(gt: dict) -> dict[str, str]:
    return {cid: c["pattern_type"] for cid, c in gt["clusters"].items()}


def actors_of(dataset: Dataset) -> list[Actor]:
    """Group the ground truth into illicit operations.

    A ransomware instance is already one actor in the generator (collector plus
    its peel change addresses). A layering instance is not: every hop is given
    its own `Actor` object because every wallet needs an owner. Those are
    grouped back by the originating cluster of the instance's split/merge
    transactions, which is the launderer.
    """
    gt = dataset.ground_truth()
    patterns = _cluster_patterns(gt)
    wallet_cluster = gt["wallets"]
    tx_meta = gt["transactions"]

    def illicit(wallet: str) -> bool:
        return patterns.get(wallet_cluster.get(wallet, ""), "") in ILLICIT_ACTOR_PATTERNS

    members: dict[str, set[str]] = {}
    typology: dict[str, str] = {}
    claimed: set[str] = set()
    for tx in iter_transactions(dataset.frame()):
        meta = tx_meta.get(tx.txid)
        if not meta or meta["pattern"] not in OPERATION_TX_PATTERNS:
            continue
        operation = meta["cluster_id"]
        typology.setdefault(operation, meta["typology"])
        bucket = members.setdefault(operation, set())
        for wallet in tx.input_addresses + tx.output_addresses:
            if illicit(wallet):
                bucket.add(wallet)
                claimed.add(wallet)

    # Anything illicit that no operation transaction touched (a ransomware
    # instance whose pot was too small to peel, say) still stands as its own
    # actor rather than vanishing from the denominator.
    for cid, pattern in patterns.items():
        if pattern not in ILLICIT_ACTOR_PATTERNS:
            continue
        rest = {w for w in gt["clusters"][cid]["wallets"] if w not in claimed}
        if rest:
            members.setdefault(cid, set()).update(rest)
            typology.setdefault(cid, pattern)

    return [Actor(cid, typology.get(cid, "unknown"), frozenset(wallets))
            for cid, wallets in sorted(members.items()) if wallets]


def broad_label_wallets(dataset: Dataset) -> set[str]:
    """The old label: every wallet of every illicit-patterned cluster."""
    gt = dataset.ground_truth()
    return {w for cid, c in gt["clusters"].items() if c["pattern_type"] in BROAD_PATTERNS
            for w in c["wallets"]}


def illicit_entities(actors: list[Actor], entity_of) -> set[str]:
    """The entity-level actor label: an entity holding any actor's wallet."""
    return {entity_of(w) for actor in actors for w in actor.wallets} - {None}


def reachable(entity_graph: nx.DiGraph, starts: set[str], hops: int,
              both: bool = False) -> set[str]:
    """Entities within `hops` of any start, walked the way taint walks."""
    seen = set(starts)
    frontier = deque((node, 0) for node in starts)
    while frontier:
        node, depth = frontier.popleft()
        if depth >= hops or node not in entity_graph:
            continue
        neighbours = set(entity_graph.successors(node))
        if both:
            neighbours |= set(entity_graph.predecessors(node))
        for nxt in neighbours - seen:
            seen.add(nxt)
            frontier.append((nxt, depth + 1))
    return seen


def case_metrics(dataset: Dataset, alerted: set[str], entity_of,
                 entity_wallets: dict[str, set[str]], entity_graph: nx.DiGraph,
                 cfg: dict, hops: tuple[int, ...] = (2, 4)) -> dict:
    """The actor-level scoreboard from docs/detection_unit_protocol.md."""
    actors = actors_of(dataset)
    both = cfg["fusion"]["taint"]["follow"] == "both"
    all_illicit = {w for actor in actors for w in actor.wallets}

    detected, coverage = [], {n: [] for n in hops}
    for actor in actors:
        alerted_wallets = {w for w in actor.wallets if entity_of(w) in alerted}
        if not alerted_wallets:
            continue
        detected.append(actor)
        others = set(actor.wallets) - alerted_wallets
        if not others:
            continue                    # nothing left to trace to: undefined, not zero
        starts = {entity_of(w) for w in alerted_wallets} - {None}
        for n in hops:
            reached = reachable(entity_graph, starts, n, both)
            found = {w for w in others if entity_of(w) in reached}
            coverage[n].append(len(found) / len(others))

    out = {
        "actors": len(actors),
        "detected_actors": len(detected),
        "case_detection_rate": _mean([1.0] * len(detected) + [0.0] * (len(actors) - len(detected))),
        "alert_precision": _mean([1.0 if entity_wallets.get(e, {e}) & all_illicit else 0.0
                                  for e in sorted(alerted)]),
        "alerts": len(alerted),
    }
    for n in hops:
        out[f"trace_coverage@{n}"] = _mean(coverage[n])
        out[f"traceable_actors@{n}"] = len(coverage[n])
    out["wallet_recall_broad"] = _mean(
        [1.0 if entity_of(w) in alerted else 0.0 for w in sorted(broad_label_wallets(dataset))])
    return out


def per_typology_cases(dataset: Dataset, alerted: set[str], entity_of,
                       entity_graph: nx.DiGraph, cfg: dict,
                       hops: tuple[int, ...] = (2, 4)) -> pd.DataFrame:
    """The same metrics, one row per typology."""
    actors = actors_of(dataset)
    both = cfg["fusion"]["taint"]["follow"] == "both"
    rows = []
    for typology in sorted({a.typology for a in actors}):
        group = [a for a in actors if a.typology == typology]
        row = {"typology": typology, "actors": len(group)}
        found = []
        cover = {n: [] for n in hops}
        for actor in group:
            alerted_wallets = {w for w in actor.wallets if entity_of(w) in alerted}
            found.append(1.0 if alerted_wallets else 0.0)
            others = set(actor.wallets) - alerted_wallets
            if not alerted_wallets or not others:
                continue
            starts = {entity_of(w) for w in alerted_wallets} - {None}
            for n in hops:
                reached = reachable(entity_graph, starts, n, both)
                cover[n].append(len({w for w in others if entity_of(w) in reached}) / len(others))
        row["case_detection_rate"] = _mean(found)
        row["mean_wallets"] = round(sum(len(a.wallets) for a in group) / len(group), 1)
        for n in hops:
            # n/a, not zero, when every wallet of every detected actor was
            # already alerted: there was nothing left to trace to.
            row[f"trace_coverage@{n}"] = _mean(cover[n])
            row[f"traceable@{n}"] = len(cover[n])
        rows.append(row)
    return pd.DataFrame(rows)


def _mean(values: list[float]) -> float | None:
    """None, not zero, for an empty sample — the metric is undefined, not bad."""
    return round(sum(values) / len(values), 3) if values else None
