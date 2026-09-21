"""Which IP most likely *originated* each transaction.

Three estimators, compared rather than assumed:

  first_timestamp
      Whichever IP we saw first. The "first-spy" baseline: cheap, and what
      naive analysis does. It is badly biased when observation is sparse — the
      first hop you happen to record is usually a relay downstream of the
      source, not the source.

  rumor_centrality
      Shah & Zaman, "Rumors in a Network: Who's the Culprit?", IEEE
      Transactions on Information Theory 57(8), 2011. For a tree of n nodes the
      rumor centrality of v is R(v) = n! / prod_u t_u^v, where t_u^v is the
      size of u's subtree when the tree is rooted at v. The maximiser is the
      maximum-likelihood source under a diffusion model. Computed here in log
      space, with the standard O(n) reroot recurrence
      log R(child) = log R(parent) + log t_child - log(n - t_child).
      Caveat: the estimator assumes the tree IS the infected set. Ours is a
      sampled subset of the real diffusion, so this is an approximation.

  timestamp_weighted_centrality
      Fanti & Viswanath, "Anonymity Properties of the Bitcoin P2P Network",
      arXiv:1703.08761, which studies exactly this: how diffusion timing plus
      graph position leak the source. Combines normalised rumor centrality with
      how early a node reported, weights in config.yaml.

All three are then multiplied by a per-class weight, because a publicly
reachable Bitcoin node sitting at the centre of an observed tree is where
everybody's transactions pass through — it is the least informative place to
find a candidate, not the most.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

import networkx as nx
import pandas as pd

import config
from ingest.ip_intel import IpIntel, IpClassification

from .tree import PropagationTree, build_trees, degraded_mode

COLUMNS = ["txid", "estimated_origin_ip", "ip_class", "estimator_used", "confidence",
           "runner_up_ips", "runner_up_scores", "n_observations", "degraded"]


@dataclass
class OriginEstimate:
    txid: str
    ip: str | None
    ip_class: str
    estimator: str
    confidence: float
    ranked: list[tuple[str, float]] = field(default_factory=list)
    n_observations: int = 0
    degraded: bool = False
    evidence: list[str] = field(default_factory=list)

    @property
    def runner_ups(self) -> list[tuple[str, float]]:
        return self.ranked[1:]


# --- estimators -----------------------------------------------------------
def first_timestamp(tree: PropagationTree, cfg: dict | None = None) -> dict[str, float]:
    """Earliest sighting wins; scores decay with reporting order."""
    if not tree.first_seen:
        return {}
    order = sorted(tree.first_seen, key=tree.first_seen.get)
    n = len(order)
    return {ip: (n - i) / n for i, ip in enumerate(order)}


def rumor_centrality(tree: PropagationTree, cfg: dict | None = None) -> dict[str, float]:
    """Shah & Zaman (2011), in log space and normalised to [0, 1]."""
    t = tree.undirected_tree()
    n = t.number_of_nodes()
    if n == 0:
        return {}
    if n == 1:
        return {next(iter(t.nodes)): 1.0}

    root = tree.earliest() if tree.earliest() in t else next(iter(t.nodes))
    parent: dict[str, str | None] = {root: None}
    order: list[str] = []
    stack = [root]
    seen = {root}
    while stack:                                   # iterative DFS: trees can be deep
        node = stack.pop()
        order.append(node)
        for nb in t.neighbors(node):
            if nb not in seen:
                seen.add(nb)
                parent[nb] = node
                stack.append(nb)

    subtree = {node: 1 for node in order}
    for node in reversed(order):                   # post-order accumulation
        if parent[node] is not None:
            subtree[parent[node]] += subtree[node]

    log_r = {root: sum(math.log(i) for i in range(1, n + 1))
             - sum(math.log(subtree[node]) for node in order)}
    for node in order:                             # reroot along each edge
        if parent[node] is None:
            continue
        log_r[node] = log_r[parent[node]] + math.log(subtree[node]) - math.log(n - subtree[node])

    top = max(log_r.values())
    scores = {ip: math.exp(value - top) for ip, value in log_r.items()}
    for ip in tree.ips:                            # nodes trimmed from the tree
        scores.setdefault(ip, 0.0)
    return scores


def timestamp_weighted_centrality(tree: PropagationTree, cfg: dict | None = None) -> dict[str, float]:
    """Fanti & Viswanath (2017): graph position and timing together."""
    cfg = cfg or config.load()
    p = cfg["engines"]["propagation"]
    centrality = rumor_centrality(tree, cfg)
    timing = first_timestamp(tree, cfg)
    if not centrality:
        return timing
    w_c, w_t = p["centrality_weight"], p["timing_weight"]
    return {ip: w_c * centrality.get(ip, 0.0) + w_t * timing.get(ip, 0.0)
            for ip in set(centrality) | set(timing)}


ESTIMATORS = {
    "first_timestamp": first_timestamp,
    "rumor_centrality": rumor_centrality,
    "timestamp_weighted_centrality": timestamp_weighted_centrality,
}


# --- class weighting and confidence --------------------------------------
def apply_class_weights(scores: dict[str, float], tree: PropagationTree, intel: IpIntel,
                        cfg: dict | None = None) -> tuple[dict[str, float], dict[str, IpClassification]]:
    """Down-weight infrastructure. A public relay is where everyone's traffic
    passes; finding it at the centre of a tree is expected, not incriminating."""
    cfg = cfg or config.load()
    weights = cfg["engines"]["propagation"]["class_weights"]
    classified: dict[str, IpClassification] = {}
    weighted = {}
    for ip, score in scores.items():
        asn = tree.graph.nodes.get(ip, {}).get("asn")
        c = intel.classify(ip, asn)
        classified[ip] = c
        weighted[ip] = score * weights.get(c.ip_class, 1.0)
    return weighted, classified


def confidence_of(ranked: list[tuple[str, float]], n_observations: int) -> float:
    """Share of the total score, damped by how much we actually observed.

    A clear winner among many candidates still means little if we only saw two
    hops, so the observation count caps how confident the estimate may be.
    """
    total = sum(max(s, 0.0) for _, s in ranked)
    share = (ranked[0][1] / total) if total > 0 else 0.0
    observed = 1.0 - math.exp(-n_observations / 3.0)
    return round(min(1.0, max(0.0, share * observed)), 4)


def estimate_origin(tree: PropagationTree, intel: IpIntel, cfg: dict | None = None,
                    estimator: str | None = None) -> OriginEstimate:
    cfg = cfg or config.load()
    p = cfg["engines"]["propagation"]
    name = estimator or p["estimator"]

    if tree.is_single_observation or tree.size <= 1:
        # Nothing to estimate from: report the first-seen IP, say so, and keep
        # the confidence low enough that nothing downstream leans on it.
        ip = tree.earliest()
        c = intel.classify(ip, tree.graph.nodes.get(ip, {}).get("asn")) if ip else None
        return OriginEstimate(
            tree.txid, ip, c.ip_class if c else "residential_or_unknown", "first_timestamp",
            p["single_row_confidence"] if ip else 0.0,
            [(ip, 1.0)] if ip else [], tree.n_observations, degraded=True,
            evidence=["single relay observation: first-seen IP, not an estimate"])

    scores = ESTIMATORS[name](tree, cfg)
    weighted, classified = apply_class_weights(scores, tree, intel, cfg)
    ranked = sorted(weighted.items(), key=lambda kv: (-kv[1], kv[0]))
    if not ranked:
        return OriginEstimate(tree.txid, None, "residential_or_unknown", name, 0.0, [],
                              tree.n_observations, degraded=True)
    best_ip = ranked[0][0]
    return OriginEstimate(
        tree.txid, best_ip, classified[best_ip].ip_class, name,
        confidence_of(ranked, tree.n_observations), ranked, tree.n_observations,
        degraded=False, evidence=classified[best_ip].evidence)


def estimate_all(df: pd.DataFrame, intel: IpIntel, cfg: dict | None = None,
                 estimator: str | None = None) -> tuple[pd.DataFrame, dict]:
    cfg = cfg or config.load()
    n_runner_ups = cfg["engines"]["propagation"]["runner_ups"]
    status = degraded_mode(df)
    trees = build_trees(df)
    rows = []
    for tree in trees.values():
        est = estimate_origin(tree, intel, cfg, estimator)
        runners = est.runner_ups[:n_runner_ups]
        rows.append({
            "txid": est.txid, "estimated_origin_ip": est.ip, "ip_class": est.ip_class,
            "estimator_used": est.estimator, "confidence": est.confidence,
            "runner_up_ips": [ip for ip, _ in runners],
            "runner_up_scores": [round(float(s), 6) for _, s in runners],
            "n_observations": est.n_observations, "degraded": est.degraded,
        })
    return pd.DataFrame(rows, columns=COLUMNS), status
