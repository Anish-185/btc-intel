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
find a candidate, not the most. That penalty applies to relays only: a Tor exit
or hosting address is where a masked broadcast really did enter the network, so
penalising it in the ranking costs accuracy for nothing. Those are labelled
anonymized entry points instead, and only their attribution confidence is
discounted. See docs/detection_unit_protocol.md.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

import networkx as nx
import pandas as pd

import config
from analysis import validity
from graph.builder import Tx, iter_transactions
from ingest.ip_intel import IpIntel, IpClassification

from .tree import PropagationTree, build_trees, degraded_mode

COLUMNS = ["txid", "estimated_origin_ip", "ip_class", "estimator_used", "confidence",
           "attribution_confidence", "runner_up_ips", "runner_up_scores",
           "n_observations", "degraded", "low_confidence_origin",
           "anonymized_entry_point", "calibration_basis", *validity.COLUMNS]

#: What `confidence` is, stated beside every estimate: it ranks, it is not a
#: probability. The supervised model's is (origination/, isotonic).
CALIBRATION_BASIS = ("uncalibrated: the winner's share of the estimator's score vector, "
                     "damped by observation count")


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
    low_confidence: bool = False
    anonymized_entry_point: bool = False
    # Confidence as *attribution evidence*, which is not the same thing. A Tor
    # exit or hosting address can be exactly where the transaction entered the
    # network and still say almost nothing about who sent it: the estimate keeps
    # its rank and its stated confidence, and only the share of it that the
    # correlation engine may treat as evidence is reduced.
    attribution_confidence: float = 0.0
    validity: validity.Verdict = validity.VALID

    @property
    def runner_ups(self) -> list[tuple[str, float]]:
        return self.ranked[1:]


# --- estimators -----------------------------------------------------------
def first_timestamp(tree: PropagationTree, cfg: dict | None = None) -> dict[str, float]:
    """Earliest sighting wins; scores decay with reporting order.

    The ordering, ties included, is `PropagationTree.order()` — every tree ties
    at its earliest moment because one relay record stamps both ends of a hop,
    and the tie is resolved on which end was sending. See that method.
    """
    if not tree.first_seen:
        return {}
    order = tree.order()
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

    root = tree.earliest() if tree.earliest() in t else min(t.nodes)
    parent: dict[str, str | None] = {root: None}
    order: list[str] = []
    stack = [root]
    seen = {root}
    while stack:                                   # iterative DFS: trees can be deep
        node = stack.pop()
        order.append(node)
        # Sorted, so the traversal — and the subtree sizes the centrality is
        # computed from — depend on the graph and not on insertion order.
        for nb in sorted(t.neighbors(node)):
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
def class_weights(cfg: dict | None = None, mode: str | None = None) -> dict[str, float]:
    """The rank penalties for one filter configuration: off, combined or split.

    `split` is the default and only penalises public relays. See
    docs/detection_unit_protocol.md for why Tor and hosting left the penalty.
    """
    f = (cfg or config.load())["engines"]["propagation"]["origin_filter"]
    return dict(f["variants"][mode or f["mode"]])


def is_anonymized_entry(ip_class: str, cfg: dict | None = None) -> bool:
    """A Tor exit or hosting address: where the broadcast entered the network,
    not (usefully) who sent it."""
    f = (cfg or config.load())["engines"]["propagation"]["origin_filter"]
    return ip_class in f["anonymized_entry_classes"]


def attribution_confidence_of(confidence: float, anonymized: bool,
                              cfg: dict | None = None) -> float:
    """What the correlation engine may treat as evidence, not what we believe."""
    if not anonymized:
        return confidence
    f = (cfg or config.load())["engines"]["propagation"]["origin_filter"]
    return round(confidence * float(f["attribution_confidence_factor"]), 4)


def apply_class_weights(scores: dict[str, float], tree: PropagationTree, intel: IpIntel,
                        cfg: dict | None = None,
                        mode: str | None = None) -> tuple[dict[str, float], dict[str, IpClassification]]:
    """Down-weight infrastructure. A public relay is where everyone's traffic
    passes; finding it at the centre of a tree is expected, not incriminating."""
    cfg = cfg or config.load()
    weights = class_weights(cfg, mode)
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


def low_confidence_origin(ip_class: str, confidence: float, cfg: dict | None = None,
                          verdict: validity.Verdict | None = None) -> bool:
    """"Do not lean on this estimate" — nothing stronger.

    Set when the best candidate is a public relay — a node that forwards other
    people's traffic and is never a plausible sender — or when confidence falls
    below the cutoff, which is chosen on seed A and reported on seed B per
    docs/detection_unit_protocol.md.

    Formerly `origin_likely_unobserved`. Renamed because that name claimed the
    true origin was absent from the data, which no flag can know from inside:
    measured as a predictor of literal absence its precision was ~0.24, because
    absence is rare. What it actually separates is weak estimates from strong
    ones (right ~54% of the time when raised against ~81% when clear), and it is
    now named for that.

    A failed validity check (analysis.validity) raises it too: that is how an
    invalid attribution abstains, through this flag and not beside it.
    """
    cfg = cfg or config.load()
    p = cfg["engines"]["propagation"]
    return bool(ip_class in p["low_confidence_classes"]
                or confidence < p["low_confidence_cutoff"]
                or (verdict is not None and not verdict.passed and validity.enforced(cfg)))


def estimate_origin(tree: PropagationTree, intel: IpIntel, cfg: dict | None = None,
                    estimator: str | None = None, mode: str | None = None,
                    tx: Tx | None = None) -> OriginEstimate:
    """`tx`, when the caller has the transaction's structure, lets the
    validity layer see a CoinJoin; without it that one check cannot fire."""
    cfg = cfg or config.load()
    p = cfg["engines"]["propagation"]
    name = estimator or p["estimator"]

    if tree.is_single_observation or tree.size <= 1:
        # Nothing to estimate from: report the first-seen IP, say so, and keep
        # the confidence low enough that nothing downstream leans on it.
        ip = tree.earliest()
        c = intel.classify(ip, tree.graph.nodes.get(ip, {}).get("asn")) if ip else None
        ip_class = c.ip_class if c else "residential_or_unknown"
        confidence = p["single_row_confidence"] if ip else 0.0
        verdict = validity.assess_tree(tree, ip, intel, cfg, tx)
        return OriginEstimate(
            tree.txid, ip, ip_class, "first_timestamp", confidence,
            [(ip, 1.0)] if ip else [], tree.n_observations, degraded=True,
            evidence=["single relay observation: first-seen IP, not an estimate"],
            low_confidence=low_confidence_origin(ip_class, confidence, cfg, verdict),
            validity=verdict,
            anonymized_entry_point=is_anonymized_entry(ip_class, cfg),
            attribution_confidence=attribution_confidence_of(
                confidence, is_anonymized_entry(ip_class, cfg), cfg))

    scores = ESTIMATORS[name](tree, cfg)
    weighted, classified = apply_class_weights(scores, tree, intel, cfg, mode)
    ranked = sorted(weighted.items(), key=lambda kv: (-kv[1], kv[0]))
    if not ranked:
        return OriginEstimate(tree.txid, None, "residential_or_unknown", name, 0.0, [],
                              tree.n_observations, degraded=True, low_confidence=True,
                              validity=validity.assess(0, cfg=cfg))
    best_ip = ranked[0][0]
    ip_class = classified[best_ip].ip_class
    confidence = confidence_of(ranked, tree.n_observations)
    anonymized = is_anonymized_entry(ip_class, cfg)
    evidence = list(classified[best_ip].evidence)
    verdict = validity.assess_tree(tree, best_ip, intel, cfg, tx)
    if anonymized:
        evidence.append("anonymized entry point: this is where the broadcast entered "
                        "the network, not necessarily who sent it")
    return OriginEstimate(
        tree.txid, best_ip, ip_class, name, confidence, ranked, tree.n_observations,
        degraded=False, evidence=evidence,
        low_confidence=low_confidence_origin(ip_class, confidence, cfg, verdict),
        anonymized_entry_point=anonymized, validity=verdict,
        attribution_confidence=attribution_confidence_of(confidence, anonymized, cfg))


def estimate_all(df: pd.DataFrame, intel: IpIntel, cfg: dict | None = None,
                 estimator: str | None = None,
                 mode: str | None = None) -> tuple[pd.DataFrame, dict]:
    """`mode` selects the origin-filter configuration (off | combined | split);
    None uses the configured default."""
    cfg = cfg or config.load()
    n_runner_ups = cfg["engines"]["propagation"]["runner_ups"]
    status = degraded_mode(df)
    trees = build_trees(df)
    txs = ({tx.txid: tx for tx in iter_transactions(df)}
           if "input_addresses" in df else {})
    rows = []
    for tree in trees.values():
        est = estimate_origin(tree, intel, cfg, estimator, mode, txs.get(tree.txid))
        runners = est.runner_ups[:n_runner_ups]
        rows.append({
            "txid": est.txid, "estimated_origin_ip": est.ip, "ip_class": est.ip_class,
            "estimator_used": est.estimator, "confidence": est.confidence,
            "attribution_confidence": est.attribution_confidence,
            "runner_up_ips": [ip for ip, _ in runners],
            "runner_up_scores": [round(float(s), 6) for _, s in runners],
            "n_observations": est.n_observations, "degraded": est.degraded,
            "low_confidence_origin": est.low_confidence,
            "anonymized_entry_point": est.anonymized_entry_point,
            "calibration_basis": CALIBRATION_BASIS,
            **est.validity.columns(),
        })
    return pd.DataFrame(rows, columns=COLUMNS), status
