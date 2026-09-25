"""The validity layer: when an origin attribution is invalid, say so and abstain.

Calibration answers "how often is a 0.8 right?". This module answers a prior
question — "is this a transaction origin attribution can be about at all?" —
and when the answer is no, the attribution is withheld with a reason code and
the evidence behind it. docs/VALIDITY.md is the taxonomy.

    DEGENERATE      candidate_count 0 or 1: nothing to rank.
    NOT_REACHABLE   every candidate is a known public relay (the matrix's
                    `scope_out`): the sender is not among what this observer
                    can see, which is the zero-ceiling case.
    COINJOIN        one broadcaster, many owners: naming whoever broadcast it
                    attributes nobody else's inputs.
    TOR_OR_V2       the named peer is a .onion address, or reached us over
                    BIP-324 encrypted transport.
    DANDELION_STEM  the first announcement stands alone before a burst: the
                    shape a stem-phase relay leaves, where the first announcer
                    is one hop of a serial chain, not the sender.

A failed check does not open a second abstention path. It sets
`low_confidence_origin` (engines.propagation) and is read by
`eval.origin.flagged_at`, the one rule every origin output already abstains
through; `validity.enforce: false` in config.yaml switches it off there, which
is how the with/without comparison and the no-abstention floor are scored.

Each detector returns a `Verdict` (reason code, confidence the condition is
present, evidence) or None. `assess` runs them in the order above and reports
the first that fires.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass

import pandas as pd

import config
from graph.builder import Tx
from graph.clustering import equal_value_group, is_coinjoin

PASS = "PASS"
DEGENERATE = "DEGENERATE"
NOT_REACHABLE = "NOT_REACHABLE"
COINJOIN = "COINJOIN"
TOR_OR_V2 = "TOR_OR_V2"
DANDELION_STEM = "DANDELION_STEM"
REASONS = (DEGENERATE, NOT_REACHABLE, COINJOIN, TOR_OR_V2, DANDELION_STEM)

#: The columns a frame of origins carries.
COLUMNS = ["validity", "validity_confidence", "validity_evidence"]


@dataclass(frozen=True)
class Verdict:
    reason: str = PASS
    confidence: float | None = None       # that the condition is present; None on PASS
    evidence: tuple[str, ...] = ()

    @property
    def passed(self) -> bool:
        return self.reason == PASS

    def as_dict(self) -> dict:
        return {"status": "PASS" if self.passed else "INCONCLUSIVE",
                "reason": None if self.passed else self.reason,
                "confidence": self.confidence, "evidence": list(self.evidence)}

    def columns(self) -> dict:
        return {"validity": self.reason, "validity_confidence": self.confidence,
                "validity_evidence": list(self.evidence)}


VALID = Verdict(PASS, None, ("no invalidating condition detected",))

#: Not a detector: what an output stored before this layer existed carries, so
#: that it is never served without a verdict and never passed off as PASS.
NOT_ASSESSED = Verdict("NOT_ASSESSED", None, (
    "produced before the validity layer existed; rerun the pipeline to assess it",))


def enforced(cfg: dict) -> bool:
    return bool(cfg.get("validity", {}).get("enforce", True))


# --- the detectors ----------------------------------------------------------
def degenerate(candidate_count: int) -> Verdict | None:
    if candidate_count > 1:
        return None
    return Verdict(DEGENERATE, 1.0, (
        f"{candidate_count} peer{'s' if candidate_count != 1 else ''} announced this "
        "transaction to the observer, so there is nothing to compare",))


def not_reachable(scope_out: bool) -> Verdict | None:
    if not scope_out:
        return None
    return Verdict(NOT_REACHABLE, 1.0, (
        "every peer that announced it is a known public relay; the sender is not "
        "among the candidates this observer can see",))


def coinjoin(tx: Tx | None, cfg: dict) -> Verdict | None:
    """`graph.clustering.is_coinjoin` — the check clustering already uses to skip
    common-input-ownership, so a mix is one thing everywhere."""
    if tx is None or not is_coinjoin(tx, cfg):
        return None
    value, group = equal_value_group(tx.output_values,
                                     cfg["graph"]["coinjoin"]["equal_value_tolerance"])
    target = cfg["engines"]["rules"]["coinjoin"]["target_equal_outputs"]
    return Verdict(COINJOIN, round(min(1.0, len(group) / target), 3), (
        f"{len(group)} of {len(tx.outputs)} outputs pay {value:.8f} BTC, from "
        f"{len(tx.inputs)} inputs",
        "a CoinJoin has one broadcaster and many owners: whoever broadcast it says "
        "nothing about who owns the other inputs"))


def tor_or_v2(peer: str | None, transport: str | None) -> Verdict | None:
    if peer and str(peer).endswith(".onion"):
        return Verdict(TOR_OR_V2, 1.0, (
            f"{peer} is a Tor hidden service: its timing includes a Tor circuit and "
            "its address names nobody",))
    if transport == "v2":
        return Verdict(TOR_OR_V2, 1.0, (
            f"{peer} announced over BIP-324 encrypted transport: a passive capture "
            "cannot read that link, so this view of the peer may be incomplete",))
    return None


def dandelion_stem(times, cfg: dict) -> Verdict | None:
    """First-announcement isolation. A stem hands the transaction to one peer
    at a time; an observer on or beside the stem hears one announcement, then
    nothing, then the broadcast arrives as a burst. Ordinary diffusion reaches
    an observer's neighbours at a steadier pace.

    The statistic is the gap after the first announcement over the median gap
    among the rest. Its threshold is fixed in config.yaml, before any result.
    """
    d = cfg["validity"]["dandelion"]
    t = sorted(float(x) for x in times)
    if len(t) < d["min_candidates"]:
        return None
    gaps = [b - a for a, b in zip(t, t[1:])]
    later = statistics.median(gaps[1:])
    if gaps[0] <= 0:
        return None
    ratio = gaps[0] / later if later > 0 else float("inf")
    if ratio < d["isolation_ratio"]:
        return None
    return Verdict(DANDELION_STEM, round(1.0 - 0.5 * d["isolation_ratio"] / ratio, 3), (
        f"the first announcement stood alone for {gaps[0] * 1000:.0f} ms, "
        f"{ratio:.1f}x the median gap between the {len(t) - 1} that followed",
        "a Dandelion stem forwards to one peer at a time before broadcast, so the "
        "first announcer may be a stem relay, not the sender"))


# --- one origin --------------------------------------------------------------
def assess(candidate_count: int, scope_out: bool = False, peer: str | None = None,
           transport: str | None = None, times=(), tx: Tx | None = None,
           cfg: dict | None = None) -> Verdict:
    """Every detector, in `REASONS` order; the first that fires is the verdict."""
    cfg = cfg or config.load()
    checks = (lambda: degenerate(candidate_count), lambda: not_reachable(scope_out),
              lambda: coinjoin(tx, cfg), lambda: tor_or_v2(peer, transport),
              lambda: dandelion_stem(times, cfg))
    for check in checks:
        if (verdict := check()) is not None:
            return verdict
    return VALID


def assess_tree(tree, peer: str | None, intel, cfg: dict | None = None,
                tx: Tx | None = None, exclude=()) -> Verdict:
    """For an `engines.propagation` tree. Candidates and announcement times are
    the tree's senders (`first_sent`), less `exclude` (an observer)."""
    cfg = cfg or config.load()
    exclude = set(exclude)
    announced = tree.first_sent or tree.first_seen
    candidates = [ip for ip in tree.ips if ip not in exclude]
    count = 1 if tree.is_single_observation else len(candidates)
    relay = set(cfg["engines"]["propagation"]["low_confidence_classes"])
    scope_out = bool(candidates) and all(
        intel.classify(ip, tree.graph.nodes.get(ip, {}).get("asn")).ip_class in relay
        for ip in candidates)
    return assess(count, scope_out, peer, None,
                  [ts for ip, ts in announced.items() if ip not in exclude], tx, cfg)


def tx_of(txid: str, shape) -> Tx | None:
    """A transaction's structure from a corpus row (`generator.typologies.shape`)."""
    if shape is None:
        return None
    return Tx(txid, list(zip(shape["in_addrs"], shape["in_vals"])),
              list(zip(shape["out_addrs"], shape["out_vals"])))


def assess_matrix(matrix: pd.DataFrame, named: pd.DataFrame,
                  shapes: pd.DataFrame | None = None, cfg: dict | None = None) -> pd.DataFrame:
    """For the `features.relay` matrix: one verdict per (capture_id, txid), about
    the peer `named` says was chosen (`estimated_origin_ip`)."""
    cfg = cfg or config.load()
    key = ["capture_id", "txid"]
    chosen = named.set_index(key)["estimated_origin_ip"]
    shape_of = shapes.set_index(key) if shapes is not None and len(shapes) else None
    rows = []
    for (capture_id, txid), group in matrix.groupby(key, sort=False):
        peer = chosen.get((capture_id, txid))
        mine = group[group["peer_ip"] == peer]
        v2 = bool(mine["transport_v2"].any()) if "transport_v2" in group and len(mine) else False
        shape = (shape_of.loc[(capture_id, txid)]
                 if shape_of is not None and (capture_id, txid) in shape_of.index else None)
        verdict = assess(int(group["candidate_count"].iloc[0]),
                         bool(group["scope_out"].iloc[0]), peer, "v2" if v2 else None,
                         group["delta_vs_first_s"].to_numpy(), tx_of(txid, shape), cfg)
        rows.append({"capture_id": capture_id, "txid": txid, **verdict.columns()})
    return pd.DataFrame(rows, columns=key + COLUMNS)
