"""The validity layer: when an origin attribution is invalid, or means less than
it appears to, say so — and say which.

Calibration answers "how often is a 0.8 right?". This module answers prior
questions: can an attribution be about this transaction at all, and if so,
what may it claim? docs/VALIDITY.md is the taxonomy and the pre-registered
metric revision. Every reason that fires is reported; the verdict's tier is
the most severe among them:

  ABSTAIN    DEGENERATE      candidate_count 0 or 1: nothing to rank.
             NOT_REACHABLE   every candidate is a known public relay (the
                             matrix's `scope_out`): the zero-ceiling case.
  QUALIFIED  COINJOIN        the answer is the broadcasting peer only; the
                             inputs' ownership is not attributable.
             TOR_ONION       the answer is an onion identity, never an IP.
  ANNOTATE   DANDELION_STEM  the first announcement stands alone before a
                             burst, the shape a stem leaves. Flag only:
                             Dandelion is not deployed in Bitcoin Core.
             V2_PASSIVE_TAP  a pcap capture held port-8333 flows it could not
                             decode (BIP-324 v2): v2 peers may be missing from
                             the candidates. Never on debug.log/.btcap, which
                             the node — a session endpoint — writes.

Only ABSTAIN withholds an answer, and it does so through the existing rule —
`low_confidence_origin` (engines.propagation) and `eval.origin.flagged_at` —
not a second path. `validity.enforce: false` switches the layer off there;
`validity.mode: binary` restores P6's gate, where every non-PASS verdict
abstained, so that policy can still be scored.
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
TOR_ONION = "TOR_ONION"
DANDELION_STEM = "DANDELION_STEM"
V2_PASSIVE_TAP = "V2_PASSIVE_TAP"
#: Most severe first; `assess` reports them in this order.
REASONS = (DEGENERATE, NOT_REACHABLE, COINJOIN, TOR_ONION, DANDELION_STEM, V2_PASSIVE_TAP)

ABSTAIN, QUALIFIED, ANNOTATE = "ABSTAIN", "QUALIFIED", "ANNOTATE"
TIER = {DEGENERATE: ABSTAIN, NOT_REACHABLE: ABSTAIN,
        COINJOIN: QUALIFIED, TOR_ONION: QUALIFIED,
        DANDELION_STEM: ANNOTATE, V2_PASSIVE_TAP: ANNOTATE}

#: The columns a frame of origins carries.
COLUMNS = ["validity", "validity_tier", "validity_reasons", "validity_confidence",
           "validity_evidence"]


@dataclass(frozen=True)
class Verdict:
    reason: str = PASS                    # the most severe reason that fired
    confidence: float | None = None       # that it is present; None on PASS
    evidence: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()         # every reason that fired, in REASONS order

    @property
    def passed(self) -> bool:
        return self.reason == PASS

    @property
    def tier(self) -> str:
        return TIER.get(self.reason, PASS if self.passed else self.reason)

    def as_dict(self) -> dict:
        return {"tier": self.tier, "reason": None if self.passed else self.reason,
                "reasons": list(self.reasons), "confidence": self.confidence,
                "evidence": list(self.evidence)}

    def columns(self) -> dict:
        return {"validity": self.reason, "validity_tier": self.tier,
                "validity_reasons": list(self.reasons),
                "validity_confidence": self.confidence,
                "validity_evidence": list(self.evidence)}


VALID = Verdict(PASS, None, ("no invalidating condition detected",))

#: Not a detector: what an output stored before this layer existed carries, so
#: that it is never served without a verdict and never passed off as PASS.
NOT_ASSESSED = Verdict("NOT_ASSESSED", None, (
    "produced before the validity layer existed; rerun the pipeline to assess it",),
    ("NOT_ASSESSED",))


def enforced(cfg: dict) -> bool:
    return bool(cfg.get("validity", {}).get("enforce", True))


def tiered(cfg: dict) -> bool:
    """Qualifications are in force: the layer is on and not in P6's binary mode."""
    return enforced(cfg) and cfg.get("validity", {}).get("mode", "tiered") == "tiered"


def withholds(tier: str, cfg: dict) -> bool:
    """Whether a verdict of this tier abstains under the configured policy."""
    if not enforced(cfg):
        return False
    return tier == ABSTAIN if tiered(cfg) else tier != PASS


def answer(peer: str | None, verdict: Verdict, cfg: dict) -> dict | None:
    """What an origin answer may claim. A QUALIFIED answer is never shaped like
    an IP attribution: an onion identity has no `ip`, and a CoinJoin
    broadcaster carries an explicit `input_ownership: not attributable`."""
    if peer is None or withholds(verdict.tier, cfg):
        return None
    qualified = tiered(cfg)
    if qualified and TOR_ONION in verdict.reasons:
        out = {"kind": "onion_identity", "onion": peer,
               "actionable": "not for IP-level follow-up"}
    elif qualified and COINJOIN in verdict.reasons:
        out = {"kind": "broadcasting_peer", "ip": peer}
    else:
        return {"kind": "ip_attribution", "ip": peer}
    if COINJOIN in verdict.reasons:
        out["input_ownership"] = "not attributable: a CoinJoin's inputs have many owners"
    return out


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
        "a CoinJoin has one broadcaster and many owners: the answer names who "
        "broadcast it, never who owns its inputs"))


def tor_onion(peer: str | None) -> Verdict | None:
    if not (peer and str(peer).endswith(".onion")):
        return None
    return Verdict(TOR_ONION, 1.0, (
        f"{peer} is a Tor hidden service: the answer is that onion identity, which "
        "names no IP and supports no IP-level follow-up",))


def v2_passive_tap(capture_source: str | None, unreadable_flows) -> Verdict | None:
    """Only a packet capture is blind to BIP-324: bitcoind's own log, and a
    .btcap its collector writes, come from the node, which decrypts."""
    if not (capture_source and str(capture_source).startswith("pcap:")):
        return None
    if not unreadable_flows or pd.isna(unreadable_flows) or int(unreadable_flows) <= 0:
        return None
    n = int(unreadable_flows)
    return Verdict(V2_PASSIVE_TAP, 1.0, (
        f"this packet capture held {n} port-8333 flow{'s' if n != 1 else ''} it could not "
        "decode, consistent with BIP-324 v2 encryption: peers on those links are missing "
        "from the candidates",))


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
        "consistent with a Dandelion stem, where the first announcer may be a relay; "
        "a flag only — Bitcoin Core has no stem phase"))


# --- one origin --------------------------------------------------------------
def combine(fired: list[Verdict]) -> Verdict:
    """Every verdict that fired -> one: the most severe leads, all are listed."""
    fired = sorted(fired, key=lambda v: REASONS.index(v.reason))
    if not fired:
        return VALID
    return Verdict(fired[0].reason, fired[0].confidence,
                   tuple(line for v in fired for line in v.evidence),
                   tuple(v.reason for v in fired))


def assess(candidate_count: int, scope_out: bool = False, peer: str | None = None,
           times=(), tx: Tx | None = None, cfg: dict | None = None,
           capture_source: str | None = None, unreadable_flows=None) -> Verdict:
    cfg = cfg or config.load()
    fired = [v for v in (degenerate(candidate_count), not_reachable(scope_out),
                         coinjoin(tx, cfg), tor_onion(peer),
                         dandelion_stem(times, cfg),
                         v2_passive_tap(capture_source, unreadable_flows))
             if v is not None]
    return combine(fired)


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
    return assess(count, scope_out, peer,
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
        shape = (shape_of.loc[(capture_id, txid)]
                 if shape_of is not None and (capture_id, txid) in shape_of.index else None)
        first = group.iloc[0]
        verdict = assess(int(first["candidate_count"]), bool(first["scope_out"]), peer,
                         group["delta_vs_first_s"].to_numpy(), tx_of(txid, shape), cfg,
                         first.get("capture_source"), first.get("unreadable_flows"))
        rows.append({"capture_id": capture_id, "txid": txid, **verdict.columns()})
    return pd.DataFrame(rows, columns=key + COLUMNS)
