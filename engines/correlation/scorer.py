"""IP ↔ wallet-cluster correlation — confidence, not attribution.

⚠️  WHAT THIS MODULE PRODUCES IS A PROBABILISTIC LEAD, NEVER A CERTAIN
    ATTRIBUTION.

Every score here answers exactly one question: *how confident are we that IP X
is associated with cluster Y?* It never answers "IP X belongs to Y", and no
output of this module may be described that way — not in a report, not in the
dashboard, not in a hand-off to an investigator.

The reasons are not hedging, they are the actual state of the evidence:

  * The person who broadcast a transaction is not necessarily the wallet's
    owner. A wallet's transaction can be relayed by a service, a phone on
    someone else's network, a custodian, or a stranger given a signed
    transaction.
  * Our records are gossip observations. A node that forwarded a transaction
    looks, in the data, exactly like the node that originated it. We use
    engines/propagation to estimate the origin, but that estimate is right
    roughly 29% of the time at our default observation rate — and it cannot do
    better than 34%, because the true origin is simply absent from the observed
    hops two thirds of the time. Its confidence is folded into every score
    here, so a weak estimate cannot masquerade as strong evidence.
  * IP addresses are shared and reassigned — carrier NAT, public wifi, DHCP
    churn, a VPN exit used by thousands.
  * Addresses can be spent by more than one party (multisig, custodial
    services), so "the cluster" is not always one person either.

A high score means: keep pulling this thread. It is a reason to seek a warrant,
a subpoena to an ISP, or corroborating evidence — it is not itself evidence of
who did anything. A score of 1.0 would still be a lead.

Scoring:

    raw_confidence    = 1 - exp(-observation_count / k)   (saturating)
    asn_penalty       = 0.2 if the ASN is VPN/hosting/Tor-adjacent else 1.0
    shared_ip_penalty = 1.0 if the IP touches few clusters, decaying hyperbolically
    final_score       = raw_confidence * asn_penalty * shared_ip_penalty
"""

from __future__ import annotations

import argparse
import json
import math
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import pandas as pd

import config
from analysis.validity import ANNOTATE, COINJOIN, NOT_REACHABLE, PASS, TOR_ONION, enforced
from engines.propagation.estimators import estimate_all
from engines.rules.detectors import FeatureSet
from graph.builder import build_graph, iter_transactions, load
from ingest.geoip import is_high_risk_asn
from ingest.ip_intel import HOSTING, RESIDENTIAL, TOR_EXIT, IpIntel, load_intel

COLUMNS = ["entity_id", "ip", "ip_class", "asn", "asn_org", "geo_country", "high_risk_asn",
           "observation_count", "effective_observations", "origin_confidence",
           "distinct_entities", "raw_confidence", "asn_penalty", "shared_ip_penalty",
           "final_score", "first_seen", "last_seen", "reason", "validity",
           "validity_reasons", "validity_evidence"]

HOUR = 3600.0
DAY = 86400.0


@dataclass
class Observation:
    """One transaction's estimated origin, as evidence about a cluster."""

    entity_id: str
    ip: str
    txid: str
    timestamp: float
    asn: int | None = None
    asn_org: str | None = None
    country: str | None = None
    ip_class: str = RESIDENTIAL
    origin_confidence: float = 1.0
    validity: tuple[str, ...] = ()       # every reason the origin's verdict gave


def raw_confidence(observation_count: float, cfg: dict | None = None) -> float:
    """Saturating: the 20th sighting adds far less than the 2nd, and no amount
    of repetition ever reaches certainty.

    `observation_count` may be fractional: each observation is weighted by how
    confident engines/propagation is that this IP actually originated that
    transaction, so three shaky estimates count for less than one solid one.
    Weighting the *evidence* rather than scaling the *result* keeps the scale
    meaningful — enough good observations can still reach a high score.
    """
    k = (cfg or config.load())["engines"]["correlation"]["saturation_k"]
    return 1.0 - math.exp(-max(observation_count, 0.0) / k)


def asn_penalty(asn: int | None, cfg: dict | None = None) -> float:
    """An IP behind a VPN exit, a hosting provider or a Tor exit node is weak
    evidence of anything.

    Thousands of unrelated people share that address, the operator chose it for
    exactly that reason, and it says nothing about where the sender is or who
    they are. Treating it like a residential line — which usually maps to one
    subscriber the ISP can name — would manufacture confidence that the
    evidence does not contain. So it is multiplied down, hard, and never
    silently: the reason string always says the penalty was applied.
    """
    cfg = cfg or config.load()
    if asn is None:
        return 1.0
    return cfg["engines"]["correlation"]["high_risk_asn_factor"] if is_high_risk_asn(asn) else 1.0


def infrastructure_penalty(asn: int | None, ip_class: str, cfg: dict | None = None) -> float:
    """The ASN penalty, with the IP's classification as a fallback.

    Our records carry the ASN of the *source* of each hop, so an IP we only
    ever saw as a destination has no ASN attached. Without this fallback a Tor
    exit seen only as a destination would escape the discount entirely.
    """
    cfg = cfg or config.load()
    by_asn = asn_penalty(asn, cfg)
    if by_asn < 1.0:
        return by_asn
    if ip_class in (TOR_EXIT, HOSTING):
        return cfg["engines"]["correlation"]["high_risk_asn_factor"]
    return 1.0


def shared_ip_penalty(distinct_entities: int, cfg: dict | None = None) -> float:
    """A NAT gateway, a café's wifi or a relay node is linked to many unrelated
    clusters. Co-occurrence there is coincidence, not association, so the more
    clusters an IP touches the less any single link is worth."""
    s = (cfg or config.load())["engines"]["correlation"]["shared_ip"]
    free = s["free_entities"]
    if distinct_entities <= free:
        return 1.0
    return max(s["min_factor"], free / distinct_entities)


def asn_index(df: pd.DataFrame) -> dict[str, int]:
    """ip -> the first ASN seen for it, built once per call.

    This used to be a `df.loc[df["src_ip"] == ip]` scan inside the observation
    loop: one full pass over every relay row for every observation, which is
    quadratic in the dataset and was the second-slowest stage of the pipeline.
    The result is identical — first non-null wins, same as before.
    """
    if "asn" not in df.columns or "src_ip" not in df.columns:
        return {}
    pairs = df[["src_ip", "asn"]].dropna(subset=["asn"])
    if pairs.empty:
        return {}
    first = pairs.groupby("src_ip", sort=False)["asn"].first()
    return {str(ip): int(asn) for ip, asn in first.items()}


def collect_observations(df: pd.DataFrame, features: FeatureSet, cfg: dict | None = None,
                         origins: pd.DataFrame | None = None,
                         intel: IpIntel | None = None) -> list[Observation]:
    """Relay rows -> (cluster, IP) evidence, via estimated transaction origins.

    The broadcaster of a transaction is its *spender*, so a transaction is
    attributed to the entity behind its inputs. Two refinements over reading
    the first-seen IP directly:

      * the IP is engines/propagation's estimated origin, not whichever hop we
        happened to record first, and that estimate's own confidence is carried
        into the score — a weak estimate must not become a strong lead;
      * CoinJoins are excluded, because one participant or a coordinator
        broadcasts for everybody and tying that IP to every participant would
        invent associations that do not exist.
    """
    cfg = cfg or config.load()
    mixes = features.clustering.coinjoins
    intel = intel if intel is not None else load_intel(cfg=cfg)
    if origins is None:
        origins, _ = estimate_all(df, intel, cfg)

    inputs_by_tx = {tx.txid: tx.input_addresses for tx in iter_transactions(df)}
    asn_by_ip = asn_index(df)
    meta = {}
    for row in df.sort_values("timestamp", kind="stable").itertuples():
        meta.setdefault(str(row.txid), row)          # earliest row, for asn/country/time

    observations = []
    for est in origins.itertuples():
        txid = str(est.txid)
        if txid in mixes or not est.estimated_origin_ip:
            continue
        # A lead says "this IP broadcast for this cluster's inputs". So no lead
        # is built from an answer that may not say that: a CoinJoin's (input
        # ownership is not attributable), an onion identity (no IP), or one
        # with only relays in view. DEGENERATE is kept: one transaction offering
        # nothing to compare is exactly what aggregating many of them, each
        # weighted by its low confidence, exists for. ANNOTATE flags ride along.
        reasons = tuple(getattr(est, "validity_reasons", ()) or ())
        if enforced(cfg) and {COINJOIN, TOR_ONION, NOT_REACHABLE} & set(reasons):
            continue
        row = meta.get(txid)
        entities = {features.entity_of(a) for a in inputs_by_tx.get(txid, [])}
        ts = pd.Timestamp(row.timestamp).timestamp() if row is not None else 0.0
        ip = str(est.estimated_origin_ip)
        asn = asn_by_ip.get(ip)
        for entity_id in entities:
            observations.append(Observation(
                entity_id=entity_id, ip=ip, txid=txid, timestamp=ts, asn=asn,
                asn_org=_text(getattr(row, "asn_org", None)) if row is not None else None,
                country=_text(getattr(row, "geo_country", None)) if row is not None else None,
                ip_class=str(est.ip_class),
                # The *attribution* confidence, not the estimate's own: an
                # anonymized entry point (Tor exit, hosting) is discounted here
                # rather than being pushed down the ranking. See
                # engines.propagation.attribution_confidence_of.
                origin_confidence=float(getattr(est, "attribution_confidence",
                                                est.confidence)),
                validity=reasons))
    return observations


def _text(value) -> str | None:
    return None if value is None or pd.isna(value) else str(value)


def _span_phrase(first: float, last: float, count: int) -> str:
    if count == 1:
        return "on a single occasion"
    seconds = max(last - first, 0.0)
    if seconds >= DAY:
        days = seconds / DAY
        return f"over {days:.0f} day{'' if 0.5 <= days < 1.5 else 's'}"
    if seconds >= HOUR:
        return f"over {seconds / HOUR:.0f} hours"
    return f"within {max(seconds / 60.0, 1):.0f} minutes"


CLASS_WORDS = {"known_bitcoin_relay": "a known public Bitcoin relay",
               "tor_exit": "a Tor exit node", "hosting_vpn": "hosting/VPN infrastructure",
               "residential_or_unknown": "residential or unclassified"}


def build_reason(link: dict) -> str:
    """Plain English, stating the evidence and every discount applied to it."""
    kind = CLASS_WORDS.get(link["ip_class"], link["ip_class"])
    asn = f"ASN {link['asn']}" if link["asn"] is not None else "ASN unknown"
    if link["asn_org"]:
        asn += f" {link['asn_org']}"
    if link["geo_country"]:
        asn += f", {link['geo_country']}"
    span = _span_phrase(link["first_seen"], link["last_seen"], link["observation_count"])
    n = link["observation_count"]
    reason = (f"estimated origin {link['ip']} ({asn}, {kind}), origin confidence "
              f"{link['origin_confidence']:.2f}, {n} transaction"
              f"{'' if n == 1 else 's'} broadcast from it by this cluster {span}")
    if link["asn_penalty"] < 1.0:
        reason += (f"; confidence reduced because this address is {kind}, "
                   "shared by unrelated people")
    if link["shared_ip_penalty"] < 1.0:
        reason += (f"; confidence reduced because this IP also broadcasts for "
                   f"{link['distinct_entities'] - 1} other clusters, consistent with "
                   f"a NAT gateway, shared network or relay node")
    return reason + " — an association to investigate, not an attribution"


def score_observations(observations: list[Observation], cfg: dict | None = None) -> pd.DataFrame:
    cfg = cfg or config.load()
    pairs: dict[tuple[str, str], dict] = {}
    entities_per_ip: dict[str, set[str]] = {}

    for obs in observations:
        key = (obs.entity_id, obs.ip)
        link = pairs.setdefault(key, {
            "entity_id": obs.entity_id, "ip": obs.ip, "asn": obs.asn,
            "asn_org": obs.asn_org, "geo_country": obs.country, "txids": set(),
            "first_seen": obs.timestamp, "last_seen": obs.timestamp})
        if obs.txid not in link["txids"]:    # independent broadcasts, not rows
            link["txids"].add(obs.txid)
            link.setdefault("origin_confidences", []).append(obs.origin_confidence)
            link.setdefault("verdicts", []).append(obs.validity)
        link.setdefault("ip_class", obs.ip_class)
        link["first_seen"] = min(link["first_seen"], obs.timestamp)
        link["last_seen"] = max(link["last_seen"], obs.timestamp)
        if link["asn"] is None:
            link["asn"] = obs.asn
        entities_per_ip.setdefault(obs.ip, set()).add(obs.entity_id)

    rows = []
    for link in pairs.values():
        count = len(link["txids"])
        distinct = len(entities_per_ip[link["ip"]])
        link["observation_count"] = count
        link["distinct_entities"] = distinct
        link["high_risk_asn"] = is_high_risk_asn(link["asn"]) if link["asn"] is not None else False
        # Each observation counts only as much as we believe the origin estimate.
        confidences = link["origin_confidences"]
        link["origin_confidence"] = sum(confidences) / len(confidences)
        link["effective_observations"] = round(sum(confidences), 4)
        link["raw_confidence"] = raw_confidence(link["effective_observations"], cfg)
        link["asn_penalty"] = infrastructure_penalty(link["asn"], link["ip_class"], cfg)
        link["shared_ip_penalty"] = shared_ip_penalty(distinct, cfg)
        link["final_score"] = (link["raw_confidence"] * link["asn_penalty"]
                               * link["shared_ip_penalty"])
        link["reason"] = build_reason(link)
        flagged: dict[str, int] = {}
        for reasons in link["verdicts"]:
            for reason in reasons:
                flagged[reason] = flagged.get(reason, 0) + 1
        link["validity"] = ANNOTATE if flagged else PASS
        link["validity_evidence"] = (
            "; ".join(f"{n} of {count} contributing origin estimates flagged {reason}"
                      for reason, n in sorted(flagged.items()))
            + " — the lead rests on their repetition, not on any one"
            if flagged else f"all {count} contributing origin estimates passed validity")
        link["validity_reasons"] = sorted(flagged)
        link["first_seen"] = pd.Timestamp(link["first_seen"], unit="s", tz="UTC")
        link["last_seen"] = pd.Timestamp(link["last_seen"], unit="s", tz="UTC")
        rows.append({c: link[c] for c in COLUMNS})

    # No score floor. Links are ranked and consumed top-k per entity
    # (fusion.pipeline.attribution_leads); the old min_score was calibrated
    # against a scale that no longer exists now that each observation is
    # weighted by its origin-estimate confidence.
    df = pd.DataFrame(rows, columns=COLUMNS)
    return df.sort_values(["final_score", "entity_id"], ascending=[False, True],
                          ignore_index=True)


def correlate(df: pd.DataFrame, features: FeatureSet | None = None,
              cfg: dict | None = None, origins: pd.DataFrame | None = None,
              intel: IpIntel | None = None) -> pd.DataFrame:
    cfg = cfg or config.load()
    features = features or FeatureSet.from_graph(build_graph(df, cfg), cfg)
    return score_observations(
        collect_observations(df, features, cfg, origins, intel), cfg)


def run(input_path=None, output=None, cfg: dict | None = None, node_intel=None) -> dict:
    cfg = cfg or config.load()
    df = load(input_path, cfg)
    intel = load_intel(None, node_intel or cfg["ingest"]["input_dir"], cfg)
    links = correlate(df, cfg=cfg, intel=intel)
    output = Path(output or cfg["engines"]["correlation"]["output_path"])
    output.parent.mkdir(parents=True, exist_ok=True)
    links.to_parquet(output, index=False)
    return {"links": len(links), "entities": int(links["entity_id"].nunique()) if len(links) else 0,
            "ips": int(links["ip"].nunique()) if len(links) else 0,
            "penalised_asn": int((links["asn_penalty"] < 1).sum()) if len(links) else 0,
            "penalised_shared": int((links["shared_ip_penalty"] < 1).sum()) if len(links) else 0,
            "mean_score": round(float(links["final_score"].mean()), 4) if len(links) else 0.0,
            "output": str(output),
            "caveat": "probabilistic leads — association, never attribution"}


def main(argv=None) -> None:
    cfg = config.load()
    ap = argparse.ArgumentParser(prog="engines.correlation.scorer", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", default=cfg["ingest"]["output_path"])
    ap.add_argument("--output", default=cfg["engines"]["correlation"]["output_path"])
    ap.add_argument("--evidence", choices=["earliest_hop", "all_hops"],
                    default=cfg["engines"]["correlation"]["evidence"])
    args = ap.parse_args(argv)
    cfg = json.loads(json.dumps(cfg))
    cfg["engines"]["correlation"]["evidence"] = args.evidence
    print(json.dumps(run(args.input, args.output, cfg), indent=2))


if __name__ == "__main__":
    main()
