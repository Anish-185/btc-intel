"""Per-candidate relay features, the third grain.

    python -m features.relay --input data/capture/2026-09-24-node1 \
        --observer-ip 198.51.100.2 \
        --output data/processed/features_relay.parquet

`engineer.py` has two grains — entities and transactions — both derived from the
blockchain. This adds a third derived from the network: one row per **candidate
peer per transaction per capture**, grain `(txid, peer_ip, capture_id)`. It is
the input the supervised origination model needs and the thing no blockchain
feature can express: not "is this transaction suspicious" but "did this peer
originate it or merely forward it".

TWO CLASSES OF CAUSALITY, BECAUSE THEY ARE NOT THE SAME CONSTRAINT
A strict reading of "no feature may use information observed after the
announcement it describes" would forbid the announcement rank, the deltas
against the transaction's own distribution, and every estimator score — all of
which read the transaction's other announcements, some of which arrive later.
Those features are also the entire signal. So the constraint is applied at two
different boundaries, and every column is labelled with which one:

  strict   Uses only events strictly BEFORE this announcement's timestamp.
           Every peer-history feature is in this class, because that is where
           leakage would actually be fatal: a peer aggregate computed over the
           whole capture encodes how often this peer *will* be first, which is
           close to the label.
  window   Uses only announcements OF THIS TRANSACTION, at the moment its
           observation window closes. This is the same information
           `engines.propagation` already estimates from, and it is what an
           operator holds when they ask the question. It may not read any other
           transaction, past or future.

Both are tested by shuffling and by appending later events; neither test is a
substitute for the other. The per-column argument is in
docs/FEATURE_SCHEMA_RELAY.md.

Nothing here rebuilds what exists: trees come from
`engines.propagation.tree.build_trees`, estimator scores from
`engines.propagation.estimators`, enrichment from `ingest.geoip` and
`ingest.ip_intel`, the clock-resolution threshold from
`eval.ground_truth.preflight`, and the quarantine convention from
`ingest.pipeline`.
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import statistics
from dataclasses import asdict
from pathlib import Path

import pandas as pd

import config
from engines.propagation.estimators import ESTIMATORS, apply_class_weights
from engines.propagation.tree import build_trees
from ingest.geoip import GeoIp
from ingest.ip_intel import KNOWN_RELAY, TOR_EXIT, load_intel
from ingest.pipeline import QUARANTINE_COLUMNS

log = logging.getLogger(__name__)

#: Events that say "this peer had this transaction". `tx` counts: receiving the
#: transaction body from a peer is an announcement of possession too.
ANNOUNCEMENTS = ("inv", "tx")

#: Grain, then the feature blocks. Order is the schema doc's order.
KEY_COLUMNS = ["txid", "peer_ip", "capture_id"]

VANTAGE_COLUMNS = ["observer_ip", "observer_ips", "direction", "direction_basis",
                   "direction_confidence", "capture_source"]

WINDOW_COLUMNS = ["announce_ts", "announce_rank", "is_first", "candidate_count",
                  "delta_vs_first_s", "delta_vs_median_s", "delta_z",
                  "window_span_s", "announcements_of_txid"]

STRICT_COLUMNS = ["peer_txids_before", "peer_firsts_before", "peer_fraction_first_before",
                  "peer_announce_rate_per_min", "peer_mean_interval_s",
                  "peer_median_interval_s", "peer_stdev_interval_s",
                  "peer_first_seen_age_s"]

CONTEXT_COLUMNS = ["peer_port", "non_standard_port", "is_ipv6", "is_onion", "transport_v2",
                   "unreadable_flows",
                   "user_agent", "user_agent_class", "ip_class", "is_tor_exit",
                   "connection_age_s", "connection_age_known"]

ENRICHMENT_COLUMNS = ["geo_country", "asn", "asn_org", "high_risk_asn", "asn_source"]

ESTIMATOR_COLUMNS = [f"est_{name}_{suffix}" for name in ESTIMATORS
                     for suffix in ("score", "rank")]

FLAG_COLUMNS = ["degenerate", "scope_out", "wtxid_unresolved"]

RELAY_COLUMNS = (KEY_COLUMNS + VANTAGE_COLUMNS + WINDOW_COLUMNS + STRICT_COLUMNS
                 + CONTEXT_COLUMNS + ENRICHMENT_COLUMNS + ESTIMATOR_COLUMNS
                 + FLAG_COLUMNS)

#: Known client families, from the version handshake's subver string.
_AGENT_CLASSES = {"satoshi": "core", "bitcoin core": "core", "btcd": "btcd",
                  "bcoin": "bcoin", "libbitcoin": "libbitcoin", "bitcoinj": "bitcoinj",
                  "knots": "knots", "gocoin": "gocoin"}


class VantageError(Exception):
    """Arrival deltas are only comparable within one vantage point."""


# --- vantage -------------------------------------------------------------
def observer_of(local_ips=None, cfg: dict | None = None,
                labels: dict | None = None) -> tuple[set[str], str]:
    """The observer's own addresses, and how we came to know them.

    Read in the same order `p2p.capture_reader` reads them, because a capture
    and its features must agree about which end is us: an explicit argument,
    then the label file of a ground-truth run, then `p2p.local_ips`. There is no
    inference step here on purpose — the reader can infer the local address from
    a pcap's flows, but a debug.log never contains it, so a guess would be a
    different quantity depending on the capture format.
    """
    cfg = cfg or config.load()
    if local_ips:
        return {str(ip) for ip in local_ips}, "explicit"
    if labels and labels.get("observer_local_ips"):
        return {str(ip) for ip in labels["observer_local_ips"]}, "label_file"
    configured = (cfg.get("p2p") or {}).get("local_ips") or []
    if configured:
        return {str(ip) for ip in configured}, "config:p2p.local_ips"
    raise VantageError(
        "the observer's own address is unknown, so inbound and outbound cannot be told "
        "apart and no row could carry an observer identity. Pass --observer-ip, set "
        "p2p.local_ips in config.yaml, or supply a ground-truth label file")


def _direction_confidence(basis: str, cfg: dict) -> float:
    """How much of the `direction` column is evidence rather than assumption.

    The direction on a `RelayEvent` is *inferred*: for a pcap the reader decided
    it from which end of the flow was local, and for a debug.log from the verb
    on the line. Recording where the observer identity came from is what stops
    that inference being read as an observation — a configured address is a
    stated fact about the deployment, a label file is a stated fact about the
    run, and nothing here is a measurement of the peer's intent.
    """
    return float((cfg.get("p2p") or {}).get("direction_confidence", {}).get(basis, 1.0))


# --- small derivations ---------------------------------------------------
def user_agent_class(subver: str | None) -> str:
    if not subver:
        return "unknown"
    lowered = subver.lower()
    for needle, name in _AGENT_CLASSES.items():
        if needle in lowered:
            return name
    return "other"


def _is_ipv6(ip: str) -> bool:
    return ":" in str(ip)


def _is_onion(ip: str) -> bool:
    return str(ip).endswith(".onion")


def _interval_stats(times: list[float]) -> tuple[float, float, float]:
    """Mean, median and stdev of the gaps between consecutive announcements."""
    if len(times) < 2:
        return (float("nan"), float("nan"), float("nan"))
    gaps = [b - a for a, b in zip(times, times[1:])]
    return (statistics.fmean(gaps), statistics.median(gaps),
            statistics.stdev(gaps) if len(gaps) > 1 else 0.0)


# --- the relay-record frame the estimators already read ------------------
def relay_frame(events, observer_ip: str) -> pd.DataFrame:
    """Announcements -> the src/dst relay-record shape `build_trees` expects.

    An inbound announcement is an edge peer -> observer: that peer had the
    transaction and told us at this time. Outbound rows are our own
    announcements and are dropped — we are not a candidate origin.

    Lives here rather than in `eval/` because it is a feature-stage concern and
    `eval.ground_truth.score` imports it from here.
    """
    rows = [{"txid": e.txid, "src_ip": e.peer_ip, "dst_ip": observer_ip,
             "timestamp": pd.Timestamp(e.wall_clock_ts, unit="s", tz="UTC"), "asn": None}
            for e in events
            if e.direction == "inbound" and e.message_type in ANNOUNCEMENTS and e.peer_ip]
    return pd.DataFrame(rows, columns=["txid", "src_ip", "dst_ip", "timestamp", "asn"])


def estimator_scores(frame: pd.DataFrame, intel, cfg: dict,
                     exclude: set[str]) -> dict[str, dict[str, tuple[float, int]]]:
    """Per-candidate score and rank from each existing estimator.

    `build_trees` and the estimators themselves are imported, not reimplemented;
    the only thing added is that the observer is struck from the candidate list,
    because it cannot be the origin of its own observations.
    """
    trees = build_trees(frame)
    out: dict[str, dict[str, tuple[float, int]]] = {}
    for txid, tree in trees.items():
        per_estimator: dict[str, dict[str, tuple[float, int]]] = {}
        for name in ESTIMATORS:
            weighted, _ = apply_class_weights(ESTIMATORS[name](tree, cfg), tree, intel, cfg)
            ranked = sorted(((ip, s) for ip, s in weighted.items() if ip not in exclude),
                            key=lambda kv: (-kv[1], kv[0]))
            per_estimator[name] = {ip: (float(score), i + 1)
                                   for i, (ip, score) in enumerate(ranked)}
        out[txid] = per_estimator
    return out


# --- the matrix ----------------------------------------------------------
def compute_relay_features(events, capture_id: str, local_ips=None,
                           cfg: dict | None = None, labels: dict | None = None,
                           intel=None, geoip=None) -> tuple[pd.DataFrame, pd.DataFrame]:
    """(features, quarantine). One row per candidate peer per txid.

    Raises `PreflightError` if the capture's timestamps cannot support timing
    features, and `VantageError` if the observer is unknown.
    """
    cfg = cfg or config.load()
    # The clock check is eval's, threshold included — a second copy of the
    # number is how two different thresholds end up in circulation.
    from eval.ground_truth.preflight import PreflightError, subsecond_share

    observers, basis = observer_of(local_ips, cfg, labels)
    share = subsecond_share(events)
    minimum = cfg["eval"]["ground_truth"]["min_subsecond_share"]
    if share < minimum:
        raise PreflightError([
            f"timestamps lack sub-second resolution: only {share:.1%} of events carry a "
            f"fractional second, below the required {minimum:.0%}. Every timing feature "
            "here would be a tie; set logtimemicros=1 on the observer, or capture with "
            "tcpdump"])

    announcements = [e for e in events
                     if e.message_type in ANNOUNCEMENTS or e.message_type == "inv_wtx"]
    quarantine = _quarantine(announcements, capture_id)
    usable = [e for e in announcements
              if e.message_type in ANNOUNCEMENTS and e.peer_ip
              and e.peer_ip not in observers and e.direction == "inbound"
              and e.wall_clock_ts is not None]

    intel = intel if intel is not None else load_intel(None, None, cfg)
    geoip = geoip if geoip is not None else GeoIp(cfg)
    observer_ip = sorted(observers)[0]
    frame = relay_frame(usable, observer_ip)
    estimators = estimator_scores(frame, intel, cfg, observers) if len(frame) else {}

    strict = _strict_history(usable)
    agents = _agents(events)
    relay_classes = set(cfg["engines"]["propagation"]["low_confidence_classes"])

    rows = []
    for txid, group in _by_txid(usable).items():
        # One entry per candidate: a peer that announced the same txid twice
        # (inv then tx) is one candidate, timed from its earliest announcement.
        earliest: dict[str, object] = {}
        for event in group:
            if (event.peer_ip not in earliest
                    or event.wall_clock_ts < earliest[event.peer_ip].wall_clock_ts):
                earliest[event.peer_ip] = event
        window = _window_stats([e.wall_clock_ts for e in earliest.values()])
        candidate_count = len(earliest)
        classes = {ip: intel.classify(ip, None).ip_class for ip in earliest}
        scope_out = candidate_count == 0 or all(c in relay_classes for c in classes.values())
        for peer_ip, event in earliest.items():
            rows.append(_row(txid, peer_ip, event, capture_id, observer_ip, observers,
                             basis, window, candidate_count, strict, agents,
                             classes[peer_ip], estimators.get(txid, {}), geoip, cfg,
                             scope_out, len(group)))

    features = pd.DataFrame(rows, columns=RELAY_COLUMNS)
    return (features.sort_values(KEY_COLUMNS, ignore_index=True), quarantine)


def _by_txid(events) -> dict[str, list]:
    out: dict[str, list] = {}
    for event in sorted(events, key=lambda e: (e.wall_clock_ts, e.peer_ip or "")):
        out.setdefault(event.txid, []).append(event)
    return out


def _quarantine(events, capture_id: str) -> pd.DataFrame:
    """Rows still identified by a wtxid, in `ingest`'s quarantine shape.

    Never merged into the matrix: a wtxid and a txid are different identifiers
    for the same transaction, and grouping them would split one transaction's
    announcements across two grains — or worse, pool two transactions under one.
    """
    rows = [{"source_file": f"{capture_id}:{event.capture_source}", "row": i,
             "reason": "unresolved wtxid — no tx message and no label file to resolve it",
             "raw": json.dumps(asdict(event), default=str)}
            for i, event in enumerate(events) if event.message_type == "inv_wtx"]
    return pd.DataFrame(rows, columns=QUARANTINE_COLUMNS)


def _window_stats(times: list[float]) -> dict:
    """This transaction's own announcement distribution, and nothing else."""
    ordered = sorted(times)
    if not ordered:
        return {"first": float("nan"), "median": float("nan"), "mean": float("nan"),
                "stdev": float("nan"), "span": float("nan"), "order": []}
    deltas = [t - ordered[0] for t in ordered]
    return {
        "first": ordered[0],
        "median": statistics.median(ordered),
        "mean": statistics.fmean(deltas),
        "stdev": statistics.stdev(deltas) if len(deltas) > 1 else 0.0,
        "span": ordered[-1] - ordered[0],
        "order": ordered,
    }


def _strict_history(events) -> dict[tuple[str, str], dict]:
    """Peer-history features, keyed by (txid, peer_ip), computed causally.

    Streamed in timestamp order; each announcement's features are recorded
    *before* the peer's state is updated with it, so no row can see its own
    announcement or any later one. This is the class of feature where leakage
    would be fatal — a peer aggregate over the whole capture encodes how often
    this peer will be first, which is most of the way to the label.
    """
    ordered = sorted(events, key=lambda e: (e.wall_clock_ts, e.txid, e.peer_ip or ""))
    seen_txids: set[str] = set()
    peers: dict[str, dict] = {}
    out: dict[tuple[str, str], dict] = {}
    for event in ordered:
        peer = peers.setdefault(event.peer_ip, {"txids": set(), "firsts": 0,
                                                "times": [], "first_seen": None})
        key = (event.txid, event.peer_ip)
        if key not in out:                     # the peer's first announcement of this txid
            count = len(peer["txids"])
            mean, median, stdev = _interval_stats(peer["times"])
            elapsed = ((event.wall_clock_ts - peer["first_seen"]) / 60.0
                       if peer["first_seen"] is not None else 0.0)
            out[key] = {
                "peer_txids_before": count,
                "peer_firsts_before": peer["firsts"],
                "peer_fraction_first_before": (peer["firsts"] / count) if count else float("nan"),
                "peer_announce_rate_per_min": (count / elapsed) if elapsed > 0 else float("nan"),
                "peer_mean_interval_s": mean,
                "peer_median_interval_s": median,
                "peer_stdev_interval_s": stdev,
                "peer_first_seen_age_s": (event.wall_clock_ts - peer["first_seen"]
                                          if peer["first_seen"] is not None else 0.0),
            }
        if event.txid not in seen_txids:        # this announcement opened the txid
            seen_txids.add(event.txid)
            peer["firsts"] += 1
        if event.txid not in peer["txids"]:
            peer["txids"].add(event.txid)
            peer["times"].append(event.wall_clock_ts)
        if peer["first_seen"] is None:
            peer["first_seen"] = event.wall_clock_ts
    return out


def _agents(events) -> dict[str, str]:
    """The user agent each peer was seen with, from the version handshake.

    Capture-wide rather than causal: a peer's client version does not change
    within a capture, so learning it from a handshake logged after an
    announcement reveals nothing about that announcement's timing or origin.
    Stated here because it is the one deliberate exception.
    """
    return {e.peer_ip: e.user_agent for e in events if e.peer_ip and e.user_agent}


def _row(txid, peer_ip, event, capture_id, observer_ip, observers, basis, window,
         candidate_count, strict, agents, ip_class, estimators, geoip, cfg,
         scope_out, announcements_of_txid) -> dict:
    delta_first = event.wall_clock_ts - window["first"]
    stdev = window["stdev"]
    history = strict.get((txid, peer_ip), {})
    enrichment = geoip.lookup(peer_ip)
    row = {
        "txid": txid, "peer_ip": peer_ip, "capture_id": capture_id,
        "observer_ip": observer_ip, "observer_ips": ",".join(sorted(observers)),
        "direction": event.direction, "direction_basis": basis,
        "direction_confidence": _direction_confidence(basis, cfg),
        "capture_source": event.capture_source,
        "announce_ts": event.wall_clock_ts,
        "announce_rank": window["order"].index(event.wall_clock_ts) + 1,
        "is_first": event.wall_clock_ts == window["first"],
        "candidate_count": candidate_count,
        "delta_vs_first_s": delta_first,
        "delta_vs_median_s": event.wall_clock_ts - window["median"],
        "delta_z": (delta_first - window["mean"]) / stdev if stdev else 0.0,
        "window_span_s": window["span"],
        "announcements_of_txid": announcements_of_txid,
        "peer_port": event.peer_port,
        "non_standard_port": (event.peer_port is not None
                              and event.peer_port != int((cfg.get("p2p") or {}).get("port", 8333))),
        "is_ipv6": _is_ipv6(peer_ip), "is_onion": _is_onion(peer_ip),
        "transport_v2": getattr(event, "transport", None) == "v2",
        "unreadable_flows": getattr(event, "unreadable_flows", None),
        "user_agent": agents.get(peer_ip), "user_agent_class": user_agent_class(agents.get(peer_ip)),
        "ip_class": ip_class, "is_tor_exit": ip_class == TOR_EXIT,
        # The reader's event stream carries announcements, not connection
        # lifecycle, so the true connection time is not derivable from it.
        # `peer_first_seen_age_s` is the causal lower bound we do have.
        "connection_age_s": float("nan"), "connection_age_known": False,
        "degenerate": candidate_count <= 1,
        "scope_out": bool(scope_out),
        "wtxid_unresolved": False,
    }
    row.update({key: history.get(key, float("nan")) for key in STRICT_COLUMNS})
    row.update({key: enrichment.get(key) for key in ENRICHMENT_COLUMNS})
    for name in ESTIMATORS:
        score, rank = estimators.get(name, {}).get(peer_ip, (float("nan"), None))
        row[f"est_{name}_score"] = score
        row[f"est_{name}_rank"] = rank
    return row


# --- CLI -----------------------------------------------------------------
def build(inputs, local_ips=None, cfg: dict | None = None,
          allow_cross_vantage: bool = False) -> tuple[pd.DataFrame, pd.DataFrame, dict]:
    """One or more captures -> one matrix.

    Several captures are only pooled with `allow_cross_vantage`, because an
    arrival delta is measured against one observer's clock and one observer's
    peer set. Pooling two vantage points silently would make `delta_vs_first_s`
    mean two different things in one column.
    """
    from p2p.capture_reader import read_capture, read_directory

    cfg = cfg or config.load()
    frames, quarantines, summaries = [], [], []
    observers: set[str] = set()
    for source in ([inputs] if isinstance(inputs, (str, Path)) else list(inputs)):
        path = Path(source)
        labels = _labels_beside(path)
        events = (read_directory(path, cfg=cfg) if path.is_dir()
                  else read_capture(path, cfg=cfg))
        if labels:
            from eval.ground_truth.broadcast import resolve_from_labels
            resolve_from_labels(events, labels)
        features, quarantine = compute_relay_features(
            events, path.name, local_ips, cfg, labels)
        if not features.empty:
            observers |= set(features["observer_ips"].unique())
        frames.append(features)
        quarantines.append(quarantine)
        summaries.append({"capture_id": path.name, "rows": len(features),
                          "quarantined": len(quarantine)})
    if len(observers) > 1 and not allow_cross_vantage:
        raise VantageError(
            f"these captures have different observers ({sorted(observers)}) and arrival "
            "deltas are only comparable within one vantage point. Pass "
            "--allow-cross-vantage if you intend to pool them anyway")
    features = (pd.concat(frames, ignore_index=True) if frames
                else pd.DataFrame(columns=RELAY_COLUMNS))
    quarantine = (pd.concat(quarantines, ignore_index=True) if quarantines
                  else pd.DataFrame(columns=QUARANTINE_COLUMNS))
    return features, quarantine, {"captures": summaries,
                                  "observers": sorted(observers),
                                  "cross_vantage": len(observers) > 1}


def _labels_beside(path: Path) -> dict | None:
    """A ground-truth bundle carries its label file; use it to resolve wtxids."""
    if not path.is_dir():
        return None
    found = sorted(path.glob("*.labels.json"))
    if not found:
        return None
    from eval.ground_truth.broadcast import load_labels
    return load_labels(found[0])


def summarise(features: pd.DataFrame, quarantine: pd.DataFrame) -> dict:
    """What the report quotes: size, and the three proportions that matter."""
    n = len(features)
    return {
        "rows": n,
        "features": len(RELAY_COLUMNS) - len(KEY_COLUMNS),
        "transactions": int(features["txid"].nunique()) if n else 0,
        "peers": int(features["peer_ip"].nunique()) if n else 0,
        "degenerate_share": round(float(features["degenerate"].mean()), 4) if n else None,
        "scope_out_share": round(float(features["scope_out"].mean()), 4) if n else None,
        "quarantined_rows": len(quarantine),
        "quarantined_share": round(len(quarantine) / (n + len(quarantine)), 4)
        if n + len(quarantine) else None,
    }


def run(inputs, output=None, quarantine_output=None, local_ips=None,
        cfg: dict | None = None, allow_cross_vantage: bool = False) -> dict:
    cfg = cfg or config.load()
    features, quarantine, meta = build(inputs, local_ips, cfg, allow_cross_vantage)
    output = Path(output or cfg["features"]["relay_path"])
    quarantine_output = Path(quarantine_output or cfg["features"]["relay_quarantine_path"])
    for path, frame in ((output, features), (quarantine_output, quarantine)):
        path.parent.mkdir(parents=True, exist_ok=True)
        frame.to_parquet(path, index=False)
    return {**summarise(features, quarantine), **meta,
            "output": str(output), "quarantine": str(quarantine_output)}


def main(argv=None) -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    cfg = config.load()
    ap = argparse.ArgumentParser(prog="features.relay", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", action="append", required=True,
                    help="a capture file or bundle directory; repeat for several")
    ap.add_argument("--observer-ip", action="append", dest="local_ips", default=None)
    ap.add_argument("--output", default=cfg["features"]["relay_path"])
    ap.add_argument("--quarantine", default=cfg["features"]["relay_quarantine_path"])
    ap.add_argument("--allow-cross-vantage", action="store_true",
                    help="pool captures taken from different observers (deltas stop "
                         "being comparable — say so wherever the numbers are quoted)")
    args = ap.parse_args(argv)
    print(json.dumps(run(args.input, args.output, args.quarantine, args.local_ips,
                         cfg, args.allow_cross_vantage), indent=2))


if __name__ == "__main__":
    main()
