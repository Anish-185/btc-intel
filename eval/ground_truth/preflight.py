"""Refuse to score a capture that cannot support a conclusion.

Every check here guards a number that would otherwise be published as if it
meant something. A capture whose timestamps are whole seconds cannot rank
announcements that arrive milliseconds apart; a capture whose `inv_wtx` rows are
mostly unresolved is measuring a different population than it claims; a capture
whose local address is unknown has inbound and outbound the wrong way round,
which inverts the entire signal; and a capture with no recorded topology
condition cannot be filed under either row of the result table, which is the one
distinction this whole exercise exists to draw.

All four **fail**, loudly, with every failure listed at once rather than the
first one found — an operator fixing a capture should learn everything wrong
with it in one run. Nothing here warns and continues: a warning in a log is not
a number an investigator will not quote.
"""

from __future__ import annotations

import config
from .broadcast import CONDITIONS


class PreflightError(Exception):
    """A capture that must not be scored. Carries every reason."""

    def __init__(self, failures: list[str]):
        self.failures = failures
        super().__init__("this capture cannot be scored:\n  - " + "\n  - ".join(failures))


def subsecond_share(events: list) -> float:
    """Fraction of events whose timestamp has a non-zero fractional part.

    Not "does any timestamp have decimals": a capture written without
    `logtimemicros=1` has whole-second timestamps throughout, and one stray
    fractional value must not pass the file. A real microsecond capture lands
    above 0.9 here; a whole-second one lands at 0.
    """
    stamped = [e.wall_clock_ts for e in events if e.wall_clock_ts is not None]
    if not stamped:
        return 0.0
    return sum(1 for t in stamped if t % 1 != 0) / len(stamped)


def check(events: list, labels: dict, local_ips, cfg: dict | None = None,
          resolution: dict | None = None) -> dict:
    """Raise `PreflightError` unless this capture can be scored.

    `resolution` is the result of `broadcast.resolve_from_labels`, i.e. the
    wtxid rows are counted *after* the label file has had its say — the question
    is what remains unresolvable, not what the capture could not do alone.
    """
    cfg = cfg or config.load()
    g = cfg["eval"]["ground_truth"]
    failures: list[str] = []

    if not events:
        raise PreflightError(["the capture holds no relay events at all"])

    share = subsecond_share(events)
    if share < g["min_subsecond_share"]:
        failures.append(
            f"timestamps lack sub-second resolution: only {share:.1%} of events carry a "
            f"fractional second, below the required {g['min_subsecond_share']:.0%}. "
            "Set logtimemicros=1 on the observer (or capture with tcpdump) and re-run — "
            "announcements arrive milliseconds apart and whole seconds cannot order them")

    unresolved = (resolution or {}).get("unresolved_after")
    if unresolved is None:
        unresolved = sum(1 for e in events if e.message_type == "inv_wtx")
    share_unresolved = unresolved / len(events)
    if share_unresolved > g["max_unresolved_wtxid_share"]:
        failures.append(
            f"{unresolved} of {len(events)} events ({share_unresolved:.1%}) are still "
            f"identified by wtxid after label-side resolution, above the permitted "
            f"{g['max_unresolved_wtxid_share']:.0%}. Those rows name a different "
            "identifier than the txid rows and cannot be grouped with them; capture the "
            "tx messages (pcap) or broadcast from a node whose labels cover them")

    given = {str(ip) for ip in (local_ips or []) if ip}
    if not given:
        failures.append(
            "local_ips is unset, so inbound and outbound cannot be told apart — and "
            "getting that backwards inverts every observation. Set eval.ground_truth."
            "observer_local_ips, config p2p.local_ips, or record observer_local_ips in "
            "the label file")
    else:
        leaked = sorted({e.peer_ip for e in events if e.peer_ip in given})
        if leaked:
            failures.append(
                f"local_ips is ambiguous: {leaked} appears as a peer address as well as "
                "a local one. One of the two is wrong, and the observer must not be a "
                "candidate for its own observations")

    condition = labels.get("topology_condition")
    if condition not in CONDITIONS:
        failures.append(
            f"topology_condition is {condition!r}, not one of {CONDITIONS}. The adjacent "
            "and non-adjacent results are different measurements and are never pooled, "
            "so an unlabelled capture cannot be filed under either")
    else:
        topology = labels.get("topology_check") or {}
        if topology.get("as_claimed") is False:
            failures.append(
                f"the label file's own topology check failed: {topology.get('detail')}. "
                "A run claiming non_adjacent while peered with the observer measures the "
                "trivial upper bound and would be reported as the real result")

    labelled = {t["txid"] for t in labels.get("transactions", [])}
    seen = {e.txid for e in events}
    overlap = labelled & seen
    if not overlap:
        failures.append(
            f"none of the {len(labelled)} labelled transactions appear in the capture's "
            f"{len(seen)} observed transactions — the capture and the label file are "
            "from different runs")

    if failures:
        raise PreflightError(failures)
    return {"events": len(events), "subsecond_share": round(share, 4),
            "unresolved_wtxid": int(unresolved),
            "unresolved_share": round(share_unresolved, 4),
            "local_ips": sorted(given), "topology_condition": condition,
            "labelled_transactions": len(labelled),
            "labelled_transactions_observed": len(overlap),
            "topology_verified": bool((labels.get("topology_check") or {}).get("as_claimed"))}
