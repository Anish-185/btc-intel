"""How the alert queue is ordered when the composite score cannot decide.

The fused risk score separates alerts from non-alerts and then runs out of
resolution: `eval/results.md` §4 measures five distinct values across 197
alerts, with every one of the top fifty printing 1.000. A queue sorted on that
alone is in an arbitrary order at the top — whatever order the rows happened to
come out of a dict — and "ranked alert list" is a deliverable, so the order has
to come from somewhere.

It comes from here: a fixed, documented sequence of tiebreakers, all of them
signals the pipeline already computes. **Nothing below changes a score.** The
composite still decides, and still shows on screen; these only order what it has
declared equal.

The order, and why each one is where it is:

1. **`risk_score`**, descending. The composite. Everything else is a tiebreak
   within a value it has already assigned.
2. **`rule_typologies`**, descending — how many *distinct* rule detectors fired
   on this entity. Two independent detectors agreeing is a stronger case than
   one firing twice, and unlike every other signal here it is a count of
   separate evidence rather than a restatement of one thing.
3. **`taint_hops`**, ascending — distance from a watchlist entity along the
   money. One hop from a known-bad address is more urgent than four. Entities
   with no taint path sort last within their group rather than first, which is
   what `NO_TAINT` is for: absence of a path is not proximity zero.
4. **`lead_confidence`**, descending — the strongest attribution lead. Of two
   equally risky entities, the one an ISP request could act on is the one to
   open first.
5. **`tx_count`**, descending — the entity's transaction volume. A bigger
   operation, all else equal.
6. **`entity_id`**, ascending — never a judgement, only a guarantee. With this
   last, the order is a total order: the same dataset produces the same queue on
   every run, on every machine, whatever order the rows arrived in.

Steps 2-5 are all "more evidence first"; step 6 exists so that two genuinely
identical alerts still land in a stable place instead of wherever pandas or a
dict iteration put them.
"""

from __future__ import annotations

import json

import pandas as pd

#: Sorts after every real hop count. An entity with no path to a watchlist seed
#: is not "zero hops away" — it is not connected at all, and must not outrank
#: something that is.
NO_TAINT = 10**6

#: (column, ascending). The published order; `docs`/`eval` quote this.
SORT_KEY: tuple[tuple[str, bool], ...] = (
    ("risk_score", False),
    ("rule_typologies", False),
    ("taint_hops", True),
    ("lead_confidence", False),
    ("tx_count", False),
    ("entity_id", True),
)

#: The tiebreak columns, in order, without the composite or the id backstop.
TIEBREAKERS = ("rule_typologies", "taint_hops", "lead_confidence", "tx_count")


def taint_hops(taint_path) -> int:
    """Hops from the watchlist seed at the head of the path to this entity.

    The path includes both ends, so a direct hit is length 1 and zero hops.
    """
    path = list(taint_path or [])
    return len(path) - 1 if path else NO_TAINT


def lead_confidence(leads) -> float:
    """The strongest attribution lead's score, or 0.0 when there is none."""
    if isinstance(leads, str):
        try:
            leads = json.loads(leads)
        except (TypeError, ValueError):
            return 0.0
    return round(max((float(lead.get("confidence") or 0.0) for lead in leads or []),
                     default=0.0), 6)


def with_sort_columns(alerts: pd.DataFrame) -> pd.DataFrame:
    """Add the tiebreak columns, deriving any that are not already there."""
    out = alerts.copy()
    if "rule_typologies" not in out:
        out["rule_typologies"] = [len(set(p or [])) for p in out.get("pattern_types", [])]
    if "taint_hops" not in out:
        out["taint_hops"] = [taint_hops(p) for p in out.get("taint_path", [])]
    if "lead_confidence" not in out:
        out["lead_confidence"] = [lead_confidence(le) for le in out.get("leads", [])]
    if "tx_count" not in out:
        out["tx_count"] = 0
    return out


def sort(alerts: pd.DataFrame) -> pd.DataFrame:
    """The queue, ordered. Deterministic for a given set of alerts."""
    if alerts.empty:
        return alerts
    out = with_sort_columns(alerts)
    columns = [c for c, _ in SORT_KEY if c in out]
    ascending = [asc for c, asc in SORT_KEY if c in out]
    # `mergesort` is the stable one in pandas; with entity_id last the sort is
    # already total, so stability only matters if a caller drops that column.
    return out.sort_values(columns, ascending=ascending, kind="mergesort",
                           ignore_index=True)


def sort_key(row) -> list:
    """One alert's key, in the published order, as JSON-safe values.

    Exposed on the alert record so the console, the PDF and anything else
    reading the API order identically without re-deriving the rule — and so a
    reader can see *why* one row sits above another that shows the same score.
    """
    get = row.get if hasattr(row, "get") else (lambda k, d=None: getattr(row, k, d))

    def value(name, default):
        """`x or default` is wrong here: zero hops from a watchlist seed is the
        strongest possible taint, and `0 or NO_TAINT` would turn the best case
        into the worst. Only a genuinely missing or null value takes the
        default."""
        found = get(name, None)
        return default if found is None or pd.isna(found) else found

    # Not rounded. The key has to be exactly what the sort compared, or it
    # stops reproducing the queue: rounding 0.9999996 to 1.0 invents a tie with
    # the rows that really are at 1.0, and a consumer re-sorting on the key
    # would produce a different order from the screen.
    return [
        float(value("risk_score", 0.0)),
        int(value("rule_typologies", 0)),
        int(value("taint_hops", NO_TAINT)),
        float(value("lead_confidence", 0.0)),
        int(value("tx_count", 0)),
        str(value("entity_id", "")),
    ]
