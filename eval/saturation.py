"""Does the ranked alert queue actually rank?

`docs/demo_script.md` has long said every alert scores 1.000. If that is true
the queue is not ranked — it is a set with a number printed on it — and "a
ranked, explainable alert list" is a literal deliverable of the problem
statement, not a nice-to-have. So it gets measured rather than asserted.

Three questions, because they fail differently:

  * **How are the scores spread?** Deciles over the alerts that fired. A flat
    distribution is a working ranking; a spike at one value is not.
  * **How many sit at exactly 1.000?** The specific claim in the demo script.
  * **How many distinct values are in the top 50?** This is the one an analyst
    feels. Fifty alerts sharing three scores cannot be worked in order, however
    well spread the tail below them is.

Nothing here changes a threshold or a model. It reports what the fitted stacker
produces on the canonical sets.
"""

from __future__ import annotations

import pandas as pd

#: What counts as "the same score" to a reader. The queue prints three decimals,
#: so two alerts that differ in the fourth are indistinguishable on screen and
#: are counted as one value here.
DISPLAYED = 3


def evaluate(signals: pd.DataFrame, stacker, cfg: dict, top: int = 50) -> dict:
    """The spread of composite risk among alerts, at the configured threshold."""
    scored = pd.Series(stacker.score(signals), index=signals.index).round(6)
    threshold = cfg["fusion"]["alert_threshold"]
    alerts = scored[scored >= threshold].sort_values(ascending=False)
    if alerts.empty:
        return {"alerts": 0, "threshold": threshold}

    shown = alerts.round(DISPLAYED)
    head = shown.head(top)
    return {
        "alerts": int(len(alerts)),
        "threshold": threshold,
        "min": round(float(alerts.min()), 4),
        "max": round(float(alerts.max()), 4),
        "spread": round(float(alerts.max() - alerts.min()), 4),
        "at_exactly_one": int((alerts >= 0.9999995).sum()),
        "distinct_values": int(shown.nunique()),
        "distinct_in_top": int(head.nunique()),
        "top_n": int(len(head)),
        "most_common_value": float(shown.mode().iloc[0]),
        "share_at_most_common": round(float((shown == shown.mode().iloc[0]).mean()), 3),
        "deciles": deciles(alerts),
        "top_values": top_values(shown, top),
    }


def deciles(alerts: pd.Series) -> pd.DataFrame:
    """Ten cut points. If they are all the same number, there is no ranking.

    `nearest` rather than the default linear interpolation: a table claiming to
    show the distribution of real scores must not contain values that no alert
    has. Interpolating between 0.996 and 1.000 invents a 0.998 and makes the
    spread look finer than it is.
    """
    qs = [i / 10 for i in range(11)]
    return pd.DataFrame({
        "quantile": [f"{int(q * 100)}%" for q in qs],
        "risk score": [round(float(alerts.quantile(q, interpolation="nearest")), 4)
                       for q in qs],
    })


def top_values(shown: pd.Series, top: int) -> pd.DataFrame:
    """The distinct values in the head of the queue, and how many alerts share
    each. This is what an analyst sees when they sort by risk and start work."""
    head = shown.head(top)
    counts = head.value_counts().sort_index(ascending=False)
    return pd.DataFrame({
        "risk score": [f"{v:.3f}" for v in counts.index],
        "alerts sharing it": counts.values,
    })
