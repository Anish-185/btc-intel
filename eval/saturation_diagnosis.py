"""Where the composite loses its resolution.

Section 4 measures that it does: a handful of distinct values across hundreds of
alerts. This asks *where*. There are only two places it can happen, and the fix
is different for each:

  * **The sigmoid.** The stacker is a logistic regression, so the score is
    `1 / (1 + exp(-z))` over a linear `z`. Past about z = 7 that function is
    flat to three decimals — 0.9991, 0.9995, 0.9998 — so inputs that differ
    perfectly well in log-odds arrive at the same displayed score. If this is
    the cause, the information still exists in `z` and a calibration change
    recovers it without touching a model.
  * **The inputs.** If the entities genuinely have identical signal vectors —
    the same rule score, the same taint, the same everything — then no
    transformation of `z` can separate them, because there is nothing to
    separate. That is a detector problem, not a presentation one.

The distinguishing measurement is the last one here: how many alerts share an
identical input vector. Alerts with different inputs and the same score are the
sigmoid's doing; alerts with the same inputs were never distinguishable.

Reports only. Nothing in `fusion/` is changed by this module.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from fusion.stacker import SIGNALS

#: Where the logistic curve stops resolving at the three decimals the console
#: prints: sigmoid(7.6) rounds to 1.000, and everything above it does too.
FLAT_LOGIT = 7.6


def logits(signals: pd.DataFrame, stacker) -> pd.Series:
    """The linear score before the sigmoid.

    Recomputed from the coefficients rather than asked of sklearn, so it works
    for the config-weights fallback too — and so the arithmetic is visible here
    rather than behind `predict_proba`.
    """
    coefficients = stacker.coefficients()
    intercept = float(getattr(getattr(stacker, "model", None), "intercept_", [0.0])[0]) \
        if getattr(stacker, "fitted", False) else 0.0
    values = signals[list(SIGNALS)].astype(float).fillna(0.0)
    z = pd.Series(intercept, index=values.index, dtype=float)
    for signal in SIGNALS:
        z = z + values[signal] * float(coefficients.get(signal, 0.0))
    return z


def evaluate(bundle: dict, stacker, cfg: dict) -> dict:
    """Input distributions, the logit distribution, and identical-input counts."""
    signals = bundle["signals"]
    scored = pd.Series(stacker.score(signals), index=signals.index)
    threshold = cfg["fusion"]["alert_threshold"]
    alerts = signals[scored >= threshold].copy()
    if alerts.empty:
        return {"alerts": 0}
    alerts["risk_score"] = scored[scored >= threshold]
    alerts["logit"] = logits(alerts, stacker)

    vectors = alerts[list(SIGNALS)].round(6)
    groups = vectors.groupby(list(SIGNALS), dropna=False).size()
    displayed = alerts["risk_score"].round(3)

    # The crux. Among alerts that print the same score, how many distinct input
    # vectors are there beyond the first? Those are the ones the sigmoid
    # flattened — different evidence, same number on screen.
    distinguishable = sum(
        group[list(SIGNALS)].round(6).drop_duplicates().shape[0] - 1
        for _, group in alerts.groupby(displayed) if len(group) > 1)

    return {
        "alerts": int(len(alerts)),
        "threshold": threshold,
        "distinct_displayed_scores": int(displayed.nunique()),
        "distinct_input_vectors": int(len(groups)),
        "largest_identical_input_group": int(groups.max()),
        "alerts_sharing_an_input_vector": int(groups[groups > 1].sum()),
        "logit_min": round(float(alerts["logit"].min()), 3),
        "logit_max": round(float(alerts["logit"].max()), 3),
        "logit_spread": round(float(alerts["logit"].max() - alerts["logit"].min()), 3),
        "logit_distinct": int(alerts["logit"].round(6).nunique()),
        "above_flat_logit": int((alerts["logit"] >= FLAT_LOGIT).sum()),
        "flat_logit": FLAT_LOGIT,
        # The verdict, in one number: distinct input vectors that the display
        # collapses onto a shared score.
        "distinguishable_but_collapsed": int(distinguishable),
        "inputs": input_distribution(alerts),
        "logit_deciles": logit_deciles(alerts["logit"]),
        "identical_groups": identical_groups(alerts, groups),
    }


def input_distribution(alerts: pd.DataFrame) -> pd.DataFrame:
    """Each input signal among the alerts: is it already maxed before fusion?"""
    rows = []
    for signal in SIGNALS:
        values = alerts[signal].astype(float)
        rows.append({
            "signal": signal,
            "min": round(float(values.min()), 4),
            "median": round(float(values.median()), 4),
            "max": round(float(values.max()), 4),
            "distinct": int(values.round(6).nunique()),
            "at max": int((values >= values.max() - 1e-9).sum()),
            "zero": int((values <= 1e-12).sum()),
        })
    return pd.DataFrame(rows)


def logit_deciles(z: pd.Series) -> pd.DataFrame:
    """The linear score's spread, and what the sigmoid does with each cut."""
    qs = [i / 10 for i in range(11)]
    values = [float(z.quantile(q, interpolation="nearest")) for q in qs]
    return pd.DataFrame({
        "quantile": [f"{int(q * 100)}%" for q in qs],
        "logit": [round(v, 3) for v in values],
        "sigmoid": [round(float(1 / (1 + np.exp(-v))), 6) for v in values],
        "displayed": [f"{float(1 / (1 + np.exp(-v))):.3f}" for v in values],
    })


def identical_groups(alerts: pd.DataFrame, groups: pd.Series) -> pd.DataFrame:
    """The biggest clumps of genuinely identical input vectors."""
    top = groups[groups > 1].sort_values(ascending=False).head(6)
    rows = []
    for key, count in top.items():
        key = key if isinstance(key, tuple) else (key,)
        row = {"alerts": int(count)}
        row.update({s: round(float(v), 4) for s, v in zip(SIGNALS, key)})
        rows.append(row)
    return pd.DataFrame(rows)
