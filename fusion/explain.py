"""Why an entity was flagged, in numbers and in English.

Two layers:

  shap_contributions  which of the five signals moved this score, and by how
                      much. The stacker is a logistic regression, so it is
                      additive in log-odds and each signal's SHAP value is
                      exactly coefficient x (value - mean) — no approximation
                      and no sampling. If the stacker is ever swapped for a
                      tree ensemble, replace this with shap.TreeExplainer.

  reason              a sentence assembled from the signals that actually
                      fired, with this entity's real numbers in it. Templates
                      supply the grammar; every figure comes from the data.

Evidence is carried alongside: the specific txids, wallets and IPs the sentence
refers to, so nothing in the reason is unverifiable.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pandas as pd

import config

from .stacker import SIGNALS, Stacker


@dataclass
class Explanation:
    entity_id: str
    score: float
    reason: str
    evidence: list[str] = field(default_factory=list)
    contributions: dict[str, float] = field(default_factory=dict)
    top_signal: str = ""


def shap_contributions(stacker: Stacker, row: pd.Series, baseline: pd.Series) -> dict[str, float]:
    """Exact SHAP values for an additive (logistic) model: coef x (x - E[x])."""
    coefs = stacker.coefficients()
    return {s: round(coefs.get(s, 0.0) * (float(row.get(s, 0.0) or 0.0)
                                          - float(baseline.get(s, 0.0) or 0.0)), 6)
            for s in stacker.signals}


def _fan_phrase(row: pd.Series) -> str | None:
    if float(row.get("fan_in_ratio", 0) or 0) >= 0.75 and int(row.get("counterparties_in", 0) or 0) >= 5:
        return (f"high fan-in ratio ({row['fan_in_ratio']:.2f}) from "
                f"{int(row['counterparties_in'])} distinct counterparties")
    if float(row.get("fan_out_ratio", 0) or 0) >= 0.75 and int(row.get("counterparties_out", 0) or 0) >= 5:
        return (f"high fan-out ratio ({row['fan_out_ratio']:.2f}) across "
                f"{int(row['counterparties_out'])} distinct counterparties")
    return None


def _velocity_phrase(row: pd.Series) -> str | None:
    velocity = float(row.get("velocity", 0) or 0)
    if velocity >= 20:
        return f"{velocity:.0f} transactions per day over {float(row.get('lifetime_days', 0) or 0):.1f} days"
    if bool(row.get("dormant_then_active", False)):
        return (f"dormant for {float(row.get('max_dormant_gap_days', 0) or 0):.0f} days "
                f"then {int(row.get('max_burst_transactions', 0) or 0)} transactions in a burst")
    return None


def _round_phrase(row: pd.Series) -> str | None:
    ratio = float(row.get("round_amount_ratio", 0) or 0)
    return f"{ratio:.0%} of its amounts are round figures" if ratio >= 0.5 else None


def build_reason(row: pd.Series, contributions: dict[str, float],
                 rule_reasons: list[str], correlation_reason: str | None,
                 taint_path: list[str] | None, cfg: dict | None = None) -> str:
    """One sentence, assembled from whatever actually fired."""
    parts: list[str] = []
    if rule_reasons:
        parts.extend(rule_reasons[:2])
    for phrase in (_fan_phrase(row), _velocity_phrase(row), _round_phrase(row)):
        if phrase:
            parts.append(phrase)
    if correlation_reason:
        parts.append(correlation_reason)
    if taint_path and len(taint_path) > 1:
        parts.append(f"{len(taint_path) - 1}-hop taint inheritance from flagged entity "
                     f"{taint_path[0]} (taint {float(row.get('taint_score', 0) or 0):.2f})")
    if float(row.get("anomaly_score", 0) or 0) >= 0.7:
        parts.append(f"feature profile is an outlier among all entities "
                     f"(anomaly {float(row['anomaly_score']):.2f})")
    if float(row.get("gnn_score", 0) or 0) >= 0.7:
        parts.append(f"graph model scores this transaction pattern {float(row['gnn_score']):.2f} "
                     "against synthetic training labels")
    if not parts:
        strongest = max(contributions, key=contributions.get) if contributions else "signals"
        parts.append(f"composite of weak signals, strongest being {strongest.replace('_', ' ')}")

    if bool(row.get("suspicious_merge", False)):
        parts.append("NOTE: this cluster is above the collapse-guard size limit and may "
                     "merge unrelated wallets — verify before acting")
    return "Flagged due to " + "; ".join(parts) + f" (composite score: {float(row['risk_score']):.2f})"


def explain_entity(row: pd.Series, stacker: Stacker, baseline: pd.Series,
                   rule_reasons: list[str], evidence: list[str],
                   correlation_reason: str | None, taint_path: list[str] | None,
                   cfg: dict | None = None) -> Explanation:
    contributions = shap_contributions(stacker, row, baseline)
    top = max(contributions, key=contributions.get) if contributions else ""
    reason = build_reason(row, contributions, rule_reasons, correlation_reason, taint_path, cfg)
    return Explanation(str(row["entity_id"]), float(row["risk_score"]), reason,
                       list(dict.fromkeys(evidence)), contributions, top)
