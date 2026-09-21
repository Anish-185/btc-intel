"""Combine five engine signals into one calibrated risk score.

Logistic regression, on purpose. A gradient-boosted ensemble would score a
little better and explain a lot worse; here the coefficients themselves are
part of the deliverable — an investigator (or a court) can be shown that the
composite is a weighted sum of five named signals, each with a sign and a
magnitude. Interpretability outranks the last few points of AUC.

⚠️  TWO THINGS TO KNOW BEFORE QUOTING ANY AUC FROM THIS MODULE.

1. TAINT IS CIRCULAR HERE. Taint is seeded from high-confidence rules alerts,
   and our labels mark exactly the clusters those rules fire on. Measured on
   generated data, taint_score alone scores AUC 0.999 — it is not predicting
   the label, it is a copy of it. The stack WITHOUT taint scores 0.85, and that
   is the number worth reporting. In production, where seeds come from an
   analyst's own list rather than from our rules, the loop is broken and taint
   becomes a real signal; on our data it is not evidence of anything. Every
   fitted model therefore carries an `ablation` block showing each signal alone
   and the stack without it — read it before believing the headline.

2. TRAINED ON OUR SYNTHETIC GROUND TRUTH.

   The labels come from generator/, so the fitted weights encode how *our*
   simulator builds ransomware collectors and layering chains. In production
   this stacker must be refitted on NTRO's own synthetic corpus — ideally on
   labelled real cases if any exist — before its output ranks real leads. Until
   then the fallback below (fixed weights from config's risk_weights) is the
   honest default for unlabelled data, and the engines' own explanations, not
   this number, are what an investigator should read first.

   Note also that on our data two signals come out *inverted*: anomaly scores
   0.16 alone and correlation 0.38, both below chance. That is a real property
   of the synthetic population — exchanges are the biggest outliers, and our
   illicit actors use fresh wallets with few broadcasts each — not a bug in
   those engines. A fitted stacker will happily learn a negative weight for
   them; whether that generalises to real data is exactly what is unproven.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score

import config

SIGNALS = ["rule_score", "anomaly_score", "gnn_score", "correlation_score", "taint_score"]


@dataclass
class Stacker:
    """A fitted composite scorer, or a config-weighted fallback when unfitted."""

    model: LogisticRegression | None = None
    signals: list[str] = field(default_factory=lambda: list(SIGNALS))
    metrics: dict = field(default_factory=dict)
    fallback_weights: dict[str, float] = field(default_factory=dict)

    @property
    def fitted(self) -> bool:
        return self.model is not None

    def coefficients(self) -> dict[str, float]:
        if not self.fitted:
            return dict(self.fallback_weights)
        return dict(zip(self.signals, (float(c) for c in self.model.coef_[0])))

    def score(self, X: pd.DataFrame) -> np.ndarray:
        values = X[self.signals].astype(float).fillna(0.0)
        if self.fitted:
            return self.model.predict_proba(values)[:, 1]
        weights = np.array([self.fallback_weights.get(s, 0.0) for s in self.signals])
        total = weights.sum() or 1.0
        return (values.to_numpy() @ weights) / total

    def contributions(self, row: pd.Series) -> dict[str, float]:
        """Per-signal contribution to this row's score: coefficient x value.

        For a logistic regression this *is* the SHAP value up to the model's
        baseline — the model is additive in log-odds, so there is nothing to
        approximate. See explain.shap_contributions.
        """
        coefs = self.coefficients()
        return {s: coefs.get(s, 0.0) * float(row.get(s, 0.0) or 0.0) for s in self.signals}


def default_weights(cfg: dict | None = None) -> dict[str, float]:
    """config.yaml's risk_weights, used when there are no labels to fit on."""
    cfg = cfg or config.load()
    weights = dict(cfg["risk_weights"])
    return {"rule_score": weights.get("rules", 0.35),
            "anomaly_score": weights.get("anomaly", 0.25),
            "gnn_score": weights.get("gnn", 0.25),
            "correlation_score": weights.get("correlation", 0.15),
            "taint_score": weights.get("taint", 0.25)}


def chronological_split(signals: pd.DataFrame, cfg: dict | None = None):
    """Hold out the latest entities, never a random sample."""
    cfg = cfg or config.load()
    fraction = cfg["fusion"]["stacker"]["test_fraction"]
    order = (signals["first_seen"].rank(method="first")
             if "first_seen" in signals.columns else pd.Series(range(len(signals))))
    cut = order.quantile(1 - fraction)
    return order <= cut, order > cut


def ablation(signals: pd.DataFrame, labels: pd.Series, stacker_signals: list[str],
             cfg: dict | None = None) -> dict:
    """AUC of each signal alone, and of the stack without it.

    This exists because a headline AUC can be produced by one circular feature.
    Taint in particular is seeded from the rules engine, which fires on the same
    structures the labels describe — so a stack scoring 1.0 may be measuring
    nothing but that loop. The per-signal column shows where the skill is.
    """
    cfg = cfg or config.load()
    y = labels.astype(int).to_numpy()
    if len(set(y)) < 2:
        return {}
    X = signals[stacker_signals].astype(float).fillna(0.0)
    out: dict[str, dict] = {}
    for signal in stacker_signals:
        column = X[signal].to_numpy()
        alone = round(float(roc_auc_score(y, column)), 4) if column.std() else None
        rest = [s for s in stacker_signals if s != signal]
        without = None
        if rest and len(set(y)) > 1:
            model = LogisticRegression(max_iter=cfg["fusion"]["stacker"]["max_iter"],
                                       class_weight="balanced",
                                       random_state=cfg["fusion"]["stacker"]["seed"])
            try:
                model.fit(X[rest], y)
                without = round(float(roc_auc_score(y, model.predict_proba(X[rest])[:, 1])), 4)
            except ValueError:
                without = None
        out[signal] = {"alone": alone, "stack_without_it": without}
    return out


def train(signals: pd.DataFrame, labels: pd.Series, cfg: dict | None = None) -> Stacker:
    """Fit on the earlier entities, report AUC on the later ones."""
    cfg = cfg or config.load()
    s = cfg["fusion"]["stacker"]
    stacker = Stacker(signals=list(s["signals"]), fallback_weights=default_weights(cfg))

    y = labels.astype(int).to_numpy()
    if len(set(y)) < 2:
        stacker.metrics = {"fitted": False,
                           "reason": "only one class present — using config weights"}
        return stacker

    X = signals[stacker.signals].astype(float).fillna(0.0)
    train_mask, test_mask = chronological_split(signals, cfg)
    if len(set(y[train_mask])) < 2 or not test_mask.any():
        train_mask = pd.Series(True, index=signals.index)
        test_mask = train_mask

    model = LogisticRegression(max_iter=s["max_iter"], class_weight="balanced",
                               random_state=s["seed"])
    model.fit(X[train_mask], y[train_mask])
    stacker.model = model

    probs = model.predict_proba(X[test_mask])[:, 1]
    held_out = y[test_mask]
    stacker.metrics = {
        "fitted": True,
        "auc": round(float(roc_auc_score(held_out, probs)), 4) if len(set(held_out)) > 1 else None,
        "train_rows": int(train_mask.sum()), "test_rows": int(test_mask.sum()),
        "positives": int(y.sum()),
        "coefficients": {k: round(v, 4) for k, v in stacker.coefficients().items()},
        "ablation": ablation(signals, labels, stacker.signals, cfg),
        "warning": "fitted on synthetic labels — refit on NTRO data before production use",
    }
    return stacker


def save(stacker: Stacker, path) -> Path:
    import joblib
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": stacker.model, "signals": stacker.signals,
                 "metrics": stacker.metrics, "fallback": stacker.fallback_weights}, path)
    return path


def load(path) -> Stacker:
    import joblib
    blob = joblib.load(path)
    return Stacker(blob["model"], blob["signals"], blob["metrics"], blob["fallback"])
