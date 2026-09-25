"""Fit, calibrate, abstain and explain: did this peer originate this transaction?

One row in, one probability out, per `(txid, peer_ip, capture_id)` of the
`features.relay` matrix. The three estimators are already columns of that
matrix; the model fuses them with the timing and peer-history columns rather
than replacing them.

THE MODEL IS ADDITIVE, AND THAT IS A CHOICE
Gradient boosting (scikit-learn's HistGradientBoostingClassifier) with every
feature in its own interaction group, so each tree splits on one feature and
the fitted margin is a sum of one shape function per feature. That buys the
thing the brief asked for: SHAP values that are exact, computed by the SHAP
implementation this repo already has (`fusion.explain.shap_contributions`,
exact for any model additive in its inputs) rather than a second one. It costs
interactions — "early *and* not a relay" has to be carried by the per-
transaction features below rather than learned. If that ceiling ever matters,
the upgrade is interaction groups plus TreeSHAP, which is the path
`fusion/explain.py`'s own docstring names.

CANDIDATES COMPETE WITHIN A TRANSACTION
Two places. Features: every timing and estimator column also enters relative
to the rest of its transaction (share of rank, lead over the next announcer,
gap to the transaction's best estimator score). Output: the per-row
probabilities of one transaction are scaled so they sum to at most one —
`p_i / max(1, sum_j p_j)` — which lets candidates compete without forcing a
winner on a transaction whose origin was never observed, which is most of
them. A softmax would force one.

ABSTENTION IS BY CONSTRUCTION FIRST, BY COST SECOND
A `degenerate` or `scope_out` row is never scored: its probability is NaN and
its transaction's confidence is 0, below every cutoff the rule can choose. The
remaining transactions abstain by `engines.propagation`'s own discipline — the
cutoff on confidence, chosen by `eval.origin.choose_cutoff_for` under the
pre-registered `cost_weights` — fitted on the calibration captures, never on a
test capture.
"""

from __future__ import annotations

import math
import pickle
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.isotonic import IsotonicRegression

import config
from analysis import validity
from engines.propagation.estimators import ESTIMATORS
from eval import origin as origin_eval
from fusion.explain import shap_contributions
from ingest.ip_intel import HOSTING, KNOWN_RELAY

#: Matrix columns read as-is. Identity columns (addresses, ASN numbers,
#: timestamps) are left out on purpose: the model may learn what a peer did,
#: never who it is. Columns constant in the simulation — user agent, real
#: connection age — are left out because there is nothing in the corpus to
#: learn them from, and a weight fitted to a constant is a guess.
RAW = ["announce_rank", "is_first", "candidate_count", "delta_vs_first_s",
       "delta_vs_median_s", "delta_z", "window_span_s", "announcements_of_txid",
       "peer_txids_before", "peer_firsts_before", "peer_fraction_first_before",
       "peer_announce_rate_per_min", "peer_mean_interval_s", "peer_median_interval_s",
       "peer_stdev_interval_s", "peer_first_seen_age_s",
       "non_standard_port", "is_ipv6", "is_onion", "is_tor_exit", "high_risk_asn",
       *[f"est_{n}_{s}" for n in ESTIMATORS for s in ("score", "rank")]]

#: Derived within each transaction — the per-txid normalisation.
RELATIVE = ["ip_known_relay", "ip_hosting", "rank_share", "lead_s", "history_gap",
            *[f"est_{n}_gap" for n in ESTIMATORS]]

FEATURES = RAW + RELATIVE

#: Features that say the same thing to an investigator, summed into one phrase.
#: Summing is exact: SHAP values of an additive model add.
GROUPS = {
    "median": ["delta_vs_median_s", "delta_z"],
    "order": ["announce_rank", "is_first", "rank_share", "delta_vs_first_s"],
    "lead": ["lead_s"],
    "history": ["peer_firsts_before", "peer_fraction_first_before", "history_gap"],
    "volume": ["peer_txids_before", "peer_announce_rate_per_min", "peer_mean_interval_s",
               "peer_median_interval_s", "peer_stdev_interval_s", "peer_first_seen_age_s"],
    "class": ["ip_known_relay", "ip_hosting", "is_tor_exit", "high_risk_asn",
              "non_standard_port", "is_ipv6", "is_onion"],
    "crowd": ["candidate_count", "window_span_s", "announcements_of_txid"],
    **{f"est_{n}": [f"est_{n}_score", f"est_{n}_rank", f"est_{n}_gap"] for n in ESTIMATORS},
}

KEY = ["capture_id", "txid"]


def design(matrix: pd.DataFrame) -> pd.DataFrame:
    """The matrix -> the model's inputs, relative columns included."""
    X = matrix[RAW].astype(float)
    tx = [matrix["capture_id"], matrix["txid"]]
    X["ip_known_relay"] = (matrix["ip_class"] == KNOWN_RELAY).astype(float)
    X["ip_hosting"] = (matrix["ip_class"] == HOSTING).astype(float)
    X["rank_share"] = X["announce_rank"] / X["candidate_count"]
    # Lead over the next announcer: for the first peer, its margin over the
    # runner-up — the quantity a timing argument actually rests on.
    order = matrix.assign(_t=X["delta_vs_first_s"]).sort_values(KEY + ["_t", "peer_ip"])
    following = order.groupby(KEY)["_t"].shift(-1)
    X["lead_s"] = (following - order["_t"]).reindex(matrix.index)
    history = X["peer_fraction_first_before"]
    X["history_gap"] = history - history.groupby(tx).transform("max")
    for name in ESTIMATORS:
        score = X[f"est_{name}_score"]
        X[f"est_{name}_gap"] = score - score.groupby(tx).transform("max")
    return X[FEATURES]


def abstains_by_construction(matrix: pd.DataFrame) -> pd.Series:
    """Rows no probability may be emitted for: nothing to rank, or no plausible sender."""
    return matrix["degenerate"].astype(bool) | matrix["scope_out"].astype(bool)


class _Terms:
    """The fitted model as `fusion.explain` sees a stacker: a sum of named
    terms, each with weight one. The terms are the model's own shape
    functions, so `shap_contributions` over them is exact SHAP for the model."""

    def __init__(self, signals: list[str]):
        self.signals = signals

    def coefficients(self) -> dict[str, float]:
        return {s: 1.0 for s in self.signals}


@dataclass
class OriginationModel:
    gbm: HistGradientBoostingClassifier
    calibrator: IsotonicRegression | None = None
    cutoff: float | None = None
    cutoff_table: pd.DataFrame | None = None
    reference: pd.Series | None = None          # one background row, for term probes
    baseline_terms: pd.Series | None = None     # E[term] over the background
    meta: dict = field(default_factory=dict)

    # --- fitting ----------------------------------------------------------
    @classmethod
    def fit(cls, train: pd.DataFrame, cfg: dict | None = None,
            background_size: int = 500) -> "OriginationModel":
        """Learn from in-scope rows only. Degenerate and scope_out rows are the
        ones the model must abstain on, not the ones it learns from."""
        cfg = cfg or config.load()
        g = cfg["origination"]["gbm"]
        keep = ~abstains_by_construction(train)
        X, y = design(train)[keep], train.loc[keep, "originated"].astype(int)
        gbm = HistGradientBoostingClassifier(
            max_iter=g["max_iter"], learning_rate=g["learning_rate"],
            max_leaf_nodes=g["max_leaf_nodes"], min_samples_leaf=g["min_samples_leaf"],
            l2_regularization=g["l2_regularization"], early_stopping=False,
            interaction_cst=[[i] for i in range(len(FEATURES))], random_state=0)
        gbm.fit(X, y)
        background = X.sample(min(background_size, len(X)), random_state=0)
        model = cls(gbm, reference=background.iloc[0],
                    meta={"rows": int(len(X)), "positives": int(y.sum()),
                          "features": list(FEATURES)})
        model.baseline_terms = model.terms(background).mean()
        return model

    def calibrate(self, calibration: pd.DataFrame, cfg: dict | None = None,
                  shapes: pd.DataFrame | None = None) -> "OriginationModel":
        """Isotonic on the calibration captures, then the abstention cutoff on
        the same captures by the pre-registered rule. Never on a test capture."""
        cfg = cfg or config.load()
        scored = self.score(calibration, calibrated=False)
        fit_on = scored["p_raw"].notna()
        self.calibrator = IsotonicRegression(y_min=0.0, y_max=1.0, out_of_bounds="clip")
        self.calibrator.fit(scored.loc[fit_on, "p_raw"],
                            calibration.loc[fit_on, "originated"].astype(float))
        truth = calibration[calibration["originated"]].set_index(KEY)["peer_ip"]
        frame = self.decide(calibration, truth, cfg, shapes)
        self.cutoff, self.cutoff_table = origin_eval.choose_cutoff_for(frame, cfg)
        return self

    # --- scoring ----------------------------------------------------------
    def margin(self, X: pd.DataFrame) -> np.ndarray:
        return self.gbm.decision_function(X[FEATURES])

    def score(self, matrix: pd.DataFrame, calibrated: bool = True) -> pd.DataFrame:
        """Per-row probability, normalised within each transaction.

        `p_raw` is the model's, after the within-transaction scaling;
        `p_calibrated` is the isotonic map of it. Both are NaN on a row that
        abstains by construction.
        """
        out = matrix[KEY + ["peer_ip"]].copy()
        out["abstain_reason"] = np.where(matrix["degenerate"].astype(bool), "degenerate",
                                         np.where(matrix["scope_out"].astype(bool),
                                                  "scope_out", ""))
        live = out["abstain_reason"] == ""
        p = pd.Series(np.nan, index=matrix.index)
        if live.any():
            p[live] = 1.0 / (1.0 + np.exp(-self.margin(design(matrix[live]))))
            total = p[live].groupby([out.loc[live, "capture_id"],
                                     out.loc[live, "txid"]]).transform("sum")
            p[live] = p[live] / np.maximum(1.0, total)
        out["p_raw"] = p
        if calibrated and self.calibrator is not None:
            out["p_calibrated"] = np.where(live, self.calibrator.predict(p.fillna(0.0)), np.nan)
        return out

    def decide(self, matrix: pd.DataFrame, truth: pd.Series | None = None,
               cfg: dict | None = None, shapes: pd.DataFrame | None = None) -> pd.DataFrame:
        """One row per transaction, in the shape `eval.ground_truth.score.summarise`
        and `eval.origin.cost_score` read — so the outcome machinery is theirs.

        `confidence` is the calibrated probability of the top candidate, and 0
        on a transaction that abstains by construction.
        """
        cfg = cfg or config.load()
        runner_ups = cfg["engines"]["propagation"]["runner_ups"]
        scored = self.score(matrix, calibrated=self.calibrator is not None)
        column = "p_calibrated" if "p_calibrated" in scored else "p_raw"
        scored["ip_class"] = matrix["ip_class"]
        scored["_p"] = scored[column].fillna(-1.0)
        scored = scored.sort_values(KEY + ["_p", "peer_ip"], ascending=[True, True, False, True])
        rows = []
        for (capture_id, txid), group in scored.groupby(KEY, sort=False):
            best = group.iloc[0]
            answer = truth.get((capture_id, txid)) if truth is not None else None
            by_construction = bool(best["abstain_reason"])
            rows.append({
                "capture_id": capture_id, "txid": txid,
                "estimated_origin_ip": best["peer_ip"], "ip_class": best["ip_class"],
                "confidence": 0.0 if by_construction else float(best[column]),
                "abstain_reason": best["abstain_reason"] or None,
                "n_candidates": len(group),
                "correct": best["peer_ip"] == answer,
                "top3": answer in list(group["peer_ip"][:1 + runner_ups]),
                "origin_observed": answer in set(group["peer_ip"]),
            })
        decided = pd.DataFrame(rows)
        if decided.empty:
            return decided
        # The verdict is about the candidate actually named. `flagged_at` reads
        # it, so a failed check abstains through the same rule as the cutoff.
        verdicts = validity.assess_matrix(matrix, decided, shapes, cfg)
        return decided.merge(verdicts, on=KEY, how="left").assign(
            calibration_basis=self.calibration_basis)

    @property
    def calibration_basis(self) -> str:
        if self.calibrator is None:
            return "uncalibrated: within-transaction normalised model output"
        return (f"isotonic regression fitted on the calibration captures of corpus "
                f"{self.meta.get('corpus', '?')}, never on a test capture")

    def predict(self, matrix: pd.DataFrame, cfg: dict | None = None,
                shapes: pd.DataFrame | None = None) -> pd.DataFrame:
        """Serving output: per row, the calibrated probability, its calibration
        basis, the transaction's validity verdict and whether it is answered.
        No labels are read."""
        scored = self.score(matrix)
        decided = self.decide(matrix, None, cfg, shapes).set_index(KEY)
        answered = ~origin_eval.flagged_at(decided, cfg or config.load(), self.cutoff)
        key = pd.MultiIndex.from_frame(scored[KEY])
        scored["answered_tx"] = answered.reindex(key).to_numpy()
        for column in ("calibration_basis", *validity.COLUMNS):
            scored[column] = decided[column].reindex(key).to_numpy()
        scored["rank_in_tx"] = (scored.groupby(KEY)["p_calibrated"]
                                .rank(ascending=False, method="first"))
        return scored

    # --- explanation ------------------------------------------------------
    def terms(self, X: pd.DataFrame) -> pd.DataFrame:
        """Each feature's shape-function value, relative to the reference row.

        For an additive margin f(x) = c + sum_j g_j(x_j), setting feature j of
        the reference row to x_j moves f by exactly g_j(x_j) - g_j(ref_j). One
        probe per feature per row, no sampling; `shap_contributions` then
        subtracts the background mean, which is exact SHAP.
        """
        base = self.margin(self.reference.to_frame().T)[0]
        out = {}
        for feature in FEATURES:
            probe = pd.DataFrame([self.reference] * len(X), columns=FEATURES)
            probe[feature] = X[feature].to_numpy()
            out[feature] = self.margin(probe) - base
        return pd.DataFrame(out, index=X.index)

    def shap(self, X: pd.DataFrame) -> pd.DataFrame:
        """Exact SHAP values of the margin, via fusion's implementation."""
        terms = self.terms(X)
        stacker = _Terms(FEATURES)
        return pd.DataFrame([shap_contributions(stacker, row, self.baseline_terms)
                             for _, row in terms.iterrows()], index=X.index)

    def explain(self, matrix: pd.DataFrame, top: int | None = None,
                cfg: dict | None = None) -> pd.DataFrame:
        """One investigator-language sentence per row, with its SHAP values."""
        cfg = cfg or config.load()
        top = top or cfg["origination"]["explain_top_features"]
        scored = self.score(matrix)
        live = scored["abstain_reason"] == ""
        values = self.shap(design(matrix[live])) if live.any() else pd.DataFrame()
        sentences = []
        for index, row in matrix.iterrows():
            reason = scored.at[index, "abstain_reason"]
            if reason:
                sentences.append(_abstain_sentence(row, reason))
                continue
            grouped = {g: float(values.loc[index, cols].sum()) for g, cols in GROUPS.items()}
            sentences.append(_sentence(row, scored.at[index, "p_calibrated"], grouped, top))
        out = scored[KEY + ["peer_ip", "p_calibrated", "abstain_reason"]].copy()
        out["explanation"] = sentences
        return out

    # --- persistence ------------------------------------------------------
    def save(self, path: Path | str) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(pickle.dumps(self))
        return path

    @staticmethod
    def load(path: Path | str) -> "OriginationModel":
        # Only ever a file this repo wrote: pickle executes what it loads.
        return pickle.loads(Path(path).read_bytes())


# --- sentences ------------------------------------------------------------
def _ms(seconds: float) -> str:
    return f"{abs(seconds) * 1000:.0f} ms"


def _phrase(group: str, row: pd.Series) -> str | None:
    """One group's evidence, with this row's own numbers in it."""
    n = int(row["candidate_count"])
    if group == "median":
        d = float(row["delta_vs_median_s"])
        return f"announced {_ms(d)} {'before' if d < 0 else 'after'} the median"
    if group == "order":
        rank = int(row["announce_rank"])
        return (f"was the first of {n} peers to announce it" if rank == 1
                else f"was {rank} of {n} to announce it")
    if group == "lead":
        lead = row.get("lead_s")
        return ("was the last to announce it" if lead is None or pd.isna(lead)
                else f"announced {_ms(lead)} ahead of the next peer")
    if group == "history":
        seen, first = row["peer_txids_before"], row["peer_firsts_before"]
        if pd.isna(seen) or not seen:
            return "had announced nothing earlier in this capture"
        return (f"was first in {int(first)} of {int(seen)} earlier "
                f"observation{'s' if seen != 1 else ''}")
    if group == "volume":
        seen = row["peer_txids_before"]
        if pd.isna(seen) or not seen:
            return None                    # "history" already says so
        return (f"had announced {int(seen)} earlier "
                f"transaction{'s' if seen != 1 else ''} in this capture")
    if group == "class":
        return {KNOWN_RELAY: "is a listed public relay",
                HOSTING: "sits in a hosting network",
                "tor_exit": "is a Tor exit"}.get(row["ip_class"],
                                                 "is not listed as relay, Tor or hosting")
    if group == "crowd":
        return f"{n} peers announced this transaction"
    if group.startswith("est_"):
        name = group[4:]
        rank = row[f"est_{name}_rank"]
        return None if pd.isna(rank) else f"{name.replace('_', ' ')} ranked it {int(rank)} of {n}"
    return None


def _sentence(row: pd.Series, p: float, grouped: dict[str, float], top: int) -> str:
    ranked = sorted(grouped.items(), key=lambda kv: -abs(kv[1]))
    supporting, opposing = [], []
    for group, value in ranked:
        phrase = _phrase(group, row)
        if phrase is None or not value:
            continue
        (supporting if value > 0 else opposing).append(phrase)
        if len(supporting) + len(opposing) >= top:
            break
    parts = [f"peer {row['peer_ip']} ({p:.0%} calibrated)"]
    if supporting:
        parts.append(" and ".join(supporting))
    if opposing:
        parts.append("against: " + "; ".join(opposing))
    if not supporting and not opposing:
        parts.append("nothing in its features moves the score")
    return parts[0] + " " + "; ".join(parts[1:])


def _abstain_sentence(row: pd.Series, reason: str) -> str:
    if reason == "degenerate":
        return (f"peer {row['peer_ip']}: no answer — it was the only peer to announce "
                "this transaction, so there is nothing to compare it against")
    return (f"peer {row['peer_ip']}: no answer — every peer that announced this "
            "transaction is a listed relay, and a relay is never a plausible sender")


def ece(p: pd.Series, y: pd.Series, bins: int) -> float:
    """Expected calibration error, equal-width bins."""
    frame = pd.DataFrame({"p": p.to_numpy(float), "y": y.to_numpy(float)}).dropna()
    if frame.empty:
        return math.nan
    bucket = np.minimum((frame["p"] * bins).astype(int), bins - 1)
    grouped = frame.groupby(bucket)
    gap = (grouped["p"].mean() - grouped["y"].mean()).abs()
    return round(float((gap * grouped.size() / len(frame)).sum()), 4)

