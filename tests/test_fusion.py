"""Taint decay, stacker calibration, and the explanation contract.

The AUC is printed, with and without taint — see fusion/stacker.py on why the
number with taint is circular on our data.
"""

from __future__ import annotations

import json

import networkx as nx
import pandas as pd
import pytest

import config
from fusion.explain import build_reason, explain_entity, shap_contributions
from fusion.pipeline import collect_signals, build_alerts, labels_for
from fusion.pipeline import run as fusion_run
from fusion.stacker import SIGNALS, Stacker, ablation, default_weights, train
from fusion.taint import Taint, compute_taint, propagate, seeds_from_rules

CFG = config.load()
TAINT = CFG["fusion"]["taint"]


def chain(n: int) -> nx.DiGraph:
    """seed -> e1 -> e2 -> ... so hop distance is unambiguous."""
    g = nx.DiGraph()
    nodes = ["seed"] + [f"e{i}" for i in range(1, n)]
    g.add_edges_from(zip(nodes, nodes[1:]))
    return g


# --- taint ----------------------------------------------------------------
def test_taint_halves_at_every_hop():
    taints = propagate(chain(5), {"seed": 1.0}, CFG)
    decay = TAINT["decay_per_hop"]
    for hop, entity in enumerate(["seed", "e1", "e2", "e3"]):
        assert taints[entity].score == pytest.approx(decay ** hop)
        assert taints[entity].hops == hop


def test_taint_respects_the_max_hop_cap():
    taints = propagate(chain(12), {"seed": 1.0}, CFG)
    assert max(t.hops for t in taints.values()) <= TAINT["max_hops"]
    assert f"e{TAINT['max_hops']}" in taints
    assert f"e{TAINT['max_hops'] + 1}" not in taints, "taint escaped the hop cap"


def test_taint_records_the_path_back_to_its_seed():
    taints = propagate(chain(5), {"seed": 1.0}, CFG)
    assert taints["e3"].path == ["seed", "e1", "e2", "e3"]
    assert taints["e3"].seed == "seed"


def test_the_strongest_chain_wins_when_two_seeds_reach_one_entity():
    g = nx.DiGraph([("strong", "target"), ("weak", "mid"), ("mid", "target")])
    taints = propagate(g, {"strong": 0.8, "weak": 1.0}, CFG)
    assert taints["target"].path[0] == "strong"          # 0.8*0.5=0.4 beats 1.0*0.25
    assert taints["target"].score == pytest.approx(0.4)


def test_taint_below_the_floor_is_dropped():
    tight = json.loads(json.dumps(CFG))
    tight["fusion"]["taint"]["min_taint"] = 0.3
    taints = propagate(chain(6), {"seed": 1.0}, tight)
    assert all(t.score >= 0.3 for t in taints.values())


def test_taint_does_not_loop_through_cycles():
    g = nx.DiGraph([("seed", "a"), ("a", "b"), ("b", "seed")])
    taints = propagate(g, {"seed": 1.0}, CFG)
    assert taints["seed"].score == 1.0 and len(taints) == 3


def test_taint_follows_the_money_not_the_reverse():
    g = nx.DiGraph([("payer", "seed"), ("seed", "payee")])
    taints = propagate(g, {"seed": 1.0}, CFG)
    assert "payee" in taints
    assert "payer" not in taints, "taint flowed backwards to whoever paid the seed"


def test_both_direction_mode_is_configurable():
    both = json.loads(json.dumps(CFG))
    both["fusion"]["taint"]["follow"] = "both"
    g = nx.DiGraph([("payer", "seed"), ("seed", "payee")])
    assert "payer" in propagate(g, {"seed": 1.0}, both)


def test_seeds_come_from_confident_rule_alerts_only():
    alerts = pd.DataFrame({"entity_id": ["a", "b"], "score": [0.9, 0.4],
                           "rule_name": ["r", "r"], "reason": ["x", "y"],
                           "evidence": [[], []]})
    seeds = seeds_from_rules(alerts, CFG)
    assert set(seeds) == {"a"}                          # 0.4 is below seed_rule_score
    assert seeds_from_rules(pd.DataFrame(), CFG) == {}


def test_compute_taint_returns_a_frame_with_paths():
    alerts = pd.DataFrame({"entity_id": ["seed"], "score": [1.0], "rule_name": ["r"],
                           "reason": ["x"], "evidence": [[]]})
    df = compute_taint(chain(4), alerts, cfg=CFG)
    assert list(df.columns) == ["entity_id", "taint_score", "taint_path", "taint_hops",
                                "taint_seed"]
    assert df["taint_score"].is_monotonic_decreasing


# --- stacker --------------------------------------------------------------
def signal_frame(n=200, separable=True) -> tuple[pd.DataFrame, pd.Series]:
    rows, labels = [], []
    for i in range(n):
        bad = i % 4 == 0
        rows.append({"entity_id": f"c{i}", "first_seen": i,
                     "rule_score": 0.8 if (bad and separable) else 0.1,
                     "anomaly_score": 0.6 if (bad and separable) else 0.2,
                     "gnn_score": 0.0, "correlation_score": 0.3, "taint_score": 0.0})
        labels.append(int(bad))
    return pd.DataFrame(rows), pd.Series(labels)


def test_stacker_learns_a_separable_signal():
    X, y = signal_frame()
    stacker = train(X, y, CFG)
    assert stacker.fitted and stacker.metrics["auc"] >= 0.9
    assert stacker.coefficients()["rule_score"] > 0


def test_stacker_falls_back_to_config_weights_without_labels():
    X, _ = signal_frame()
    stacker = train(X, pd.Series([0] * len(X)), CFG)
    assert not stacker.fitted
    assert "one class" in stacker.metrics["reason"]
    scores = stacker.score(X)
    assert ((scores >= 0) & (scores <= 1)).all()
    assert stacker.coefficients() == default_weights(CFG)


def test_stacker_scores_are_probabilities():
    X, y = signal_frame()
    scores = train(X, y, CFG).score(X)
    assert ((scores >= 0) & (scores <= 1)).all()


def test_split_is_chronological_not_random():
    X, y = signal_frame(n=100)
    stacker = train(X, y, CFG)
    assert stacker.metrics["test_rows"] == pytest.approx(
        len(X) * CFG["fusion"]["stacker"]["test_fraction"], abs=2)


def test_ablation_exposes_a_single_dominant_signal():
    """The guard against one circular feature carrying a headline AUC.

    Every other signal here is pure noise, so a stack that still scores 1.0
    after dropping taint would mean the ablation is not actually dropping it.
    """
    X, y = signal_frame(separable=False)
    X["taint_score"] = y.astype(float)                   # a perfect copy of the label
    table = ablation(X, y, SIGNALS, CFG)
    assert table["taint_score"]["alone"] == 1.0
    assert table["taint_score"]["stack_without_it"] < 1.0
    assert table["rule_score"]["stack_without_it"] == 1.0   # taint still present


# --- explanations ---------------------------------------------------------
def test_shap_contributions_are_exact_for_a_linear_model():
    X, y = signal_frame()
    stacker = train(X, y, CFG)
    baseline = X[SIGNALS].mean()
    row = X.iloc[0]
    contributions = shap_contributions(stacker, row, baseline)
    coefs = stacker.coefficients()
    for signal in SIGNALS:
        assert contributions[signal] == pytest.approx(
            coefs[signal] * (row[signal] - baseline[signal]), abs=1e-6)


def test_reason_uses_this_entity_s_real_numbers():
    row = pd.Series({"entity_id": "C1", "risk_score": 0.83, "fan_in_ratio": 0.91,
                     "counterparties_in": 12, "velocity": 40.0, "lifetime_days": 2.0,
                     "round_amount_ratio": 0.8, "anomaly_score": 0.9, "gnn_score": 0.0,
                     "taint_score": 0.25, "suspicious_merge": False})
    reason = build_reason(row, {"rule_score": 0.4},
                          ["received from 12 distinct wallets"],
                          "estimated origin 1.2.3.4, hosting/VPN infrastructure",
                          ["C_seed", "C_mid", "C1"], CFG)
    assert "0.91" in reason and "12 distinct" in reason
    assert "40 transactions per day" in reason
    assert "80% of its amounts are round figures" in reason
    assert "2-hop taint inheritance from flagged entity C_seed" in reason
    assert "composite score: 0.83" in reason
    assert "0.78" not in reason, "the docstring's example numbers leaked into output"


def test_reason_warns_when_the_cluster_may_be_over_merged():
    row = pd.Series({"entity_id": "C1", "risk_score": 0.7, "suspicious_merge": True,
                     "fan_in_ratio": 0.0, "anomaly_score": 0.0, "taint_score": 0.0})
    assert "collapse-guard" in build_reason(row, {}, [], None, None, CFG)


def test_explanation_carries_evidence_and_a_top_signal():
    X, y = signal_frame()
    stacker = train(X, y, CFG)
    row = X.iloc[0].copy()
    row["risk_score"] = 0.9
    row["suspicious_merge"] = False
    explanation = explain_entity(row, stacker, X[SIGNALS].mean(), ["a rule fired"],
                                 ["tx1", "bc1qwallet", "1.2.3.4"], None, None, CFG)
    assert explanation.reason.startswith("Flagged due to")
    assert explanation.evidence == ["tx1", "bc1qwallet", "1.2.3.4"]
    assert explanation.top_signal in SIGNALS


# --- end to end -----------------------------------------------------------
@pytest.fixture(scope="module")
def pipeline(tmp_path_factory):
    from generator.main import build_parser, generate
    from ingest.pipeline import run as ingest_run

    d = tmp_path_factory.mktemp("fusion")
    raw = d / "raw"
    generate(build_parser().parse_args(["--n-actors", "200", "--n-transactions", "1500",
                                        "--output", str(raw), "--seed", "17",
                                        "--formats", "csv"]))
    ingest_run(raw, d / "t.parquet", d / "q.parquet", "csv")
    summary = fusion_run(d / "t.parquet", raw / "ground_truth.json",
                         d / "final.parquet", d / "final.json", CFG)
    return d, summary


def test_pipeline_reports_auc_with_and_without_taint(pipeline):
    _, summary = pipeline
    metrics = summary["stacker"]
    table = metrics["ablation"]
    print(f"\n  stacker AUC (all five signals): {metrics['auc']}")
    print(f"  {'signal':<20}{'alone':>8}{'stack without it':>20}")
    for signal, scores in table.items():
        print(f"  {signal:<20}{str(scores['alone']):>8}{str(scores['stack_without_it']):>20}")
    print("  NB: taint is seeded from the rules engine, which fires on the same "
          "clusters the\n      labels mark — its AUC is circular. The honest number is "
          "the stack without it.")
    assert metrics["auc"] is not None
    without_taint = table["taint_score"]["stack_without_it"]
    assert without_taint > 0.5, "the non-circular signals carry no information at all"


def test_every_alert_has_a_reason_and_evidence(pipeline):
    d, summary = pipeline
    alerts = pd.read_parquet(d / "final.parquet")
    assert len(alerts) == summary["alerts"] > 0
    assert alerts["risk_score"].ge(CFG["fusion"]["alert_threshold"]).all()
    assert alerts["reason"].str.len().gt(30).all()
    assert alerts["reason"].str.startswith("Flagged due to").all()
    assert alerts["evidence"].map(len).ge(1).all(), "an alert cited no evidence"
    assert alerts["top_signal"].isin(SIGNALS).all()
    for blob in alerts["contributions"]:
        assert set(json.loads(blob)) == set(SIGNALS)


def test_alerts_json_is_servable(pipeline):
    d, _ = pipeline
    payload = json.loads((d / "final.json").read_text())
    assert set(payload) >= {"alerts", "stacker", "alert_threshold", "degraded_mode"}
    assert payload["alerts"] and "reason" in payload["alerts"][0]
    assert "warning" in payload["stacker"]


def test_alerts_are_ranked(pipeline):
    d, _ = pipeline
    alerts = pd.read_parquet(d / "final.parquet")
    assert alerts["risk_score"].is_monotonic_decreasing


def test_pipeline_survives_without_a_trained_gnn(pipeline):
    """torch is an optional extra; the other four signals must still stack."""
    d, summary = pipeline
    alerts = pd.read_parquet(d / "final.parquet")
    assert (alerts["gnn_score"] == 0.0).all()
    assert summary["alerts"] > 0
