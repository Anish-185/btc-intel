"""The supervised origination model: the split cannot leak, and abstention holds.

Two classes of test, because they fail in different ways. The split tests run
on the real manifest (expanding it is cheap and needs no corpus), so they guard
the split the report actually quotes. The model tests run on a tiny corpus
built from a cut-down manifest that forces the three awkward placements —
leaf, relay_only and isolated — so degenerate, scope_out and unobserved
transactions are guaranteed to be present rather than hoped for.
"""

from __future__ import annotations

import copy

import numpy as np
import pandas as pd
import pytest

import config
from eval import origin as origin_eval
from origination import corpus, evaluate
from origination.model import OriginationModel, abstains_by_construction, design

TINY = {
    "name": "tiny", "seed": 7,
    "topology": {"families": ["relay_hub", "scale_free"], "n_nodes": [80],
                 "relay_share": [0.1], "graphs_per_topology": 1},
    "cross_topology_test": ["scale_free-n80-r0.1"],
    "capture": {"per_graph": 16, "observer_count": [1, 2],
                "placement": {"random": 0.4, "hub": 0.15, "leaf": 0.15,
                              "relay_only": 0.15, "isolated": 0.15},
                "message_loss": [0.0, 0.3], "sender_adjacency": [0.3, 0.8],
                "n_transactions": [15, 25], "senders": [2, 6], "tx_interval_s": 15.0},
    "split": {"within_test_share": 0.25, "calibration_share": 0.35},
}


@pytest.fixture(scope="module")
def cfg():
    cfg = copy.deepcopy(config.load())
    cfg["origination"]["gbm"]["max_iter"] = 40          # speed, not a result
    return cfg


@pytest.fixture(scope="module")
def tiny(cfg, tmp_path_factory):
    directory = corpus.build(cfg, TINY, root=tmp_path_factory.mktemp("corpus"), workers=1)
    return corpus.load(directory)


@pytest.fixture(scope="module")
def fitted(tiny, cfg):
    roles = evaluate.assign(tiny["captures"], TINY)
    role = tiny["matrix"]["capture_id"].map(roles)
    model = OriginationModel.fit(tiny["matrix"][role == "train"], cfg, background_size=100)
    return model.calibrate(tiny["matrix"][role == "calibration"], cfg)


# --- the split -------------------------------------------------------------
def test_no_capture_or_topology_crosses_the_real_split():
    """On the manifest the report uses: no capture_id in two roles, and no
    topology configuration both learnt from and in the cross-topology test."""
    manifest = corpus.load_manifest()
    captures = pd.DataFrame(corpus.expand(manifest))
    roles = evaluate.assign(captures, manifest)

    assert roles.index.is_unique and set(roles.index) == set(captures["capture_id"])
    topo = captures.set_index("capture_id")["topology_id"]
    learnt = set(topo[roles[roles.isin(["train", "calibration"])].index])
    tested = {role: set(roles[roles == role].index) for role in evaluate.TEST_SETS}
    trained = set(roles[roles.isin(["train", "calibration"])].index)
    for ids in tested.values():
        assert not ids & trained
    assert not learnt & set(topo[list(tested["cross_test"])])
    assert set(topo[list(tested["cross_test"])]) == set(manifest["cross_topology_test"])
    assert evaluate.check_split(roles, captures)["shared_topologies_train_vs_cross"] == 0


def test_the_split_check_can_actually_fail():
    """Move one held-out capture into training; the check must refuse."""
    manifest = corpus.load_manifest()
    captures = pd.DataFrame(corpus.expand(manifest))
    roles = evaluate.assign(captures, manifest).copy()
    roles[roles[roles == "cross_test"].index[0]] = "train"
    with pytest.raises(AssertionError, match="topology configurations"):
        evaluate.check_split(roles, captures)


def test_split_is_a_function_of_the_manifest():
    manifest = corpus.load_manifest()
    a = evaluate.assign(pd.DataFrame(corpus.expand(manifest)), manifest)
    b = evaluate.assign(pd.DataFrame(corpus.expand(manifest)), manifest)
    pd.testing.assert_series_equal(a, b)


# --- the corpus ------------------------------------------------------------
def test_corpus_contains_the_cases_the_fixtures_lack(tiny):
    summary = corpus.summarise(tiny["matrix"], tiny["truth"], tiny["captures"])
    assert summary["candidate_count_distribution"]["0"] > 0
    assert summary["degenerate_transactions"] > 0
    assert summary["scope_out_transactions"] > 0
    assert 0 < summary["positive_rows"] < summary["rows"]


def test_corpus_is_deterministic_across_workers(cfg, tiny, tmp_path):
    again = corpus.load(corpus.build(cfg, TINY, root=tmp_path, workers=2))
    for name in ("matrix", "truth", "captures"):
        pd.testing.assert_frame_equal(tiny[name], again[name])


# --- abstention ------------------------------------------------------------
def test_degenerate_and_scope_out_rows_never_get_a_probability(tiny, fitted):
    matrix = tiny["matrix"]
    scored = fitted.score(matrix)
    blocked = abstains_by_construction(matrix)
    assert blocked.any() and (~blocked).any()
    assert scored.loc[blocked, "p_calibrated"].isna().all()
    assert scored.loc[blocked, "p_raw"].isna().all()
    assert scored.loc[~blocked, "p_calibrated"].notna().all()
    assert set(scored.loc[matrix["degenerate"].astype(bool), "abstain_reason"]) == {"degenerate"}


@pytest.mark.parametrize("reason", ["degenerate", "scope_out"])
def test_those_transactions_abstain_at_every_cutoff_the_rule_can_pick(tiny, fitted, cfg,
                                                                      reason):
    """Confidence 0 is below every cutoff in the pre-registered grid, and the
    abstention is eval.origin's own, so no choice of cutoff can answer one."""
    truth = tiny["truth"].set_index(["capture_id", "txid"])["origin_ip"]
    decided = fitted.decide(tiny["matrix"], truth, cfg)
    cases = decided[decided["abstain_reason"] == reason]
    assert len(cases)
    assert (cases["confidence"] == 0.0).all()
    for step in range(2, 19):
        assert origin_eval.flagged_at(cases, cfg, round(step * 0.05, 2)).all()
    assert fitted.cutoff > 0
    served = fitted.predict(tiny["matrix"], cfg)
    keys = set(zip(cases["capture_id"], cases["txid"]))
    mine = served[[k in keys for k in zip(served["capture_id"], served["txid"])]]
    assert not mine["answered_tx"].any()


def test_an_ordinary_transaction_can_still_be_answered(tiny, fitted, cfg):
    """The abstention tests would pass on a model that never answers anything."""
    served = fitted.predict(tiny["matrix"], cfg)
    assert served["answered_tx"].any()


def test_calibrated_probabilities_are_probabilities(tiny, fitted):
    scored = fitted.score(tiny["matrix"])
    p = scored["p_calibrated"].dropna()
    assert p.between(0, 1).all()
    per_tx = scored.groupby(["capture_id", "txid"])["p_raw"].sum()
    assert (per_tx <= 1 + 1e-9).all()        # candidates compete: at most one origin


# --- explanation -----------------------------------------------------------
def test_shap_is_exact(tiny, fitted):
    """Efficiency: the values sum to the margin minus its background mean.
    Holds only because the model is additive; this is what would break first
    if interaction constraints were ever lifted without switching to TreeSHAP."""
    live = tiny["matrix"][~abstains_by_construction(tiny["matrix"])].head(30)
    X = design(live)
    values = fitted.shap(X)
    base = fitted.margin(fitted.reference.to_frame().T)[0] + fitted.baseline_terms.sum()
    np.testing.assert_allclose(values.sum(axis=1), fitted.margin(X) - base, atol=1e-4)


def test_explanations_name_the_peer_and_its_numbers(tiny, fitted):
    matrix = tiny["matrix"]
    live = matrix[~abstains_by_construction(matrix)].head(5)
    blocked = matrix[abstains_by_construction(matrix)].head(2)
    out = fitted.explain(pd.concat([live, blocked]))
    for row, text in zip(pd.concat([live, blocked]).itertuples(), out["explanation"]):
        assert f"peer {row.peer_ip}" in text
    assert all("no answer" in t for t in out["explanation"].iloc[-2:])
    assert all("calibrated" in t for t in out["explanation"].iloc[:5])
