"""The actor unit and the cost-weighted origin metric.

docs/detection_unit_protocol.md is the specification; these are the checks that
it is what the code does.
"""

from __future__ import annotations

import json

import networkx as nx
import pandas as pd
import pytest

import config
from eval import actors as actors_mod
from eval import origin as origin_mod
from eval.datasets import build

CFG = config.load()


@pytest.fixture(scope="module")
def small(tmp_path_factory):
    """A small generated dataset — enough for a handful of illicit operations."""
    cfg = json.loads(json.dumps(CFG))
    cfg["eval"].update({"n_actors": 60, "n_transactions": 400})
    return build(0.3, False, 7, cfg, root=tmp_path_factory.mktemp("actors"))


# --- the actor ------------------------------------------------------------
def test_an_actor_holds_only_wallets_of_illicit_clusters(small):
    gt = small.ground_truth()
    patterns = {cid: c["pattern_type"] for cid, c in gt["clusters"].items()}
    actors = actors_mod.actors_of(small)
    assert actors, "the dataset produced no illicit operations to score"
    for actor in actors:
        for wallet in actor.wallets:
            assert patterns[gt["wallets"][wallet]] in actors_mod.ILLICIT_ACTOR_PATTERNS


def test_victims_and_cashouts_are_not_part_of_the_actor(small):
    """They are counterparties of the operation, not the operation."""
    gt = small.ground_truth()
    excluded = {w for c in gt["clusters"].values()
                if c["pattern_type"] in ("ransomware_victim", "cashout")
                for w in c["wallets"]}
    owned = {w for a in actors_mod.actors_of(small) for w in a.wallets}
    assert excluded and not (owned & excluded)


def test_a_layering_instance_is_one_actor_not_one_per_hop(small):
    """The generator gives every hop its own owner; they are one launderer."""
    layering = [a for a in actors_mod.actors_of(small) if a.typology == "layering"]
    if not layering:
        pytest.skip("no layering instance in this draw")
    assert max(len(a.wallets) for a in layering) > 1


def test_the_broad_label_is_wider_than_the_actor_label(small):
    owned = {w for a in actors_mod.actors_of(small) for w in a.wallets}
    assert owned < actors_mod.broad_label_wallets(small)


def test_reachable_respects_the_hop_budget():
    g = nx.DiGraph([("a", "b"), ("b", "c"), ("c", "d")])
    assert actors_mod.reachable(g, {"a"}, 1) == {"a", "b"}
    assert actors_mod.reachable(g, {"a"}, 2) == {"a", "b", "c"}
    assert actors_mod.reachable(g, {"d"}, 3) == {"d"}          # outgoing only


def test_case_detection_rate_is_per_actor_not_per_wallet(small):
    actors = actors_mod.actors_of(small)
    entity_of = {w: w for a in actors for w in a.wallets}.get   # one wallet, one entity
    graph = nx.DiGraph()
    everything = {w for a in actors for w in a.wallets}

    found = actors_mod.case_metrics(small, everything, entity_of, {}, graph, CFG)
    assert found["case_detection_rate"] == 1.0
    assert found["detected_actors"] == len(actors)

    # One wallet of one actor: still a detected case, and still one case.
    one = {next(iter(actors[0].wallets))}
    partial = actors_mod.case_metrics(small, one, entity_of, {}, graph, CFG)
    assert partial["detected_actors"] == 1
    assert partial["case_detection_rate"] == pytest.approx(round(1 / len(actors), 3))
    assert partial["wallet_recall_broad"] < partial["case_detection_rate"]


# --- the cost-weighted origin metric --------------------------------------
def frame(rows) -> pd.DataFrame:
    return pd.DataFrame(rows, columns=["ip_class", "confidence", "correct",
                                       "origin_observed"])


RESIDENTIAL, TOR, RELAY = "residential_or_unknown", "tor_exit", "known_bitcoin_relay"


def test_every_outcome_is_priced_as_pre_registered():
    df = frame([(RESIDENTIAL, 0.9, True, True),      # correct_actionable       +1
                (TOR, 0.9, True, True),              # correct_infrastructure   +0.3
                (RESIDENTIAL, 0.9, False, True),     # wrong third party        -3
                (RESIDENTIAL, 0.1, False, False)])   # abstained (low conf)      0
    scored = origin_mod.cost_score(df, CFG, cutoff=0.35)
    assert (scored["correct_actionable"], scored["correct_infrastructure"],
            scored["wrong_uninvolved_third_party"], scored["abstained"]) == (1, 1, 1, 1)
    assert scored["cost_weighted_score"] == pytest.approx((1 + 0.3 - 3 + 0) / 4)
    assert scored["accuracy"] == 0.5          # accuracy cannot see the difference


def test_a_relay_at_the_top_abstains_whatever_its_confidence():
    df = frame([(RELAY, 0.99, False, True)])
    assert origin_mod.cost_score(df, CFG)["abstained"] == 1


def test_the_cutoff_is_chosen_by_the_cost_rule_with_ties_to_the_lower_value(small):
    chosen, table = origin_mod.choose_cutoff(small, CFG)
    best = table["cost_weighted_score"].max()
    assert table[table["cutoff"] == chosen]["cost_weighted_score"].iloc[0] == best
    assert chosen == table[table["cost_weighted_score"] == best]["cutoff"].min()


def test_the_split_filter_is_reported_beside_the_old_one(small):
    comparison = origin_mod.filter_comparison(small, CFG)
    assert list(comparison["filter"]) == list(origin_mod.FILTER_MODES)
    assert comparison["n"].nunique() == 1        # same transactions, three filters
