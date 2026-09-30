"""The origination results, rendered once for two destinations.

`python -m eval.report` calls `section` for eval/results.md section 9 and
`write_doc` for docs/ORIGINATION_RESULTS.md, from the same `evaluate.run`
result — so the two files cannot quote different numbers. Neither is ever
edited by hand.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from .evaluate import MODEL, TEST_SETS


def _omitted(omissions: str) -> str:
    return f"\n*`condition=\"simulated\"`.* {omissions}\n"


def section(result: dict, md_table) -> str:
    """Markdown for the corpus subsection of section 9."""
    s, split, v = result["summary"], result["split"], result["verdict"]
    omissions = result["omissions"]
    out = [
        "\n### simulated — supervised origination (row 5), on a capture corpus\n",
        f"`condition=\"simulated\"`. **What the simulator omits:** {omissions}\n",
        "\nThe model reads one observer's relay matrix (`features/relay.py`), so it is "
        "trained and scored on single-vantage captures from `origination/corpus.py`: "
        f"corpus `{result['corpus']}`, deterministic from `origination/manifest.json`. "
        "Every row of both tables below is scored on the **same transactions** — the "
        "floor and the three estimators through `eval.ground_truth.score` unchanged, the "
        "model's per-transaction answer through the same `summarise` — and every "
        "abstention cutoff, the model's and each estimator's, was chosen on the "
        "calibration captures by `eval.origin`'s pre-registered rule, never on a test "
        "capture. **The headline is `cost_weighted_score` and `acc if answered`, not "
        "top-1.** The cross-topology table is the honest one.\n",
        "\n#### Cross-topology — topology configurations never seen in training\n\n",
        md_table(result["tables"]["cross_test"]),
        _omitted(omissions),
        "\n#### Within-topology — unseen captures, seen configurations (optimistic)\n\n",
        md_table(result["tables"]["within_test"]),
        _omitted(omissions),
        "\n" + verdict(result) + "\n",
        "\n#### Calibration\n\nIsotonic, fitted on the calibration captures. "
        "Per-candidate ECE is dominated by the many rows with probability near zero "
        "and is small almost by construction; the top-candidate ECE — the probability "
        "the abstention rule actually reads — is the one to quote.\n\n",
        md_table(pd.DataFrame([{"test set": TEST_SETS[k], **v_}
                               for k, v_ in result["reliability"].items()]), floats=4),
        _omitted(omissions),
        "\n#### The corpus and the split\n\n",
        md_table(pd.DataFrame([{
            "condition": "simulated", "captures": s["captures"],
            "topology configurations": s["topology_configurations"], "graphs": s["graphs"],
            "transactions broadcast": s["transactions_broadcast"],
            "transactions observed": s["transactions_observed"], "rows": s["rows"],
            "positive rows": s["positive_rows"],
            "degenerate transactions": s["degenerate_transactions"],
            "scope_out transactions": s["scope_out_transactions"],
            "origin among candidates": s["origin_among_candidates_share"]}]), floats=4),
        "\n`candidate_count` per broadcast transaction (0 = never observed, so no row in "
        "the matrix; 1 = degenerate):\n\n",
        md_table(pd.DataFrame([{"condition": "simulated",
                                **s["candidate_count_distribution"]}])),
        "\n" + md_table(pd.DataFrame([{"condition": "simulated", **split["captures"],
                                       "topologies trained on": split["topologies_trained_on"],
                                       "topologies held out": split["topologies_held_out"],
                                       "shared capture_ids": split["shared_capture_ids"],
                                       "shared topologies (train vs cross)":
                                       split["shared_topologies_train_vs_cross"]}])),
        "\nThe split is asserted, not assumed: `evaluate.check_split` refuses a run in "
        "which a capture sits in two roles or a held-out configuration reaches training, "
        "and `tests/test_origination.py` proves that check can fail.\n",
        _omitted(omissions),
        "\n#### Why it answered — exact SHAP, in words\n\n"
        "Top candidates from the cross-topology set, chosen by sorted key rather than by "
        "how well the sentence reads. SHAP values come from `fusion.explain."
        "shap_contributions`, exact because the model is additive by construction; the "
        "phrases are the features with the largest contributions, carrying this peer's "
        "own numbers.\n\n",
        md_table(result["examples"]),
        _omitted(omissions),
        f"\nSignet rows for the model stay **PENDING**: it has been trained and scored "
        f"only on simulated captures (row `{MODEL}` in the signet tables above).\n",
    ]
    return "".join(out)


def verdict(result: dict) -> str:
    """The comparison, written from the numbers in either direction."""
    v = result["verdict"]
    cross = result["tables"]["cross_test"].set_index("estimator")
    best, mine = cross.loc[v["best_estimator"]], cross.loc[MODEL]
    lines = [f"**Verdict (cross-topology).** The model's cost-weighted score is "
             f"{v['model_cost']:.3f} against {v['best_estimator_cost']:.3f} for the best "
             f"single estimator, `{v['best_estimator']}`."]
    if v["earns_its_place"]:
        lines.append("On the pre-registered measure the fusion earns its place.")
    else:
        lines.append("**The fusion does not earn its place**: at or below the best single "
                     "estimator on held-out topologies. It was not tuned further — that "
                     "result is the finding.")
    if mine["acc if answered"] is not None and best["acc if answered"] is not None:
        if mine["acc if answered"] < best["acc if answered"]:
            lines.append(
                f"Accuracy-given-answered is *lower* for the model ({mine['acc if answered']:.3f} "
                f"vs {best['acc if answered']:.3f}): `{v['best_estimator']}` answers only "
                f"{1 - best['abstention rate']:.1%} of transactions and is right more often "
                f"when it does; the model answers {1 - mine['abstention rate']:.1%}, and the "
                "cost weights price that coverage above the precision it gives up.")
        else:
            lines.append(f"Accuracy-given-answered is {mine['acc if answered']:.3f} against "
                         f"{best['acc if answered']:.3f}.")
    lines.append(
        f"Most of the difference is in *when to answer*, not in ranking: top-1 is "
        f"{mine['top1']:.3f} against {best['top1']:.3f}, both bounded by the "
        f"{mine['ceiling (origin observed)']:.3f} of transactions whose origin was a "
        "candidate at all. The estimators abstain on "
        f"{best['abstention rate']:.1%} of transactions because their confidence — the "
        "winner's share of the score vector — is small whenever many peers announce. "
        "A single estimator with a calibrated confidence was not built, so this table "
        "does not separate the value of fusing from the value of calibrating.")
    return " ".join(lines)


DOC_HEADER = """# Supervised origination — results

**Generated by `python -m eval.report`. Do not edit by hand**; the same tables
are in `eval/results.md` section 9, from the same run.

Per `(txid, peer_ip)`: did this peer *originate* the transaction, or only
forward it? Code in `origination/`; the input is the `features/relay.py`
matrix; the three `engines/propagation` estimators are columns of that matrix
and the model fuses them rather than replacing them.

## Method, in one screen

* **Corpus** (`origination/corpus.py`, `origination/manifest.json`). Thousands
  of single-vantage captures from `generator/`'s gossip simulation, varied over
  seed, node count, four topology families, relay share, observer count and
  placement, message loss, and sender count/adjacency. Placements `leaf`,
  `relay_only` and `isolated` exist to produce degenerate, scope_out and
  never-observed transactions, which the hand-written fixtures do not contain.
  Deterministic from the manifest and offline; cached by a digest of the
  manifest and the config blocks it reads.
* **Split** (`origination/evaluate.py`). By capture, never by row. Six whole
  topology configurations are held out for the cross-topology test; the rest
  are divided by a hash of the capture id into train, calibration and a
  within-topology test. Checked by `check_split` and by
  `tests/test_origination.py`.
* **Model** (`origination/model.py`). Gradient boosting with every feature in
  its own interaction group — an additive model — over the matrix's timing,
  peer-history, class and estimator columns plus per-transaction relative
  versions of them. Row probabilities within a transaction are scaled to sum to
  at most one, so candidates compete without a winner being forced where the
  origin was never observed. Hyperparameters were fixed in `config.yaml` before
  the first result and not tuned afterwards.
* **Calibration and abstention.** Isotonic on the calibration captures.
  `degenerate` and `scope_out` rows get no probability and their transactions
  confidence 0, so they abstain at every cutoff the rule can choose. Everything
  else abstains by `engines.propagation`'s rule (`eval.origin.flagged_at`),
  cutoff chosen by `eval.origin.choose_cutoff_for` under the pre-registered
  `cost_weights`. Each estimator's cutoff is chosen the same way on the same
  captures, so no method gets an in-distribution cutoff the others lack.
* **Explanation.** Exact SHAP through `fusion.explain.shap_contributions`, the
  repo's existing implementation, which is exact for additive models: the
  model's per-feature shape functions are its terms. Rendered as sentences.

## Semi-supervised: an extension point, not built

There is no pool of real, unlabelled mainnet captures in this repository — two
hand-written fixtures only — so a semi-supervised variant would have had
nothing real to learn from. Fed more simulator output as its "unlabelled" pool
it would learn nothing the supervised model has not already seen while
appearing to use real data. The extension point is described in
`origination/__init__.py`.

## Known limits of these numbers

* All of them are `condition="simulated"`. The omission sentence beside every
  table says what that leaves out; the most consequential for a deployment is
  that there is **no Dandelion stem phase**, which on the real network is
  designed to defeat exactly this kind of first-announcer inference.
* `top3` follows `eval.origin`'s existing definition: the best candidate plus
  `runner_ups` (3) more, i.e. four candidates. Kept so the rows stay comparable
  with every other origin table in the repo.
* The estimators' abstention comes from their confidence heuristic, not their
  ranking. No single estimator with a *calibrated* confidence was built, so
  the tables do not separate the value of fusing from the value of calibrating.
* Senders keep one address and one peer set for a whole capture, which is what
  makes the peer-history features informative here. How often a real sender
  reuses an address within an observation window is not something this corpus
  can say.
* Signet rows are PENDING: no sealed signet capture exists, and the model has
  not been applied to one.

## Results
"""


def write_doc(result: dict, md_table, path: Path | str) -> Path:
    path = Path(path)
    body = section(result, md_table).replace("\n### simulated — supervised origination "
                                             "(row 5), on a capture corpus\n", "", 1)
    path.write_text(DOC_HEADER + body.replace("\n#### ", "\n### "))
    return path
