"""The validity layer, measured: detector precision/recall and what it does to cost.

`python -m eval.report` calls `run` and renders `section` into eval/results.md
section 10 and `write_doc` into docs/VALIDITY.md, from one result.

On the corpus variant (`origination/manifest_validity.json`) — the base corpus
with Dandelion stems, onion senders, v2 links and CoinJoins switched on per
capture — the supervised model is fitted, calibrated and scored exactly as in
section 9 (`origination.evaluate.run`), then scored twice on the same test
transactions: with the validity layer enforced and without it, each with its
abstention cutoff chosen on the calibration captures by the same
pre-registered rule. Nothing about the detectors was tuned against either.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

import config
from eval import origin as origin_eval
from eval.ground_truth import score
from origination import corpus
from origination import evaluate as origination_eval
from origination.evaluate import MODEL, TEST_SETS, with_cutoff
from origination.model import KEY

from . import validity

#: The base corpus's omission sentence with its Dandelion clause struck, then
#: what the variant adds and how it simplifies.
OMISSIONS = (corpus.OMISSIONS.replace(
    "any Dandelion/Dandelion++ stem phase (every broadcast diffuses from its first "
    "hop immediately), ", "") + " " + corpus.VALIDITY_ADDS)


def unenforced(cfg: dict) -> dict:
    return {**cfg, "validity": {**cfg["validity"], "enforce": False}}


# --- detectors against ground truth -------------------------------------------
def detections(matrix: pd.DataFrame, decided: pd.DataFrame, truth: pd.DataFrame,
               cfg: dict) -> pd.DataFrame:
    """Each detector run on its own, per observed transaction, beside the
    generator's labels. TOR_OR_V2 is about the peer the model named, so it is
    split into its two clauses."""
    named = decided.set_index(KEY)["estimated_origin_ip"]
    labels = truth.set_index(KEY)
    rows = []
    for (capture_id, txid), group in matrix.groupby(KEY, sort=False):
        peer = named.get((capture_id, txid))
        t = labels.loc[(capture_id, txid)]
        mine = group[group["peer_ip"] == peer]
        rows.append({
            "stem_fired": validity.dandelion_stem(group["delta_vs_first_s"], cfg) is not None,
            "coinjoin_fired": validity.coinjoin(validity.tx_of(txid, t), cfg) is not None,
            "onion_fired": str(peer).endswith(".onion"),
            "v2_fired": bool(mine["transport_v2"].any()),
            "stem": bool(t["stem_length"] > 0),
            "stem_through_observer": bool(t["stem_through_observer"]),
            "coinjoin": t["shape"] == "coinjoin",
            "onion_origin": bool(t["onion_origin"]),
        })
    return pd.DataFrame(rows)


def _pr(name: str, against: str, fired: pd.Series, actual: pd.Series, cfg: dict,
        test_set: str) -> dict:
    tp, n_fired, n_actual = int((fired & actual).sum()), int(fired.sum()), int(actual.sum())
    return {"condition": "simulated", "test set": test_set, "detector": name,
            "ground truth": against, "transactions": len(fired),
            "truly present": n_actual, "fired": n_fired, "true positives": tp,
            "precision": round(tp / n_fired, 3) if n_fired else None,
            "precision 95% CI": score._ci(tp, n_fired, cfg) if n_fired else "n/a",
            "recall": round(tp / n_actual, 3) if n_actual else None,
            "recall 95% CI": score._ci(tp, n_actual, cfg) if n_actual else "n/a"}


def precision_recall(d: pd.DataFrame, cfg: dict, test_set: str) -> list[dict]:
    either = d["onion_fired"] | d["v2_fired"]
    return [
        _pr(validity.DANDELION_STEM, "a stem was used", d["stem_fired"], d["stem"], cfg,
            test_set),
        _pr(validity.DANDELION_STEM, "the stem passed through an observer",
            d["stem_fired"], d["stem_through_observer"], cfg, test_set),
        _pr(validity.COINJOIN, "CoinJoin shape", d["coinjoin_fired"], d["coinjoin"], cfg,
            test_set),
        _pr(f"{validity.TOR_OR_V2} (onion clause)", "sender reachable only over Tor",
            d["onion_fired"], d["onion_origin"], cfg, test_set),
        _pr(f"{validity.TOR_OR_V2} (both clauses)", "sender reachable only over Tor",
            either, d["onion_origin"], cfg, test_set),
    ]


# --- the system with and without the layer ------------------------------------
def with_and_without(frame: pd.DataFrame, cut_on: float, cut_off: float,
                     cfg: dict, label: str) -> list[dict]:
    on = score.summarise(f"{MODEL} + validity", frame, with_cutoff(cfg, cut_on))
    off = score.summarise(f"{MODEL}, validity off", frame,
                          with_cutoff(unenforced(cfg), cut_off))
    rows = []
    for row, cutoff in ((off, cut_off), (on, cut_on)):
        rows.append({"condition": "simulated", "test set": label, **row,
                     "cutoff (chosen on calibration)": cutoff})
    return rows


def ablation(frame: pd.DataFrame, cut_off: float, cfg: dict, label: str) -> pd.DataFrame:
    """Per reason: how many transactions it withholds that the layer-off system
    would have answered, what those answers would have been, and the cost score
    with only that reason enforced. A reason that withholds mostly correct
    answers is abstaining on cases we were getting right."""
    off_cfg = with_cutoff(unenforced(cfg), cut_off)
    outcome = origin_eval.outcomes(frame, off_cfg)
    base = origin_eval.cost_score(frame, off_cfg)["cost_weighted_score"]
    rows = []
    for reason in validity.REASONS:
        hit = frame["validity"] == reason
        answered = hit & (outcome != "abstained")
        only = frame.assign(validity=frame["validity"].where(hit, validity.PASS))
        cost = origin_eval.cost_score(only, with_cutoff(cfg, cut_off))["cost_weighted_score"]
        counts = outcome[answered].value_counts()
        rows.append({
            "condition": "simulated", "test set": label, "reason": reason,
            "withheld": int(hit.sum()),
            "would have been answered": int(answered.sum()),
            "…correct_actionable": int(counts.get("correct_actionable", 0)),
            "…correct_infrastructure": int(counts.get("correct_infrastructure", 0)),
            "…wrong_uninvolved_third_party": int(counts.get("wrong_uninvolved_third_party", 0)),
            "cost score, this reason only": cost,
            "change vs layer off": round(cost - base, 3),
        })
    return pd.DataFrame(rows)


def run(cfg: dict | None = None, rebuild: bool = False, base: dict | None = None) -> dict:
    """`base` is section 9's `origination.evaluate.run` result, for the one
    number that needs a corpus with no invalidating condition in it: how often
    DANDELION_STEM fires where no stem exists."""
    cfg = cfg or config.load()
    manifest = corpus.load_manifest(corpus.VALIDITY_MANIFEST)
    result = origination_eval.run(cfg, rebuild, manifest=manifest)
    model, parts, truth = result["model"], result["parts"], result["truth"]
    labels = corpus.load(corpus.build(cfg, manifest))["truth"]

    calibration = model.decide(parts["calibration"], truth, cfg, result["shapes"])
    cut_on = model.cutoff
    cut_off, _ = origin_eval.choose_cutoff_for(calibration, unenforced(cfg))

    pr, system, ablations, reasons = [], [], [], []
    for role, label in TEST_SETS.items():
        frame = result["decided"][role]
        d = detections(parts[role], frame, labels, cfg)
        pr += precision_recall(d, cfg, label)
        system += with_and_without(frame, cut_on, cut_off, cfg, label)
        ablations.append(ablation(frame, cut_off, cfg, label))
        reasons.append(frame["validity"].value_counts().rename(label))

    false_alarms = None
    if base is not None:
        frame = base["decided"]["cross_test"]
        fired = frame["validity"] == validity.DANDELION_STEM
        false_alarms = {"transactions": len(frame), "fired": int(fired.sum()),
                        "rate": round(float(fired.mean()), 4) if len(frame) else None,
                        "corpus": base["corpus"]}

    system = pd.DataFrame(system)
    cross = system[system["test set"] == TEST_SETS["cross_test"]]
    return {"corpus": result["corpus"], "summary": result["summary"],
            "precision_recall": pd.DataFrame(pr), "system": system,
            "ablation": pd.concat(ablations, ignore_index=True),
            "reasons": pd.concat(reasons, axis=1).fillna(0).astype(int)
            .rename_axis("verdict").reset_index(),
            "cutoffs": {"with validity": cut_on, "without validity": cut_off},
            "improves": float(cross.iloc[1]["cost_weighted_score"])
            > float(cross.iloc[0]["cost_weighted_score"]),
            "cross": cross, "base_false_alarms": false_alarms,
            "variant_tables": result["tables"], "omissions": OMISSIONS}


# --- rendering --------------------------------------------------------------
TAXONOMY = """\
Origin attribution names the peer that announced a transaction first, or most
centrally, to an observer. **Calibration** says how often such a name is right.
The **validity layer** (`analysis/validity.py`) comes first: it asks whether the
transaction is one an attribution can be about at all, and when it is not,
withholds the attribution with a reason code and the evidence.

A withheld origin abstains through the existing rule — `low_confidence_origin`
in `engines/propagation`, `eval.origin.flagged_at` everywhere else — not
through a second path. `validity.enforce: false` in config.yaml switches the
layer off in that one place; the no-abstention floor and the "without" rows
below use it.

Every origin the system emits — `engines/propagation`'s estimates, the
origination model's output, the API's `/transactions/{txid}/propagation`, the
red-team origin table, each attribution lead, and the console views of them —
carries a probability, its calibration basis, and a verdict:
`{"status": "PASS" | "INCONCLUSIVE", "reason", "confidence", "evidence"}`.
`tests/test_validity.py` asserts that at the API boundary.

## Reason codes

Checked in this order; the first that fires is the verdict. `confidence` is
confidence that the *condition* is present, not that the attribution is wrong.

| code | fires when | reads | catches | does not catch |
| --- | --- | --- | --- | --- |
| `DEGENERATE` | 0 or 1 peers announced the transaction | `candidate_count` (the matrix's `degenerate`; a single-observation tree) | a capture with nothing to rank | — it is definitional |
| `NOT_REACHABLE` | every candidate is a known public relay | the matrix's `scope_out`; the same rule on a tree | the zero-ceiling case: the sender is not among what this observer can see | a sender absent from the candidates while an ordinary node happens to be among them — that is the unobserved-origin case calibration prices, not a validity failure |
| `COINJOIN` | `graph.clustering.is_coinjoin`: ≥3 inputs, ≥3 outputs, ≥3 equal-value outputs above dust | the transaction's structure | a mix, whose broadcaster says nothing about its other inputs' owners | an equal-value **batch payout** from one owner paying no more equal amounts than it spends inputs (a false positive: structure cannot see input ownership); a CoinJoin with unequal denominations or fewer than three equal outputs (PayJoin, some WabiSabi rounds) |
| `TOR_OR_V2` | the named peer is a `.onion` address, or its announcement came over BIP-324 v2 | the peer address (onion parsing added to `p2p/capture_reader.py`), the event's `transport` | a Tor hidden-service peer named as origin | a Tor sender whose transaction entered through a mixed-transport node: the observer sees that node's clearnet address, and nothing in one capture marks it. For v2, see below |
| `DANDELION_STEM` | the gap after the first announcement is ≥ `isolation_ratio` × the median gap among the rest, with ≥ `min_candidates` candidates | announcement times | an observer on or next to a stem, which hears one peer, then silence, then the broadcast | a stem that ends away from every observer — the broadcast then looks like an ordinary one from the fluff node, which is the common case; sparse captures whose gaps are large for no reason (false positives) |
| `NOT_ASSESSED` | not a detector: a stored output from before this layer | — | keeps an old lead from being served as PASS | — |

**v2 transport.** BIP-324 encrypts a link; it does not hide the peer's address or
change relay timing. What it removes is a *passive* observer's view of that
link, so an attribution built from a pcap can be missing that peer's
announcements. The TOR_OR_V2 detector fires on v2 as specified, and the
ablation below measures what that costs: in the simulation a v2 link is timed
exactly like v1, so every v2 abstention is an abstention the timing evidence
did not ask for.

**Taint.** A CoinJoin terminates taint rather than propagating it:
`graph.entity_graph` counts the CoinJoin transactions on each entity edge
(`mix_count`, from the same `is_coinjoin`), and `fusion.taint.propagate` does
not cross an edge made of nothing else. Correlation already skipped mixes, and
now also skips origins withheld as NOT_REACHABLE, COINJOIN, TOR_OR_V2 or
DANDELION_STEM; it keeps DEGENERATE ones, because aggregating many single-
candidate observations, each weighted by its low confidence, is what it is for.
Each lead's own verdict says how many of its observations were degenerate.

The DANDELION_STEM thresholds were fixed in config.yaml from the shape a stem
leaves, before the first result, and were not tuned afterwards.
"""


def _omitted(omissions: str) -> str:
    return f"\n*`condition=\"simulated\"`.* {omissions}\n"


def verdict(result: dict) -> str:
    off, on = result["cross"].iloc[0], result["cross"].iloc[1]
    cost_off, cost_on = off["cost_weighted_score"], on["cost_weighted_score"]
    if result["improves"]:
        head = (f"**Verdict (cross-topology).** With the validity layer the cost-weighted "
                f"score is {cost_on} against {cost_off} without it: on the pre-registered "
                "measure the layer earns its place.")
    else:
        head = (f"**Verdict (cross-topology): the validity layer does not improve the "
                f"cost score** — {cost_on} with it against {cost_off} without. That means "
                "its detectors abstain on transactions the model was getting right more "
                "often than on ones it was getting wrong; the ablation shows which.")
    return (head + f" Accuracy-given-answered is {on['acc if answered']} with the layer "
            f"and {off['acc if answered']} without; abstention {on['abstention rate']} "
            f"against {off['abstention rate']}.")


def section(result: dict, md_table) -> str:
    om = result["omissions"]
    s = result["summary"]
    prevalence = s["validity_conditions"]
    fa = result["base_false_alarms"]
    rows = [{"condition": "simulated", "measure": k.replace("_", " "),
             "transactions": v["transactions"] if isinstance(v, dict) else v,
             "share of broadcast": v["share"] if isinstance(v, dict) else None}
            for k, v in prevalence.items()
            if k not in ("captures_with_toggle_on", "transactions")]
    out = [
        f"`condition=\"simulated\"`. **What the simulator omits:** {om}\n",
        f"\nCorpus variant `{result['corpus']}`, deterministic from "
        "`origination/manifest_validity.json`: the base manifest's captures, each "
        "drawing four independent toggles. The model is fitted, calibrated and scored "
        "on it exactly as in section 9. Captures with each toggle on: "
        + ", ".join(f"{k} {v}" for k, v in prevalence["captures_with_toggle_on"].items())
        + f", of {s['captures']}.\n",
        "\n### Ground-truth prevalence\n\n", md_table(pd.DataFrame(rows)), _omitted(om),
        "\n### Detector precision and recall against the generator's labels\n\n"
        "Each detector run on its own over every observed test transaction. "
        "TOR_OR_V2 depends on which peer is named; the model's choice is used.\n\n",
        md_table(result["precision_recall"]), _omitted(om),
    ]
    if fa:
        out.append(f"\nOn the base corpus `{fa['corpus']}` (cross-topology test set), "
                   "where no transaction has a stem, DANDELION_STEM fires on "
                   f"{fa['fired']} of {fa['transactions']} transactions ({fa['rate']}): "
                   "every one a false alarm.\n")
    out += [
        "\n### The system with and without the validity layer\n\n"
        "The supervised model on the same test transactions; each row's cutoff chosen "
        "on the calibration captures by `eval.origin.choose_cutoff_for`, with the "
        "layer on and off respectively. **The headline is `cost_weighted_score` and "
        "`acc if answered`.**\n\n",
        md_table(result["system"]), _omitted(om),
        "\n" + verdict(result) + "\n",
        "\n### What each reason withholds\n\n"
        "At the layer-off cutoff: how many transactions each reason withholds that the "
        "layer-off system would have answered, what those answers would have been, "
        "and the cost score with only that reason enforced. DEGENERATE and "
        "NOT_REACHABLE were already abstentions by construction and cost nothing "
        "new.\n\n",
        md_table(result["ablation"]), _omitted(om),
        "\n### Verdicts issued on the test sets\n\n", md_table(result["reasons"]),
        _omitted(om),
        "\n### The variant's section-9 table (cross-topology), validity enforced\n\n",
        md_table(result["variant_tables"]["cross_test"]), _omitted(om),
    ]
    return "".join(out)


DOC_HEADER = """# Validity layer

**Generated by `python -m eval.report`. Do not edit by hand**; the results are
also section 10 of `eval/results.md`, from the same run.

"""


def write_doc(result: dict, md_table, path: Path | str) -> Path:
    path = Path(path)
    path.write_text(DOC_HEADER + TAXONOMY + "\n## Results\n\n"
                    + section(result, md_table))
    return path
