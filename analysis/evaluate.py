"""The validity layer, measured: detector precision/recall, and each abstention
policy under both the P6 metric and the pre-registered revised metric.

`python -m eval.report` calls `run` and renders `section` into eval/results.md
section 10 and `write_doc` into docs/VALIDITY.md, from one result. The
pre-registration (`## Metric revision`) and the frozen P6 results in
docs/VALIDITY.md are copied through verbatim, never regenerated.

Protocol, as pre-registered: three policies — off, binary (P6's gate),
tiered (the revision) — on the same test transactions, each under both
metrics, each (policy, metric) cutoff chosen on the calibration captures by
`eval.origin.choose_cutoff_for`. Base and variant corpora, within- and
cross-topology. The decision rule is `verdict`'s.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

import config
from eval import origin as origin_eval
from origination import corpus
from origination import evaluate as origination_eval
from origination.evaluate import TEST_SETS, label_coinjoins, with_cutoff
from origination.model import KEY

from . import validity

#: The base corpus's omission sentence with its Dandelion clause struck, then
#: what the variant adds and how it simplifies.
OMISSIONS = (corpus.OMISSIONS.replace(
    "any Dandelion/Dandelion++ stem phase (every broadcast diffuses from its first "
    "hop immediately), ", "") + " " + corpus.VALIDITY_ADDS)

POLICIES = ("off", "binary", "tiered")
PRESERVED = ("## Metric revision", "## P6 results (frozen)", "## Red-team timing (measured)")


def policy(cfg: dict, name: str) -> dict:
    v = cfg["validity"]
    return {**cfg, "validity": {**v, "enforce": name != "off",
                                "mode": "binary" if name == "binary" else "tiered"}}


# --- detectors against ground truth -------------------------------------------
def detections(matrix: pd.DataFrame, decided: pd.DataFrame, truth: pd.DataFrame,
               cfg: dict) -> pd.DataFrame:
    """Each detector run on its own, per observed transaction, beside the
    generator's labels. TOR_ONION is about the peer the model named."""
    named = decided.set_index(KEY)["estimated_origin_ip"]
    labels = truth.set_index(KEY)
    rows = []
    for (capture_id, txid), group in matrix.groupby(KEY, sort=False):
        peer = named.get((capture_id, txid))
        t = labels.loc[(capture_id, txid)]
        first = group.iloc[0]
        rows.append({
            "stem_fired": validity.dandelion_stem(group["delta_vs_first_s"], cfg) is not None,
            "coinjoin_fired": validity.coinjoin(validity.tx_of(txid, t), cfg) is not None,
            "onion_fired": validity.tor_onion(peer) is not None,
            "v2_fired": validity.v2_passive_tap(first.get("capture_source"),
                                                first.get("unreadable_flows")) is not None,
            "stem": bool(t["stem_length"] > 0),
            "stem_through_observer": bool(t["stem_through_observer"]),
            "coinjoin": t["shape"] == "coinjoin",
            "onion_origin": bool(t["onion_origin"]),
        })
    return pd.DataFrame(rows)


def _pr(name: str, against: str, fired: pd.Series, actual: pd.Series, cfg: dict,
        test_set: str) -> dict:
    from eval.ground_truth.score import _ci
    tp, n_fired, n_actual = int((fired & actual).sum()), int(fired.sum()), int(actual.sum())
    return {"condition": "simulated", "test set": test_set, "detector": name,
            "tier": validity.TIER[name], "ground truth": against,
            "transactions": len(fired), "truly present": n_actual, "fired": n_fired,
            "true positives": tp,
            "precision": round(tp / n_fired, 3) if n_fired else None,
            "precision 95% CI": _ci(tp, n_fired, cfg) if n_fired else "n/a",
            "recall": round(tp / n_actual, 3) if n_actual else None,
            "recall 95% CI": _ci(tp, n_actual, cfg) if n_actual else "n/a"}


def precision_recall(d: pd.DataFrame, cfg: dict, test_set: str) -> list[dict]:
    return [
        _pr(validity.DANDELION_STEM, "a stem was used", d["stem_fired"], d["stem"], cfg,
            test_set),
        _pr(validity.DANDELION_STEM, "the stem passed through an observer",
            d["stem_fired"], d["stem_through_observer"], cfg, test_set),
        _pr(validity.COINJOIN, "CoinJoin shape", d["coinjoin_fired"], d["coinjoin"], cfg,
            test_set),
        _pr(validity.TOR_ONION, "sender reachable only over Tor", d["onion_fired"],
            d["onion_origin"], cfg, test_set),
        _pr(validity.V2_PASSIVE_TAP, "a v2 peer is missing from a pcap capture",
            d["v2_fired"], pd.Series(False, index=d.index), cfg, test_set),
    ]


# --- the policies under both metrics ------------------------------------------
def cutoffs(calibration: pd.DataFrame, cfg: dict) -> dict:
    return {(p, m): origin_eval.choose_cutoff_for(calibration, policy(cfg, p), m)[0]
            for p in POLICIES for m in origin_eval.METRICS}


def policy_rows(frame: pd.DataFrame, cuts: dict, cfg: dict, corpus_name: str,
                label: str) -> list[dict]:
    from eval.ground_truth.score import _ci
    rows = []
    for p in POLICIES:
        pcfg = policy(cfg, p)
        revised = with_cutoff(pcfg, cuts[(p, "revised")])
        p6 = with_cutoff(pcfg, cuts[(p, "p6")])
        flagged = origin_eval.flagged_at(frame, revised)
        kept = frame[~flagged]
        right = int(kept["correct"].sum())
        r = origin_eval.cost_score(frame, revised, metric="revised")
        rows.append({
            "condition": "simulated", "corpus": corpus_name, "test set": label,
            "policy": p, "n": len(frame),
            "cost, revised metric": r["cost_weighted_score"],
            "cost, P6 metric": origin_eval.cost_score(frame, p6, metric="p6")
            ["cost_weighted_score"],
            "abstention rate": round(float(flagged.mean()), 3),
            "acc if answered": round(right / len(kept), 3) if len(kept) else None,
            "acc if answered 95% CI": _ci(right, len(kept), cfg) if len(kept) else "n/a",
            "correct_actionable": r["correct_actionable"],
            "correct_infrastructure": r["correct_infrastructure"],
            "wrong_uninvolved_third_party": r["wrong_uninvolved_third_party"],
            "qualified_correct": r["qualified_correct"],
            "qualified_wrong": r["qualified_wrong"],
            "coinjoin_input_misattribution": r["coinjoin_input_misattribution"],
            "cutoff, revised": cuts[(p, "revised")], "cutoff, P6": cuts[(p, "p6")],
        })
    return rows


def withheld_table(frame: pd.DataFrame, cuts: dict, cfg: dict, corpus_name: str,
                   label: str) -> pd.DataFrame:
    """P6's per-detector table, again: for each reason, the transactions it
    fires on that the layer-off system would have answered, and what those
    answers were (P6 metric, off's P6 cutoff — P6's method exactly), beside
    what the tiered policy now does with them."""
    off = with_cutoff(policy(cfg, "off"), cuts[("off", "p6")])
    outcome = origin_eval.outcomes(frame, off, metric="p6")
    rows = []
    for reason in validity.REASONS:
        hit = frame["validity_reasons"].map(lambda r: reason in list(r))
        answered = hit & (outcome != "abstained")
        counts = outcome[answered].value_counts()
        rows.append({
            "condition": "simulated", "corpus": corpus_name, "test set": label,
            "reason": reason, "tier now": validity.TIER[reason],
            "tiered policy": {"ABSTAIN": "withholds", "QUALIFIED": "answers, qualified",
                              "ANNOTATE": "answers, flagged"}[validity.TIER[reason]],
            "fired": int(hit.sum()), "would have been answered": int(answered.sum()),
            "…correct_actionable": int(counts.get("correct_actionable", 0)),
            "…correct_infrastructure": int(counts.get("correct_infrastructure", 0)),
            "…wrong_uninvolved_third_party": int(counts.get("wrong_uninvolved_third_party", 0)),
        })
    return pd.DataFrame(rows)


def tier_counts(frame: pd.DataFrame, corpus_name: str, label: str) -> list[dict]:
    reasons = frame["validity_reasons"].explode().dropna().value_counts()
    return [{"condition": "simulated", "corpus": corpus_name, "test set": label,
             "tier": t, "transactions": int((frame["validity_tier"] == t).sum()),
             "reasons fired": ", ".join(f"{r} {int(reasons.get(r, 0))}"
                                         for r in validity.REASONS if validity.TIER[r] == t)
             or "—"}
            for t in (validity.PASS, validity.ABSTAIN, validity.QUALIFIED, validity.ANNOTATE)]


def score_corpus(result: dict, cfg: dict, name: str) -> dict:
    """Every table for one corpus, from its `origination.evaluate.run` result."""
    model, parts, truth = result["model"], result["parts"], result["truth"]
    mixes = origination_eval.coinjoins_of({"truth": result["truth_frame"]})
    calibration = label_coinjoins(
        model.decide(parts["calibration"], truth, cfg, result["shapes"]), mixes)
    cuts = cutoffs(calibration, cfg)
    systems, withheld, tiers = [], [], []
    for role, label in TEST_SETS.items():
        frame = result["decided"][role]
        systems += policy_rows(frame, cuts, cfg, name, label)
        withheld.append(withheld_table(frame, cuts, cfg, name, label))
        tiers += tier_counts(frame, name, label)
    return {"systems": pd.DataFrame(systems),
            "withheld": pd.concat(withheld, ignore_index=True),
            "tiers": pd.DataFrame(tiers)}


def run(cfg: dict | None = None, rebuild: bool = False, base: dict | None = None) -> dict:
    """`base` is section 9's `origination.evaluate.run` result on the base
    corpus; the variant is run here."""
    cfg = cfg or config.load()
    manifest = corpus.load_manifest(corpus.VALIDITY_MANIFEST)
    variant = origination_eval.run(cfg, rebuild, manifest=manifest)
    labels = variant["truth_frame"]

    pr = []
    for role, label in TEST_SETS.items():
        d = detections(variant["parts"][role], variant["decided"][role], labels, cfg)
        pr += precision_recall(d, cfg, label)

    scored = {"variant": score_corpus(variant, cfg, "variant")}
    false_alarms = None
    if base is not None:
        scored["base"] = score_corpus(base, cfg, "base")
        frame = base["decided"]["cross_test"]
        fired = frame["validity_reasons"].map(lambda r: validity.DANDELION_STEM in list(r))
        false_alarms = {"transactions": len(frame), "fired": int(fired.sum()),
                        "rate": round(float(fired.mean()), 4) if len(frame) else None,
                        "corpus": base["corpus"]}

    def joined(key):
        return pd.concat([s[key] for s in scored.values()], ignore_index=True)

    return {"corpus": variant["corpus"], "summary": variant["summary"],
            "base_corpus": base["corpus"] if base else None,
            "precision_recall": pd.DataFrame(pr), "systems": joined("systems"),
            "withheld": joined("withheld"), "tiers": joined("tiers"),
            "base_false_alarms": false_alarms, "omissions": OMISSIONS}


# --- the decision rule ---------------------------------------------------------
def verdict(result: dict) -> str:
    """The pre-registered rule: tiered beats off iff its cross-topology cost on
    the revised metric is higher on the variant corpus; an unqualified
    improvement also needs it higher on the P6 metric."""
    s = result["systems"]
    cross = s[(s["corpus"] == "variant") & (s["test set"] == TEST_SETS["cross_test"])]
    row = cross.set_index("policy")
    off, tiered, binary = row.loc["off"], row.loc["tiered"], row.loc["binary"]
    rev = (tiered["cost, revised metric"], off["cost, revised metric"])
    p6 = (tiered["cost, P6 metric"], off["cost, P6 metric"])
    beats_rev, beats_p6 = rev[0] > rev[1], p6[0] > p6[1]
    if beats_rev and beats_p6:
        head = ("**Verdict (variant, cross-topology): the revised validity layer beats "
                f"no-validity on both metrics** — revised {rev[0]} against {rev[1]}, "
                f"P6 metric {p6[0]} against {p6[1]}.")
    elif beats_rev:
        head = ("**Verdict (variant, cross-topology): the revised layer beats "
                f"no-validity on the revised metric only** — {rev[0]} against {rev[1]}; "
                f"on the P6 metric it scores {p6[0]} against {p6[1]}. As pre-registered, "
                "that is reported as exactly this and not as an unqualified improvement: "
                "the difference comes from pricing the CoinJoin ownership claim, not from "
                "the policy answering better by P6's measure.")
    else:
        head = ("**Verdict (variant, cross-topology): the revised validity layer still "
                f"does not beat no-validity on the revised metric** — {rev[0]} against "
                f"{rev[1]} (P6 metric: {p6[0]} against {p6[1]}). Reported as found; the "
                "weights were not changed after this result.")
    return (head + f" P6's binary gate, rescored on the same transactions: revised "
            f"{binary['cost, revised metric']}, P6 metric {binary['cost, P6 metric']}.")


# --- rendering --------------------------------------------------------------
TAXONOMY = """\
Origin attribution names the peer that announced a transaction first, or most
centrally, to an observer. **Calibration** says how often such a name is right.
The **validity layer** (`analysis/validity.py`) asks two prior questions: can
an attribution be about this transaction at all, and if so, what may it
claim? Every detector runs; every reason that fires is reported; the verdict's
**tier** is the most severe among them.

| tier | effect |
| --- | --- |
| `ABSTAIN` | the answer is withheld, through the existing rule — `low_confidence_origin` in `engines/propagation`, `eval.origin.flagged_at` everywhere else — not a second path |
| `QUALIFIED` | the answer is given with its meaning restricted, and never shaped like an IP attribution |
| `ANNOTATE` | the answer is given unchanged, with the flag and its evidence |
| `PASS` | nothing fired |

`validity.enforce: false` switches the layer off in that one place;
`validity.mode: binary` restores P6's gate, where every non-PASS verdict
abstained.

Every origin the system emits — `engines/propagation`'s estimates, the
origination model's output, the API's `/transactions/{txid}/propagation`, the
red-team origin table, each attribution lead, and the console views of them —
carries a probability, its calibration basis, and a verdict
`{"tier", "reason", "reasons", "confidence", "evidence"}`; where an answer is
given, `answer` says what it may claim: `ip_attribution`, `onion_identity`
(no `ip` field) or `broadcasting_peer` (with `input_ownership: not
attributable`). `tests/test_api.py` asserts the verdict at the API boundary;
`tests/test_validity.py` asserts that no TOR_ONION answer carries an IP and no
COINJOIN answer attributes input ownership.

## Reason codes

`confidence` is confidence that the *condition* is present, not that the
attribution is wrong.

| code | tier | fires when | reads | catches | does not catch |
| --- | --- | --- | --- | --- | --- |
| `DEGENERATE` | ABSTAIN | 0 or 1 peers announced the transaction | `candidate_count` (the matrix's `degenerate`; a single-observation tree) | a capture with nothing to rank | — it is definitional |
| `NOT_REACHABLE` | ABSTAIN | every candidate is a known public relay | the matrix's `scope_out`; the same rule on a tree | the zero-ceiling case: the sender is not among what this observer can see | a sender absent from the candidates while an ordinary node happens to be among them — that is the unobserved-origin case calibration prices |
| `COINJOIN` | QUALIFIED | `graph.clustering.is_coinjoin`: ≥3 inputs, ≥3 outputs, ≥3 equal-value outputs above dust, no more equal outputs than inputs | the transaction's structure | a mix; the answer becomes "broadcasting peer only", input ownership non-attributable | an equal-value **batch payout** from one owner paying no more equal amounts than it spends inputs (a false positive: structure cannot see input ownership); a CoinJoin with unequal denominations or fewer than three equal outputs (PayJoin, some WabiSabi rounds) |
| `TOR_ONION` | QUALIFIED | the named peer is a `.onion` address | the peer address (onion parsing in `p2p/capture_reader.py`) | a hidden-service peer named as origin; the answer becomes an onion identity, never an IP | a Tor sender whose transaction entered through a mixed-transport node: the observer sees that node's clearnet address, and nothing in one capture marks it |
| `DANDELION_STEM` | ANNOTATE | the gap after the first announcement is ≥ `isolation_ratio` × the median gap among the rest, with ≥ `min_candidates` candidates | announcement times | an observer on or next to a stem, which hears one peer, then silence, then the broadcast | a stem that ends away from every observer (the common case); and it false-alarms on sparse captures. A flag only: BIP-156 was never merged into Bitcoin Core, which has no stem phase |
| `V2_PASSIVE_TAP` | ANNOTATE | a pcap capture held port-8333 flows that never decoded | `capture_source`, `unreadable_flows` | a packet capture blind to its BIP-324 v2 peers, whose announcements are then missing from the candidates | which peers those were. It never fires on debug.log or .btcap: the node writes those, and as a session endpoint it decrypts. A pcap on the node's own host is as blind as a span port — tcpdump holds no session keys |
| `NOT_ASSESSED` | — | not a detector: a stored output from before this layer | — | keeps an old lead from being served as PASS | — |

**Taint and leads.** A CoinJoin terminates taint: `graph.entity_graph` counts
the CoinJoin transactions on each entity edge (`mix_count`, from the same
`is_coinjoin`), and `fusion.taint.propagate` does not cross an edge made of
nothing else. A correlation lead says "this IP broadcast for this cluster's
inputs", so none is built from a COINJOIN or TOR_ONION answer or a
NOT_REACHABLE one. DEGENERATE observations are kept — aggregating many
single-candidate observations, each weighted by its low confidence, is what
correlation is for — and ANNOTATE flags ride along; a lead's own verdict is
`PASS` or `ANNOTATE`, naming how many of its observations carried each flag.

The DANDELION_STEM thresholds were fixed in config.yaml before the first P6
result and have not been tuned since.
"""


def _omitted(omissions: str) -> str:
    return f"\n*`condition=\"simulated\"`.* {omissions}\n"


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
    systems = result["systems"]
    out = [
        f"`condition=\"simulated\"`. **What the simulator omits:** {om}\n",
        f"\nVariant corpus `{result['corpus']}` (`origination/manifest_validity.json`) and "
        f"base corpus `{result['base_corpus']}` (`origination/manifest.json`). The model is "
        "fitted, calibrated and scored on each exactly as in section 9. Variant captures "
        "with each toggle on: "
        + ", ".join(f"{k} {v}" for k, v in prevalence["captures_with_toggle_on"].items())
        + f", of {s['captures']}.\n",
        "\n### The policies under both metrics\n\n"
        "Same test transactions for every row. `off`: no validity layer. `binary`: P6's "
        "gate (every non-PASS verdict abstains), current detectors. `tiered`: the "
        "revision. Each metric's cost is at that (policy, metric)'s own cutoff, chosen "
        "on the calibration captures; the other columns are at the revised-metric "
        "cutoff. **The headline is the cost score and `acc if answered`.**\n\n",
        "#### Variant corpus\n\n",
        md_table(systems[systems["corpus"] == "variant"]), _omitted(om),
        "\n#### Base corpus (no invalidating condition simulated)\n\n",
        md_table(systems[systems["corpus"] == "base"]), _omitted(om),
        "\n" + verdict(result) + "\n",
        "\n### Verdicts by tier\n\n", md_table(result["tiers"]), _omitted(om),
        "\n### What each reason fires on, and what the answers were (P6's table, again)\n\n"
        "At the layer-off policy's P6-metric cutoff, P6's method exactly: the "
        "transactions each reason fires on that the layer-off system would have "
        "answered, and whether those answers were right. The `tiered policy` column is "
        "what the revision now does with them.\n\n",
        md_table(result["withheld"]), _omitted(om),
        "\n### Detector precision and recall against the generator's labels\n\n"
        "Each detector on its own over every observed test transaction of the variant. "
        "TOR_ONION depends on which peer is named; the model's choice is used. "
        "V2_PASSIVE_TAP cannot fire here: every simulated observer is a node, which "
        "writes its own log, so no simulated capture is a pcap.\n\n",
        md_table(result["precision_recall"]), _omitted(om),
    ]
    if fa:
        out.append(f"\nOn the base corpus `{fa['corpus']}` (cross-topology test set), where "
                   "no transaction has a stem, DANDELION_STEM fires on "
                   f"{fa['fired']} of {fa['transactions']} transactions ({fa['rate']}): "
                   "every one a false alarm. It now only annotates them.\n")
    out += ["\n### Ground-truth prevalence (variant)\n\n", md_table(pd.DataFrame(rows)),
            _omitted(om)]
    return "".join(out)


def preserved(path: Path | str) -> str:
    """The pre-registration and the frozen P6 results, verbatim from the doc."""
    path = Path(path)
    if not path.exists():
        return ""
    out, keep = [], False
    for line in path.read_text().splitlines(keepends=True):
        if line.startswith("## "):
            keep = line.rstrip("\n") in PRESERVED
        if keep:
            out.append(line)
    return "".join(out)


DOC_HEADER = """# Validity layer

**Generated by `python -m eval.report`, except the two sections copied through
verbatim: `Metric revision` (pre-registered before the rerun) and `P6 results
(frozen)`. Do not edit by hand.** The results are also section 10 of
`eval/results.md`, from the same run.

"""


def write_doc(result: dict, md_table, path: Path | str) -> Path:
    path = Path(path)
    kept = preserved(path)
    if not all(h in kept for h in PRESERVED):
        raise RuntimeError(f"{path} lost a preserved section; restore it from git "
                           "before regenerating")
    path.write_text(DOC_HEADER + TAXONOMY + "\n" + kept.rstrip("\n") + "\n\n"
                    + "## Results — metric revision\n\n" + section(result, md_table))
    return path
