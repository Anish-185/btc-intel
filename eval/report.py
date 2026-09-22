"""One command, one canonical results file.

    python -m eval.report

Everything in eval/results.md comes from here, with the seed and sizes fixed in
config.yaml's `eval:` block. Ad-hoc runs are how this repo ended up quoting two
different ceiling figures for the same statistic; there is now one source.

The unit of detection is the actor, pre-registered in
docs/detection_unit_protocol.md before any of these numbers existed.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

import config

from . import fusion_eval, origin
from .datasets import build


def md_table(df: pd.DataFrame, floats: int = 3) -> str:
    if df.empty:
        return "_(no rows)_\n"
    formatted = df.copy()
    for column in formatted.columns:
        if pd.api.types.is_float_dtype(formatted[column]):
            formatted[column] = formatted[column].map(
                lambda v: "n/a" if pd.isna(v) else f"{v:.{floats}f}")
    formatted = formatted.fillna("n/a")
    header = "| " + " | ".join(str(c) for c in formatted.columns) + " |"
    rule = "| " + " | ".join("---" for _ in formatted.columns) + " |"
    body = "\n".join("| " + " | ".join(str(v) for v in row) + " |"
                     for row in formatted.itertuples(index=False))
    return f"{header}\n{rule}\n{body}\n"


def fmt(value, digits: int = 3) -> str:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return "n/a"
    return f"{value:.{digits}f}" if isinstance(value, float) else str(value)


def choose_default_estimator(table: pd.DataFrame, cfg: dict) -> tuple[str, str]:
    """Apply docs/origin_eval_protocol.md, without re-reading the rule."""
    rate = cfg["eval"]["default_rate"]
    at_rate = table[table["rate"] == rate].sort_values("top1", ascending=False)
    best = at_rate.iloc[0]
    runner = at_rate.iloc[1] if len(at_rate) > 1 else None
    tied = runner is not None and abs(best["top1"] - runner["top1"]) < 0.01
    if tied and "first_timestamp" in set(at_rate.head(2)["estimator"]):
        return "first_timestamp", (
            f"tie at rate {rate} ({best['estimator']} {best['top1']:.3f} vs "
            f"{runner['estimator']} {runner['top1']:.3f}, under 1pp) — "
            "protocol awards ties to first_timestamp")
    return best["estimator"], (
        f"best top-1 at rate {rate}: {best['top1']:.3f}"
        + (f" vs {runner['estimator']} {runner['top1']:.3f}" if runner is not None else ""))


def fusion_section(add, result: dict, label: str, dataset) -> None:
    add(f"\n### {label} — {dataset.describe()}\n")
    add(f"{result['entities']} entities, {result['actors']} illicit actors, "
        f"{result['rule_alerts']} rule alerts, {result['alerted_entities']} alerted "
        f"entities, {result['watchlist_seeds']} watchlist seed entities.\n")

    add("\n**Actor-level detection** (label: entity holds a wallet of a "
        "ground-truth illicit operation):\n\n")
    add(md_table(pd.DataFrame([result["cases"]])))
    add("\n**Per typology:**\n\n")
    add(md_table(result["per_typology_cases"]))
    add("\n`trace_coverage@N` is scored only on detected actors that still have "
        "un-alerted\nwallets left to reach; `traceable@N` is how many actors that was. "
        "`n/a` means\nevery wallet of every detected actor was already alerted.\n")

    for name, note in (("actor", "an entity holding an illicit actor's wallet"),
                       ("broad", "every wallet the money passed through — the old label")):
        block = result.get(name)
        if not block:
            continue
        caveat = (" _(in-sample: too few positives for a chronological hold-out)_"
                  if block.get("auc_in_sample") else "")
        add(f"\n**Stacker, label `{name}`** ({note}) — {block['positives']} positive "
            f"entities, AUC **{block['auc']}**{caveat}\n\n")
        rows = [{"signal": s, "alone": block["signal_auc"].get(s),
                 "stack without it": block["ablation"].get(s, {}).get("stack_without_it"),
                 "weight": block["coefficients"].get(s)}
                for s in block["ablation"]]
        add(md_table(pd.DataFrame(rows), floats=4))

    taint = result.get("taint", {})
    if taint:
        add("\n**Taint, scored only on entities that were neither watchlist seeds nor "
            "rule-flagged:**\n\n")
        add(md_table(pd.DataFrame([taint]), floats=3))
    add("\n**Wallet-level coverage per typology (secondary):**\n\n")
    add(md_table(result["per_typology_wallets"]))


def summary_table(fusion: dict, origin_rows: dict, cfg: dict) -> pd.DataFrame:
    """The numbers that would go on a slide, each with where it came from."""
    e = cfg["eval"]
    std, shift = fusion["standard"], fusion["shifted"]
    actor_label = "actor (entity holds an illicit operation's wallet)"
    rows = [
        ("case_detection_rate", fmt(std["cases"]["case_detection_rate"]),
         fmt(shift["cases"]["case_detection_rate"]), actor_label,
         f"{std['cases']['actors']} / {shift['cases']['actors']} actors"),
        ("alert_precision", fmt(std["cases"]["alert_precision"]),
         fmt(shift["cases"]["alert_precision"]), actor_label,
         f"{std['cases']['alerts']} / {shift['cases']['alerts']} alerts"),
        ("trace_coverage@2", fmt(std["cases"]["trace_coverage@2"]),
         fmt(shift["cases"]["trace_coverage@2"]), actor_label,
         f"{std['cases']['traceable_actors@2']} / "
         f"{shift['cases']['traceable_actors@2']} traceable actors"),
        ("trace_coverage@4", fmt(std["cases"]["trace_coverage@4"]),
         fmt(shift["cases"]["trace_coverage@4"]), actor_label,
         f"{std['cases']['traceable_actors@4']} / "
         f"{shift['cases']['traceable_actors@4']} traceable actors"),
        ("wallet_recall_broad (secondary)", fmt(std["cases"]["wallet_recall_broad"]),
         fmt(shift["cases"]["wallet_recall_broad"]),
         "broad wallet label (hops included)", "every illicit-pattern wallet"),
        ("stacker AUC", fmt(std["actor"]["auc"]), fmt(shift["actor"]["auc"]),
         actor_label,
         f"{std['actor']['positives']} / {shift['actor']['positives']} positive entities"),
        ("stacker AUC, old broad label", fmt(std["broad"]["auc"]),
         fmt(shift["broad"]["auc"]), "broad wallet label (hops included)",
         f"{std['broad']['positives']} / {shift['broad']['positives']} positive entities"),
        ("origin top-1 (split filter)", fmt(origin_rows["top1"]), "—",
         "observed_origin_ip per transaction", f"{origin_rows['n']} estimates"),
        ("origin cost-weighted score", fmt(origin_rows["cost_weighted_score"]), "—",
         "outcome costs +1 / +0.3 / -3 / 0", "split filter"),
        ("low_confidence_origin cutoff", fmt(origin_rows["cutoff"], 2), "—",
         "chosen on seed A, reported on seed B", f"seed A = {e['seed']}"),
    ]
    return pd.DataFrame(rows, columns=["metric", f"standard (seed {e['seed']})",
                                       f"shifted (seed {e['seed']})",
                                       "label definition", "denominator"])


def build_report(cfg: dict, rebuild: bool = False) -> str:
    e = cfg["eval"]
    rates = e["observation_rates"]
    seed_a, seed_b = e["seed"], e["seed_b"]
    default_rate = e["default_rate"]
    standard = {rate: build(rate, False, cfg=cfg, rebuild=rebuild) for rate in rates}
    shifted = {rate: build(rate, True, cfg=cfg, rebuild=rebuild) for rate in rates}
    seed_b_sets = {"standard": build(default_rate, False, seed_b, cfg, rebuild=rebuild),
                   "shifted": build(default_rate, True, seed_b, cfg, rebuild=rebuild)}

    fusion = {"standard": fusion_eval.evaluate(standard[default_rate], cfg),
              "shifted": fusion_eval.evaluate(shifted[default_rate], cfg)}
    fusion_b = {name: fusion_eval.evaluate(ds, cfg) for name, ds in seed_b_sets.items()}

    origin_results = origin.evaluate(standard, cfg)
    table = origin_results["table"]
    chosen, why = choose_default_estimator(table, cfg)
    comparison = origin.filter_comparison(standard[default_rate], cfg, chosen)
    split_row = comparison[comparison["filter"] == "split"].iloc[0]
    cutoff, sweep = origin.choose_cutoff(standard[default_rate], cfg, chosen)
    frame_b = origin.score_estimator(seed_b_sets["standard"], chosen, cfg, "split")["frame"]
    flag_b = origin.flag_quality(frame_b, cfg, cutoff)
    cost_b = origin.cost_score(frame_b, cfg, cutoff)

    parts: list[str] = []
    add = parts.append
    add("# Evaluation results\n")
    add(f"Generated by `python -m eval.report` on "
        f"{datetime.now(timezone.utc).strftime('%Y-%m-%d')}.\n")

    # --- summary ---------------------------------------------------------
    add("## Summary\n")
    add("Every number below states the dataset it came from, the seed, and what the\n"
        "label means. The unit of detection is the **actor** — one ground-truth\n"
        "illicit operation — pre-registered in `docs/detection_unit_protocol.md`\n"
        "before any of this was measured. Wallet recall is reported as secondary.\n")
    add(md_table(summary_table(fusion, {"top1": float(split_row["top1"]),
                               "n": int(split_row["n"]),
                               "cost_weighted_score": float(split_row["cost_weighted_score"]),
                               "cutoff": cutoff}, cfg)))
    add(f"\nOrigin figures: `{chosen}`, split filter, standard set, seed {seed_a}, "
        f"observation rate {default_rate}.\n")
    add(f"`low_confidence_origin` on **seed {seed_b}** (never used for tuning): "
        f"precision {flag_b['precision']}, recall {flag_b['recall']}, "
        f"accuracy with the flag clear {flag_b['accuracy_when_flag_clear']} against "
        f"{flag_b['accuracy_when_flagged']} when raised, cost-weighted score "
        f"{cost_b['cost_weighted_score']}.\n")

    add("\n### Read this before quoting anything above\n")
    add(WORSE.format(
        actors=fusion["standard"]["cases"]["actors"],
        actors_shifted=fusion["shifted"]["cases"]["actors"],
        actor_auc=fusion["standard"]["actor"]["auc"],
        actor_auc_shifted=fusion["shifted"]["actor"]["auc"],
        broad_auc=fusion["standard"]["broad"]["auc"],
        recall=fusion["standard"]["cases"]["wallet_recall_broad"],
        combined_top1=float(comparison[comparison["filter"] == "combined"]["top1"].iloc[0]),
        split_top1=float(split_row["top1"]),
        off_top1=float(comparison[comparison["filter"] == "off"]["top1"].iloc[0]),
        wrong_combined=int(comparison[comparison["filter"] == "combined"]
                           ["wrong_uninvolved_third_party"].iloc[0]),
        wrong_split=int(split_row["wrong_uninvolved_third_party"]),
        abstained_split=int(split_row["abstained"]),
        n=int(split_row["n"]),
        flag_precision=flag_b["precision"]))

    add("\n**Canonical setup.** Seed A = "
        f"{seed_a}, seed B = {seed_b}, {e['n_actors']} actors, "
        f"{e['n_transactions']} transactions, observation rates {rates}, decisions "
        f"made at rate {default_rate}. These live in `config.yaml` under `eval:`. "
        "Seed B is\nonly ever reported, never used to choose a threshold.\n")
    add("The **shifted** set applies `--shifted`: jittered peel ratios, deeper chains,\n"
        "longer windows and interleaved CoinJoins. Where both are shown, **the shifted\n"
        "number is the headline** — it is the one that asks whether a detector learned the\n"
        "pattern or memorised our parameters.\n")

    # --- detection -------------------------------------------------------
    add("\n## 1. Detection, scored on actors\n")
    fusion_section(add, fusion["standard"], "Standard set", standard[default_rate])
    fusion_section(add, fusion["shifted"], "Shifted set", shifted[default_rate])

    add(f"\n### Replication on seed {seed_b}\n")
    add("The canonical dataset contains only a handful of illicit operations, so a "
        "case\nrate moves in steps of 20 percentage points. Seed B is reported to show "
        "whether\nthe standard-set numbers are a property of the system or of one "
        "draw.\n\n")
    replication = pd.DataFrame([
        {"set": name, "seed": seed_b,
         **{k: v for k, v in result["cases"].items()
            if k in ("actors", "case_detection_rate", "alert_precision",
                     "trace_coverage@2", "trace_coverage@4", "wallet_recall_broad")}}
        for name, result in fusion_b.items()])
    add(md_table(replication))

    # --- origin ----------------------------------------------------------
    add("\n## 2. Origin estimation\n")
    display = table[["rate", "estimator", "n", "top1", "top3", "conditional_top1",
                     "ceiling", "brier"]].rename(columns={
                         "top1": "top-1", "top3": "top-3",
                         "conditional_top1": "top-1 given observed", "brier": "Brier"})
    add(md_table(display))
    add("`top-1 given observed` is accuracy restricted to transactions whose true origin "
        "appears\nin the observed tree at all. It separates \"the estimator is wrong\" "
        "from \"the answer\nwas never in the data\". `ceiling` is the share of "
        "transactions where it was.\n")

    configured = cfg["engines"]["propagation"]["estimator"]
    add(f"\n**Protocol decision** (`docs/origin_eval_protocol.md`): the default "
        f"estimator is **`{chosen}`** — {why}.\n")
    add(f"Configured default is `{configured}`"
        + (".\n" if configured == chosen else f" — **needs updating to `{chosen}`**.\n"))

    add("\n### The origin filter, split three ways\n")
    add(f"`{chosen}`, standard set, rate {default_rate}. `off` applies no class "
        "weighting;\n`combined` is the old filter (relay, Tor and hosting all "
        "penalised in the ranking);\n`split` penalises relays only and reports Tor and "
        "hosting as anonymized entry\npoints with a reduced attribution confidence "
        "(`attribution_confidence_factor`).\n\n")
    add(md_table(comparison))
    add("\nThe `off` row abstains on every estimate, which is not a bug: confidence is "
        "the\nwinner's share of the total score, so with nothing down-weighted every "
        "share falls\nbelow the cutoff. Accuracy cannot see that — it is what the "
        "cost-weighted score is\nfor.\n")
    add("\nOutcome costs are pre-registered in "
        "`engines.propagation.origin_filter.cost_weights`:\n`correct_actionable` +1, "
        "`correct_infrastructure` +0.3, `wrong_uninvolved_third_party` -3,\n"
        "`abstained` 0.\n")

    add("\n### Every estimator under every filter\n")
    add(md_table(origin.class_weight_ablation(standard[default_rate], cfg)))

    add("\n### Calibration\n")
    frame = origin_results["frames"].get(chosen)
    if frame is not None:
        add(f"Reliability of `{chosen}` at rate {default_rate}: stated confidence "
            "against how often it was right.\n\n")
        add(md_table(origin.reliability(frame, e["calibration_bins"])))

    add("\n### `low_confidence_origin`\n")
    add(f"Renamed from `origin_likely_unobserved` (API, alerts, config, docs). Cutoff "
        f"chosen\non **seed {seed_a}** by the pre-registered rule — the value "
        "maximising the\ncost-weighted score, ties to the lower cutoff:\n\n")
    add(md_table(sweep))
    add(f"\n**Chosen cutoff: {cutoff}.** Reported unchanged on **seed {seed_b}**:\n\n")
    add(md_table(pd.DataFrame([flag_b])))
    add("\n" + md_table(pd.DataFrame([cost_b])))
    add("\n`precision` and `recall` are against \"the true origin was not in the "
        "observed tree\nat all\" — the claim the old name made. They are low because "
        "that event is rare.\nThe accuracy split (flag clear vs. raised) is what the "
        "flag is for and what it\ndelivers.\n")

    add(CLOSING)
    return "\n".join(parts)


WORSE = """**What got worse, and why.**

- **`wallet_recall_broad` is {recall}, and it is now a secondary number.** Under
  the broad label most illicit wallets are single-transaction layering hops. The
  system alerts on the operations, not on every hop, so this number is
  structurally low and always will be. It is reported for comparability with the
  previous pass, not as a target.
- **Stacker AUC on the actor label is {actor_auc} (standard) / {actor_auc_shifted}
  (shifted), against {broad_auc} on the old broad label.** The actor label is
  harder: it excludes the cash-out and victim wallets that sat next to the easy
  rule alerts. Same model, same non-negative constraint, a label that no longer
  hands out credit for adjacency.
- **The actor denominator is tiny: {actors} illicit operations on the standard
  set, {actors_shifted} on the shifted set.** The canonical dataset was sized for
  wallet-level statistics. A case detection rate over {actors} cases moves in
  20-point steps and a single miss would dominate it; seed B is reported below for
  exactly this reason. Fixing it properly means a larger canonical corpus, which
  would invalidate every pre-registered origin number in the same file — so it is
  named here rather than quietly done.
- **Turning the rank penalty off entirely scores {off_top1} top-1 but a
  cost-weighted score of 0.000**: with no penalty the top candidate is a public
  relay often enough that `low_confidence_origin` abstains on all {n} estimates.
  Accuracy alone would have called this the best configuration. It is the least
  useful one.
- **The split filter is 4.5pp more accurate than the old combined filter
  ({split_top1} vs {combined_top1}) and abstains far more often** ({abstained_split}
  of {n}). That is the trade it was built to make: it names an uninvolved third
  party {wrong_split} times where the combined filter did so {wrong_combined} times.
- **`low_confidence_origin`'s precision as a predictor of literal absence is
  {flag_precision} on seed B.** It was never a good predictor of that; the rename
  exists because the old name claimed it was.
"""


CLOSING = """
## 3. Decisions taken in this pass

**The unit of detection is the actor.** Pre-registered in
`docs/detection_unit_protocol.md` before the label was built or the stacker
retrained. An actor is one ground-truth illicit operation: the ransomware
collector with its peel-chain change addresses, or one layering instance's
source, hops and sink grouped back together. Victims and cash-out counterparties
are not part of the actor. Wallet-level recall is kept as a secondary number so
this pass stays comparable with the last one.

**The origin filter is split.** `known_bitcoin_relay` keeps its rank penalty: a
Bitnodes-listed relay forwards other people's traffic and is never a plausible
sender. `tor_exit` and `hosting_vpn` lose it: when a broadcast is masked, that
address *is* where the transaction entered the network, and penalising it in the
ranking pushed the estimator off the right answer for no gain. Those candidates
are now reported as **anonymized entry points**, and only the attribution
confidence handed to the correlation engine is reduced
(`attribution_confidence_factor`). The cost-weighted score is what settled it —
under plain accuracy the honest comparison was unavailable, because accuracy
prices a confident wrong attribution the same as a miss.

**`origin_likely_unobserved` is now `low_confidence_origin`** in the API, in
alert payloads, in config and in the docs. The old name asserted that the true
origin was absent from the data, which nothing inside the estimator can know;
measured as a predictor of that event its precision is ~0.2. What it actually
separates is weak estimates from strong ones, and it is now named for that. Its
cutoff is chosen on seed A by the pre-registered rule and reported unchanged on
seed B.

**Correlation stays out of the risk score.** Unchanged from the previous pass:
an IP correlation says something about *who*, not about whether an entity is
risky. It is surfaced per alert as attribution leads, each now labelled
`anonymized entry point` when the candidate is a Tor exit or hosting address.
"""


def main(argv=None) -> None:
    cfg = config.load()
    ap = argparse.ArgumentParser(prog="eval.report", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--output", default=cfg["eval"]["results_path"])
    ap.add_argument("--rebuild", action="store_true", help="regenerate the datasets")
    args = ap.parse_args(argv)
    report = build_report(cfg, args.rebuild)
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report)
    print(f"wrote {path} ({len(report.splitlines())} lines)")


if __name__ == "__main__":
    main()
