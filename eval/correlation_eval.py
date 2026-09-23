"""What the correlation engine claims, measured as that claim.

Correlation is deliberately absent from the stacker (`fusion.stacker.signals`):
an IP link says something about **who** an entity might be, not about **how
risky** it is. Adding it as a fifth signal and reporting the AUC delta would be
measuring the wrong thing twice over — it would ask whether attribution
predicts criminality, which is not what the engine is for and not a question
anybody should want answered in the affirmative.

So this measures the claim the engine actually makes. Each alert carries up to
`fusion.leads_per_entity` attribution leads: "this entity was seen broadcasting
from this address, with this confidence." The honest test is how often a lead
names an address the entity really did broadcast from, and whether the score
attached to it means anything — a high-scored lead should be right more often
than a low-scored one, or the score is decoration.

**The ceiling.** An entity's *true* broadcast address is only nameable if it was
ever observed. A transaction sent over Tor enters the network at the exit node:
the true origin is not in the data at all, and no correlation engine can recover
it. That share is reported as its own column, the same way the origin table
reports its observability ceiling, so a miss caused by absent evidence is not
read as a miss caused by a bad estimator.
"""

from __future__ import annotations

import pandas as pd

from fusion.pipeline import attribution_leads
from graph.builder import iter_transactions

from .datasets import Dataset

#: Score bands. Chosen to straddle the values README quotes (≥0.4 and <0.2) so
#: that claim can be checked against this table rather than against a memory.
BUCKETS = [0.0, 0.2, 0.4, 0.6, 0.8, 1.01]
LABELS = ["0.0–0.2", "0.2–0.4", "0.4–0.6", "0.6–0.8", "0.8–1.0"]


def broadcast_truth(dataset: Dataset, entity_of) -> tuple[dict[str, set[str]],
                                                          dict[str, set[str]]]:
    """Per entity: the addresses it really broadcast from, true and observed.

    `true` is the actor's own address — what an attribution would have to name
    to be right. `observed` is where the broadcast entered the network, which is
    the same address unless the actor masked it.
    """
    gt = dataset.ground_truth()
    meta = gt["transactions"]
    true: dict[str, set[str]] = {}
    observed: dict[str, set[str]] = {}
    for tx in iter_transactions(dataset.frame()):
        record = meta.get(tx.txid)
        if not record:
            continue
        # The entity that spent the inputs is the one that broadcast.
        senders = {entity_of(a) for a in tx.input_addresses} - {None}
        for entity in senders:
            if record.get("true_origin_ip"):
                true.setdefault(entity, set()).add(record["true_origin_ip"])
            if record.get("observed_origin_ip"):
                observed.setdefault(entity, set()).add(record["observed_origin_ip"])
    return true, observed


def score_links(links: pd.DataFrame, true: dict, observed: dict) -> pd.DataFrame:
    """Mark every link right or wrong against both definitions."""
    if links is None or links.empty:
        return pd.DataFrame()
    rows = links.copy()
    rows["names_true_ip"] = [ip in true.get(entity, set())
                             for entity, ip in zip(rows["entity_id"], rows["ip"])]
    rows["names_observed_ip"] = [ip in observed.get(entity, set())
                                 for entity, ip in zip(rows["entity_id"], rows["ip"])]
    # Could this entity's true address have been named at all? If the actor only
    # ever broadcast through a Tor exit, no.
    rows["true_ip_observable"] = [
        bool(true.get(entity, set()) & observed.get(entity, set()))
        for entity in rows["entity_id"]]
    return rows


def by_score(rows: pd.DataFrame) -> pd.DataFrame:
    """Lead precision per score band — the table the engine lives or dies by."""
    if rows.empty:
        return pd.DataFrame(columns=["score band", "links"])
    banded = pd.cut(rows["final_score"], BUCKETS, labels=LABELS, right=False,
                    include_lowest=True)
    grouped = rows.groupby(banded, observed=True)
    out = pd.DataFrame({
        "score band": [str(b) for b in grouped.groups],
        "links": grouped.size().values,
        "names the true IP": grouped["names_true_ip"].mean().round(3).values,
        "names the observed IP": grouped["names_observed_ip"].mean().round(3).values,
        "true IP observable": grouped["true_ip_observable"].mean().round(3).values,
    })
    return out.sort_values("score band", ignore_index=True)


def by_observations(rows: pd.DataFrame) -> pd.DataFrame:
    """Precision by how many distinct transactions the link rests on."""
    if rows.empty:
        return pd.DataFrame(columns=["observations", "links"])
    bins = [1, 2, 3, 5, 10, 10_000]
    labels = ["1", "2", "3–4", "5–9", "10+"]
    banded = pd.cut(rows["observation_count"], bins, labels=labels, right=False)
    grouped = rows.groupby(banded, observed=True)
    return pd.DataFrame({
        "observations": [str(b) for b in grouped.groups],
        "links": grouped.size().values,
        "names the true IP": grouped["names_true_ip"].mean().round(3).values,
        "names the observed IP": grouped["names_observed_ip"].mean().round(3).values,
    })


def leads_shown(bundle: dict, alerted: set[str], cfg: dict, true: dict,
                observed: dict) -> pd.DataFrame:
    """Only the leads an analyst is actually shown, beside an alert.

    The whole link table includes everything the engine scored; this is the
    top-k per alerted entity that reaches the screen, which is the population
    the claim is about.
    """
    leads = attribution_leads(bundle["links"], cfg)
    rows = []
    for entity in sorted(alerted):
        for rank, lead in enumerate(leads.get(entity, []), 1):
            rows.append({
                "entity_id": entity, "ip": lead["ip"], "rank": rank,
                "final_score": lead["confidence"],
                "observation_count": lead["observations"],
                "anonymized_entry_point": lead["anonymized_entry_point"],
                "names_true_ip": lead["ip"] in true.get(entity, set()),
                "names_observed_ip": lead["ip"] in observed.get(entity, set()),
                "true_ip_observable": bool(true.get(entity, set())
                                           & observed.get(entity, set())),
            })
    return pd.DataFrame(rows)


def by_rank(shown: pd.DataFrame) -> pd.DataFrame:
    """Does the ordering mean anything? Rank 1 should beat rank 3."""
    if shown.empty:
        return pd.DataFrame(columns=["rank", "leads"])
    grouped = shown.groupby("rank", observed=True)
    return pd.DataFrame({
        "rank": list(grouped.groups),
        "leads": grouped.size().values,
        "names the true IP": grouped["names_true_ip"].mean().round(3).values,
        "names the observed IP": grouped["names_observed_ip"].mean().round(3).values,
    })


def evaluate(dataset: Dataset, bundle: dict, alerted: set[str], cfg: dict) -> dict:
    """Everything above, for one dataset."""
    entity_of = bundle["features"].entity_of
    true, observed = broadcast_truth(dataset, entity_of)
    rows = score_links(bundle["links"], true, observed)
    shown = leads_shown(bundle, alerted, cfg, true, observed)

    summary = {
        "links": int(len(rows)),
        "entities_with_a_link": int(rows["entity_id"].nunique()) if len(rows) else 0,
        "leads_shown": int(len(shown)),
        "alerts_with_a_lead": int(shown["entity_id"].nunique()) if len(shown) else 0,
        "leads_naming_the_true_ip": round(float(shown["names_true_ip"].mean()), 3)
        if len(shown) else None,
        "leads_naming_the_observed_ip": round(float(shown["names_observed_ip"].mean()), 3)
        if len(shown) else None,
        "true_ip_observable": round(float(shown["true_ip_observable"].mean()), 3)
        if len(shown) else None,
    }
    return {"summary": summary, "by_score": by_score(rows),
            "by_observations": by_observations(rows),
            "shown_by_score": by_score(shown), "by_rank": by_rank(shown)}
