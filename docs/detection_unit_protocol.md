# Detection unit protocol

**Pre-registered. Written and committed before the actor-level label was built,
the stacker retrained, or any of the numbers below were seen.**

## Why this exists

Every number this project has quoted so far has been *per wallet*: what share of
illicit-labelled wallets did we alert on. That is not what the product does and
not what an investigator asks for. A ransomware operation is one case. It owns a
collector address and a dozen change addresses in a peel chain; a layering
scheme owns a source wallet, tens of hop wallets and a sink. Wallet recall
scores a system for how many of those it enumerates, which rewards the
uninteresting half of the job (the hops are near-identical one-transaction
wallets) and says nothing about the interesting half: did we find the operation
at all, and once found, can we walk out to the rest of it.

Choosing the unit after seeing which unit flatters the numbers is how a metric
becomes marketing. So the unit is fixed here, in advance.

## The unit of detection: the actor

**An actor is one ground-truth illicit operation** — the criminal enterprise
behind one typology instance, not each address it touched.

Derived from `ground_truth.json` (`eval/actors.py`), never from anything the
pipeline produces:

- **ransomware_collector** — one actor per instance: the collector actor. Its
  wallets are the collector address plus every change address in its peel chain.
  Victims are not part of the actor (they are the complainants) and neither are
  the `cashout` counterparties, which are separate actors receiving the peel.
- **layering** — one actor per instance, identified by the originating cluster
  of that instance's `layering_split` / `layering_merge` transactions. Its
  wallets are the source, every intermediate hop wallet and the sink. The
  generator models each hop as its own `Actor` object because each needs an
  owner; in the world being simulated they are one launderer's wallets, and
  they are grouped back together here.

Patterns that are *not* actors, and why: `normal` and `exchange` are not
illicit; `same_actor_cluster` is a clustering test, not a crime; `coinjoin` is
mixing, which is suspicious but not by itself illegal (consistent with
`engines.gnn.illicit_typologies`); `ransomware_victim` and `cashout` are
counterparties of an actor, not the actor.

An **entity** (our clustering's output) is illicit **iff at least one of its
wallets belongs to an illicit actor**. That is the label the stacker is
retrained on. A wallet is **alerted** iff the entity holding it is in the final
alert list at the configured `fusion.alert_threshold`.

## Metrics

Reported per typology, on the standard and the shifted set, both at the
canonical observation rate.

1. **`case_detection_rate`** — fraction of illicit actors with at least one
   alerted wallet. *Did we find the operation?* This is the headline number.
2. **`alert_precision`** — fraction of alerts whose entity holds at least one
   wallet of any illicit actor. *Of what we put in front of an investigator, how
   much was a real case?* Alerts on victim or cash-out wallets count as
   imprecise here even though they are adjacent to crime; adjacency is what
   taint reports, not what an alert claims.
3. **`trace_coverage@N`**, N = 2 and 4 — for each *detected* actor, start from
   its alerted wallets and walk the entity graph outward as taint does
   (`fusion.taint`'s direction and hop budget), N hops. Score the fraction of
   that actor's *other* wallets that are reached. *Once we have one thread, how
   much of the operation can we pull in?* Undetected actors are excluded — this
   measures expansion, not detection, and averaging a zero over cases we never
   found would confound the two.
4. **`wallet_recall_broad`** — the old metric, kept as **secondary**: recall over
   every wallet of every illicit-patterned cluster including pass-through hops,
   under the broad label. Reported so this pass is comparable with the previous
   one, not because it is what the product optimises.

Precision has no actor-level denominator by design: an alert is a unit of an
investigator's attention, so it is counted per alert.

## Origin attribution: outcomes and costs

Accuracy treats every origin error alike. It is not alike: naming a public relay
operator's address as a suspect's is a different kind of wrong from having no
answer. Each non-degraded origin estimate falls into exactly one outcome, and
the score is the mean weight (`engines.propagation.origin_filter.cost_weights`,
defaults below):

| outcome | when | weight |
| --- | --- | --- |
| `correct_actionable` | not abstained, correct, and the named address is residential/unclassified — a lead an ISP request can act on | +1 |
| `correct_infrastructure` | not abstained, correct, but the address is a Tor exit, hosting/VPN or relay — a true *anonymized entry point*, worth recording, not directly actionable | +0.3 |
| `wrong_uninvolved_third_party` | not abstained and wrong — we named an address that did not send the transaction | -3 |
| `abstained` | `low_confidence_origin` is set: we declined to name anyone | 0 |

The asymmetry is the point: abstaining is free, being wrong out loud is three
times as costly as being right is valuable.

Three filter configurations are reported side by side, on the same data:
`off` (no class weighting), `combined` (the old filter: relay, Tor and hosting
all penalised in the ranking) and `split` (relay penalised in the ranking; Tor
and hosting not penalised, but reported as an anonymized entry point with a
reduced *attribution* confidence handed to the correlation engine). The split
exists because a masked broadcast genuinely does originate at the Tor exit or
hosting address — penalising it in the ranking pushes the estimator off the
right answer — whereas a Bitnodes-listed relay forwards other people's traffic
and is never the sender.

## `low_confidence_origin`

The flag formerly named `origin_likely_unobserved`. It was renamed because the
name asserted something it cannot know — that the true origin is absent from the
data — while what it actually measures is that this estimate is weak. It is now
called what it is, everywhere: API, alerts, config, docs.

**Cutoff selection rule, fixed here in advance:**

> The confidence cutoff is chosen on **seed A** (`eval.seed`, 41) as the value in
> {0.10, 0.15, … 0.90} maximising the cost-weighted origin score above, under
> the split filter, at the canonical observation rate. Ties go to the lower
> cutoff, which abstains less. The chosen value is then reported **unchanged**
> on **seed B** (`eval.seed_b`, 43), together with the flag's precision, recall
> and the accuracy split (accuracy with the flag clear vs. raised).

Seed B is never used to choose anything. If the seed B numbers are worse than
seed A's, that difference is the honest estimate of the selection bias, and it
gets written down rather than tuned away.

## Datasets

Unchanged from `docs/origin_eval_protocol.md`: the canonical `eval:` block in
`config.yaml` — 200 actors, 1200 transactions, observation rates 0.1 / 0.3 /
0.6, decisions at 0.3. Every table states its dataset (standard or shifted),
its seed and its label definition. The shifted set is the headline wherever
both are shown.

## What would invalidate this

If the actor-level numbers come out worse than the wallet-level ones, that is
the answer, and both go in the report. Any deviation from this document must be
written into `eval/results.md` with its reason.
