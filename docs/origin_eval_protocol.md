# Origin estimator selection protocol

**Pre-registered. Written and committed before the topology fix was made or any
post-fix numbers were seen.**

## Why this exists

The first comparison of origin estimators was run, the result was read, and the
default was then changed to match it. That is defensible once, but it is also
exactly how a result gets chosen rather than measured — especially now that we
are about to change the generator's topology in a way we expect to help the
centrality estimators specifically. Deciding the rule in advance removes the
opportunity to rationalise whichever number comes out.

## The rule

> After fixing topology realism, the default estimator is whichever has the best
> top-1 accuracy at observation rate 0.3. Ties go to `first_timestamp`.

"Tie" means a difference of less than 1 percentage point in top-1 accuracy on
the canonical evaluation dataset. `first_timestamp` wins ties because it is the
simplest estimator and the cheapest to explain to an investigator.

## What is fixed in advance

- **Dataset**: the canonical one from `config.yaml`'s `eval:` block — seed 41,
  200 actors, 1200 transactions. Stated in `eval/results.md` with every table.
- **Decision rate**: observation rate 0.3. Rates 0.1 and 0.6 are reported for
  context but do not decide the default.
- **Metric**: top-1 accuracy — the estimated origin equals the generator's
  recorded `observed_origin_ip`. Not top-3, which is nearly saturated at the
  ceiling for every estimator and therefore does not discriminate.
- **Candidates**: `first_timestamp`, `rumor_centrality`,
  `timestamp_weighted_centrality`, each with the relay/Tor/hosting class
  weighting applied, as configured.
- **Ceiling**: reported alongside, as the fraction of multi-hop transactions
  whose true origin appears anywhere in the observed tree. No estimator can
  exceed it; an estimator's share of the ceiling is the honest comparison.

## What is also reported, but does not decide

- Conditional accuracy: accuracy restricted to transactions where the origin
  was observed at all. This separates "the estimator is bad" from "the evidence
  is not there".
- Calibration: reliability curve of stated confidence against correctness, plus
  a Brier score. An estimator that is wrong but honest about it is more useful
  than one that is wrong and confident.
- Ablation with and without the relay/Tor/hosting class weighting, to show what
  that filter is worth.
- The `origin_likely_unobserved` flag's precision and recall.

## What would invalidate this

If the topology fix changes the ranking, that is the answer, not a reason to
re-open the rule. If a later change to the generator alters the result again,
the rule still applies: re-run, re-read, re-default. Any deviation must be
written into `eval/results.md` with its reason.
