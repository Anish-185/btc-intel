# Construction fingerprints

`features/fingerprint.py` estimates which **construction pattern** built a
transaction, using only its on-chain structure. The output is a ranked label
set with calibrated confidences, or `unknown`.

**The label describes how the transaction was built, not which software built
it.** Every surface that shows a label says so. "Core-like construction" means
the transaction's structure matches what this system models for Bitcoin
Core's wallet defaults. It does not mean Bitcoin Core built it, and it says
nothing about a person or an organisation.
Many unrelated parties run the same software, and one party can run several
wallets.

**Everything measured here is simulated.** The profiles below are this
simulator's stand-ins for the families they are named after. The classifier
is fitted to those profiles and scored on them. Its accuracy therefore
measures how well it recovers the simulator's own construction rules, not how
well it would identify real software. Results are in section 12 of
`eval/results.md`.

## Labels

| label | written as | what it stands for |
| --- | --- | --- |
| `core_like` | Core-like construction | a full-node wallet's defaults as modelled here |
| `electrum_like` | Electrum-like construction | a light wallet's defaults as modelled here |
| `legacy_naive` | legacy/naive construction | v1, no locktime, fixed fees, address reuse |
| `coordinator_coinjoin` | coordinator CoinJoin shape | a coordinated equal-denomination mix (Wasabi/Whirlpool-style) |
| `batch_withdrawal` | batch-withdrawal shape | many payees and one change output in one transaction: a pattern, not a product |
| `unknown` | unknown construction | too few tells, ambiguous between patterns, or unlike every trained pattern (novelty check) |

The keys are the generator's profile names and stay as they are; what a
reader sees is the right-hand column (Open-set revision, §2).

## The tells

For each tell: what it reads, what it indicates, which families show it, and
where it is ambiguous. Software claims are marked **documented** (in a BIP, in
consensus rules, or in the software's own source or release notes, without
tying the claim to a particular version) or **assumption** (this simulation's
choice, reported elsewhere or plausible but not verified here). No claim below
is tied to a specific release.

| tell | reads | indicates | families (as modelled) | basis | ambiguous when |
| --- | --- | --- | --- | --- | --- |
| `version` | tx version: v1, v2, other | v2 is required for BIP-68 relative locktimes, so modern wallets build v2 | core, electrum: v2. legacy: mostly v1. coordinator and batch: mixed | **documented**: BIP-68 needs v2; Bitcoin Core's wallet builds v2 transactions (its default in source). **assumption**: the other families' versions | most modern software builds v2, so v2 alone separates little; v1 is the informative value |
| `locktime` | nLockTime: zero, height (< 500,000,000), time | anti-fee-sniping: setting nLockTime to the current height so a reorg miner cannot include the transaction earlier | core, electrum: height. legacy, coordinator: zero. batch: mostly zero | **documented**: Bitcoin Core's wallet sets nLockTime to the tip height to discourage fee sniping, and occasionally to a height further back (its source describes this). The 10% chance of going up to 100 blocks back used here follows that description and should be checked against the source before relying on it. **assumption**: Electrum does the same | a height locktime is shared by several families. This tell does not check that the height is near the chain tip at broadcast, because the relay-log schema has no tip height |
| `sequence` | nSequence across inputs: `rbf` (≤ 0xFFFFFFFD), `locktime_only` (0xFFFFFFFE), `final` (0xFFFFFFFF), mixed | BIP-125 opt-in RBF signalling; 0xFFFFFFFE enables nLockTime without signalling RBF | core, electrum: mostly rbf. legacy, coordinator: final. batch: mostly final | **documented**: BIP-125 signalling; nLockTime is enforced only if some input is non-final (consensus). Bitcoin Core's `-walletrbf` option controls RBF signalling, and its default has differed across releases (release notes). **assumption**: the per-family rates | users toggle RBF, so any family can show either value |
| `ordering` | BIP-69: inputs by outpoint (prev txid, vout), outputs by amount then scriptPubKey | a wallet that sorts deterministically, so ordering leaks nothing about which output is change | electrum: mostly sorted. core, legacy: not. coordinator: sometimes | **documented**: BIP-69 defines the order; Bitcoin Core's wallet does not implement it and places change at a random position (its source). **assumption**: that Electrum sorts per BIP-69 (widely reported; may differ between versions) | two outputs in random order are sorted half the time, so it is weak evidence on small transactions. With no outpoints (relay logs), only outputs are checked, and the address stands in for the scriptPubKey on tied amounts, which is an approximation |
| `change_position` | first, middle or last, for an identifiable change output | a fixed change position (legacy: last) versus a randomised one | legacy: last. batch: mostly last. core, electrum: random | **documented** for Core (random position, above). **assumption** for the others | change is identifiable only structurally: a reused input address, the one output outside an equal-value group, or the one output sharing the inputs' script type. If none of these applies, there is no tell |
| `fee` | `round_btc` (a multiple of 10,000 sat), `round_rate` (a multiple of 5 sat/vB), `integer_rate`, `fractional_rate` | how the fee was chosen: typed as an amount, a round rate, an integer rate, or an estimator's fractional output | legacy: round BTC. batch: round rate. electrum: mostly integer. core, coordinator: mostly fractional | **assumption** for every family. vsize is the standard single-key estimate (`INPUT_WU`/`OUTPUT_WU`) | on real data vsize is an estimate off by a few vbytes, so an integer rate rarely lands exactly on an integer. This tell is much weaker on real data than here, where the generator uses the same size table |
| `script_mix` | the inputs' script type, or mixed | the address types a wallet generates | core: p2wpkh/p2tr. electrum: p2wpkh/p2sh. legacy: p2pkh/p2sh. coordinator: p2wpkh/p2tr | **assumption** (the mixes are this simulation's) | modern wallets overlap heavily |
| `change_type` | `reuse_input` (change paid back to an input address), `same_type`, `other_type` | address reuse, and whether change matches the inputs' script type | legacy: often reuses. Others: same type | **documented**: Bitcoin Core has a `-changetype` option. **assumption**: that its default matches the inputs; the real rule is more involved | with change found by the type rule, `same_type` holds by construction. The tell carries information only when change was found structurally |
| `io_shape` | input-count bucket × output-count bucket | the transaction's structure | coordinator: many × many. batch: several × many. payments: few × 2 | a structural pattern, not a software claim | payments from every family share it |
| `batching` | `equal_group` (≥ 3 equal outputs), `many_outputs` (≥ 5), `simple` | a mix or an equal-amount batch; a batch; an ordinary spend | coordinator and batch: equal_group | a structural pattern | an equal-amount batch payout looks like a mix. This is the same confounder the validity layer's COINJOIN detector has |

A tell that the data cannot show (no version field, one output) is left out
of the evidence and never counted as a vote.

## The classifier

* **Model.** Categorical naive Bayes over the observable tells, with Laplace
  smoothing, fitted on the fingerprint corpus's training captures. Naive Bayes
  assumes the tells are independent given the family. They are not (a v2
  transaction usually also carries a height locktime), so the raw posterior is
  overconfident.
* **Calibration.** One isotonic map per condition, pooled one-vs-rest over the
  labels and fitted on the calibration captures. That map is what gives the
  confidence its meaning. There are two conditions:
  * `full`: the tells a raw transaction shows.
  * `structural`: version, nLockTime and nSequence masked. This is what a
    relay log in the NTRO schema carries.

  A transaction is calibrated under the condition it actually shows, because a
  structure-only guess is a different and weaker measurement.
* **Unknown.** The answer is `unknown` in two cases:
  * The top calibrated confidence is under
    `features.fingerprint.unknown_below` (0.6). At 0.6 a named family is right
    at least 1.5 times as often as it is wrong on the calibration captures;
    below that, naming it points an analyst at a family more often wrongly
    than the margin justifies.
  * Fewer than `min_tells` (4) tells are observable.

  Both values were fixed before the first evaluation and not tuned on a test
  capture.
* **Output.** The label, its confidence, the ranked alternatives with their
  calibrated confidences and raw posteriors, the tells observed, the
  condition, and why an answer is `unknown`.

## Generator

`generator/wallets.py` builds a transaction under a profile, using the
probability maps in `config.yaml` under `generator.wallet_profiles`. Two
paths use it:

* **The corpus.** `origination/manifest_fingerprint.json` is the validity
  manifest plus a `fingerprint` block. CoinJoin shapes are
  `coordinator_coinjoin` and batch shapes are `batch_withdrawal`. A payment
  takes its sender's profile, drawn once per sender from `payment_mix`.
  `truth.parquet` records `wallet_profile`, `tx_version`, `locktime`,
  `sequences`, `outpoints`, `fee` and `change_indices`.
* **`generator.main --wallet-profiles`.** Each actor's transactions are
  rebuilt under its profile and a CoinJoin under the coordinator's. The
  construction columns are written to CSV, JSON and XML, and
  `ground_truth.json` records `wallet_profile` per transaction. The batch
  profile does not arise on this path, because its typologies never build a
  batch. An ordinary payment gets every tell. A typology transaction (peel
  chain, layering, collector payments, CoinJoin) gets only the tells that move
  no amount and rename no chained address: version, nLockTime, nSequence and
  input/output order (a hop spends an address, not an output index), plus the
  input script type when its inputs are one-off wallets no other transaction
  touches. Fee rounding, dust dropping and paying change back to an input are
  skipped: the next hop spends those outputs. `ground_truth.json` records per
  transaction `wallet_tells.applied` and `wallet_tells.skipped` (tell → why).
  The typology's peel chains are therefore detected exactly as on the
  unprofiled dataset; `tests/test_fingerprint.py` checks it on a seed where
  rebuilding every transaction in full used to break chains. Ordinary
  payments still get fee and change tells, so a run of them that only looked
  peel-shaped by chance may not be flagged (on the demo dataset, 2 such
  three-payment look-alikes of 9 peel alerts).

**Off means untouched.** Every profile draw comes from a random stream of its
own. With profiles off, generator files and corpus captures are
byte-identical to the committed code's output. The hashes are pinned in
`tests/test_fingerprint.py`, taken from the pre-profile commit in a separate
worktree. The profile config enters a corpus digest only for a fingerprint
manifest, so the cached base and validity corpora keep their identity.

Ingest carries `tx_version`, `locktime`, `input_sequences` and
`input_outpoints` as optional columns. They are present only when the dataset
has them, so a dataset without them ingests to exactly the columns it always
did.

## Clustering: corroboration only

`graph.clustering.corroborate` compares, for every union the heuristics made,
the confident fingerprints of the transactions that spend the merged wallets.
Only confident, in-distribution labels take part: a transaction answered
`unknown`, whether ambiguous, short of tells, or out of distribution, has no
effect. If two different patterns appear, the union is kept but its confidence is
multiplied by `graph.fingerprint.mismatch_factor` (0.5). A cluster's
confidence is its least confident merge. Mismatches are listed under
`conflicts`.

A fingerprint **never creates a merge**. `corroborate` reads the list of
merges and changes no union. The tests check this in both directions:

* a mismatch lowers a merge and keeps it;
* matching fingerprints on wallets never spent together leave them apart;
* on a generated dataset, the model's labels and an adversarial assignment
  both leave every cluster identical.

## Surfaces

* **Console display**: off by default (`features.fingerprint.console_display`;
  see the display rule under "Open-set revision"). Each surface below then shows
  a notice in place of fingerprints. The API answers either way, and each answer
  carries `statement` and `console_display`.
* **TXID page**: `GET /transactions/{txid}/fingerprint`, shown as a panel with
  the label, confidence, ranked alternatives, the tells, the condition and
  the statement. An `unknown` answer gives its reason, including the novelty
  score against its threshold.
* **Entity page**: the fingerprint distribution of the transactions spending
  the entity's wallets, the cluster's merge confidence, and any conflicts.
* **Peer profile**: the distribution among the transactions the peer is named
  origin of. Origination-model claims and `engines.propagation` origins are
  shown separately, and transactions whose structure is not in the chain data
  are counted rather than guessed.

## CoinJoin agreement

The `coordinator_coinjoin` label is compared with the validity layer's COINJOIN
detector on every test transaction. The agreement rate is reported, and the
disagreements are broken down by true profile and by what the fingerprint
said. The two are **not reconciled**:

* The validity verdict governs what an origin answer may claim
  (docs/VALIDITY.md).
* The fingerprint is shown beside it.

The main disagreement is the detector's documented batch-payout false
positive, which the fingerprint usually names correctly. The other
disagreement runs the other way: CoinJoin rounds in which few participants
took change look like batches to the fingerprint, and the detector catches
them.

## Limits

* All accuracy is simulated, and the classifier is fitted to the profiles it
  is scored on. The transfer check in section 12 (the same model on the
  generator's own typologies) shows how much accuracy falls under a shift
  inside the simulator. Real software will shift further.
* **Unseen constructions are often still named.** Leave-one-profile-out (§12
  of `eval/results.md`) fits on four profiles and asks about the fifth. With
  the novelty check, 0.336 of held-out transactions (all tells; 0.315
  structure only) still get a known pattern whose defining tells they
  contradict, down from 0.804 in P8.1. Most of what remains is Core-like and
  Electrum-like constructions standing in for each other: their profiles
  share most tells, and the novelty check cannot tell one from a variant of
  the other. Fingerprints are therefore off in the console by default.
* On real data, fee-rate tells depend on an estimated vsize, BIP-69 output
  order uses addresses in place of scriptPubKeys, and relay logs lack
  version, locktime, nSequence and outpoints. The `structural` condition
  covers the last of these.
* The served demo dataset is generated with `--wallet-profiles` (seed 41 plus
  its recorded red-team injections, which `generator.inject` profiles too), so
  its transactions carry the `full` tells. Its fingerprints recover the
  simulator's profiles, not real wallets. On it, 601 of 1247 are unknown
  (564 of them out of distribution to the corpus-trained model) and 0.853 are
  right when answered. The generator's transactions differ from the corpus's
  shapes, and typology transactions carry fewer tells than ordinary payments.

## Open-set revision

*Pre-registered on 2026-09-26, committed before any novelty-detection code was
written or any revised figure computed. The P8.1 figures below are the only
LOPO results seen so far. Later changes to this section are marked as
amendments; nothing here is edited to fit a result.*

### Why

P8.1's leave-one-profile-out evaluation (§12 of `eval/results.md`) fits the
classifier on four profiles and asks about the fifth. Pooled over the five
hold-outs, 0.948 of held-out transactions got a known family's name with all
tells and 0.994 with structure only. The only abstention rules were ambiguity
between known families (calibrated confidence under 0.6) and too few tells
(under 4). Naive Bayes posteriors are relative: they say which known family
explains a transaction least badly, never whether any of them explains it.

P8.1 LOPO, kept as the baseline (cross-topology test rows of the held-out
profile; the model fitted and calibrated without it):

| held-out profile | condition | transactions | unknown | confidently mislabelled | confident-mislabel rate |
| --- | --- | --- | --- | --- | --- |
| core_like | full | 7909 | 0 | 7909 | 1.000 |
| core_like | structural | 7909 | 0 | 7909 | 1.000 |
| electrum_like | full | 5659 | 0 | 5659 | 1.000 |
| electrum_like | structural | 5659 | 0 | 5659 | 1.000 |
| legacy_naive | full | 4544 | 1131 | 3413 | 0.751 |
| legacy_naive | structural | 4544 | 138 | 4406 | 0.970 |
| coordinator_coinjoin | full | 1602 | 0 | 1602 | 1.000 |
| coordinator_coinjoin | structural | 1602 | 0 | 1602 | 1.000 |
| batch_withdrawal | full | 2044 | 7 | 2037 | 0.997 |
| batch_withdrawal | structural | 2044 | 0 | 2044 | 1.000 |
| all (pooled) | full | 21758 | 1138 | 20620 | 0.948 |
| all (pooled) | structural | 21758 | 138 | 21620 | 0.994 |

### 1. The novelty detector

**Score: the named family's worst-supported tell.** Let ŷ be the family the
classifier ranks first. For each observed tell t with value v, the surprisal
is `-log p(v | ŷ)`. Here `p` is the classifier's own Laplace-smoothed
per-family frequency from the training rows, with an unseen value counted as
one extra category. The novelty score is the largest surprisal over the
observed tells:

    s(x) = max_t  -log p(x_t | ŷ)

**Why this one.** It is a per-family distance to training support: it asks
whether the family we are about to name ever produces every tell this
transaction shows. A different construction shows up as one or two tells
the named family essentially never produces: another fee policy, a script
type it never spends, BIP-69 order from a wallet that never sorts. A maximum
catches that single tell; the joint likelihood would average it away among
the ordinary tells. The joint likelihood also shrinks with the number of
observed tells, so one threshold could not serve both the full and the
structural condition. The score is checked against the family being named,
not the best-fitting one, because the question is whether *this label* is
supported. It needs nothing but the fitted counts, so it adds no model and no
dependency.

**Fitted on training profiles only.** The per-family frequencies come from
the training rows of the profiles the model knows. In a LOPO fold, the
held-out profile appears in neither the counts nor the threshold's
validation rows.

**Threshold-selection rule, fixed now.** θ is set separately for each
condition (`full`, `structural`, each on its own view of the rows). It is
the 99th percentile of `s` over the validation split, which is the
`calibration`-role rows of the known profiles: the same rows the isotonic
maps are fitted on, and never test rows. A transaction is novel if
`s(x) > θ`. The target is fixed at no more than 1% of in-distribution
validation transactions flagged novel. It is chosen for its in-distribution
cost and will not be moved after any LOPO or test result is seen. θ is
stored in the model file with the fitted counts.

**Decision.** The answer is `unknown` if the transaction is novel, OR if
calibrated confidence is under `unknown_below` (0.6, unchanged), OR if it
shows fewer than `min_tells` (4, unchanged). The answer states which of the
three applied.

### 2. Vocabulary

The labels describe how a transaction was built, not which software built it.
What a reader sees changes to:

| key (unchanged) | label shown |
| --- | --- |
| `core_like` | Core-like construction |
| `electrum_like` | Electrum-like construction |
| `legacy_naive` | legacy/naive construction |
| `coordinator_coinjoin` | coordinator CoinJoin shape |
| `batch_withdrawal` | batch-withdrawal shape |

The keys stay as they are. They are the generator's profile names, and
renaming them would change every cached corpus's identity and the ground truth
format for no change in meaning. Every surface that shows a label (the API
answer, the TXID page, the entity page, peer profiles, this document) also
carries one statement: *the label describes how the transaction was built,
not which software built it.*

### 3. Scoring held-out profiles

Each held-out transaction lands in exactly one of three outcomes:

1. **unknown**: the right answer for a construction never seen.
2. **shared pattern**: labelled with a known pattern K whose defining tells it
   genuinely shows.
3. **harmful mislabel**: labelled with a known pattern K while contradicting
   at least one of K's defining tells.

**Defining tells**, from data the model is allowed to see: a (tell, value) pair
is defining for K if, among K's training rows where the tell is observed, that
value occurs in at least 80% of them. The fold that holds a profile out
computes K's defining tells from K's own training rows only.

**Shares.** A transaction labelled K shares K's pattern if, for every defining
tell of K that the transaction observes, it shows K's defining value. It must
observe at least one of them. Otherwise, or on any contradiction, the label is
a harmful mislabel. The test uses only the generated tells and the training
frequencies, never the classifier's scores or the novelty score, so it grades
the decision independently. (A "shares" rule based on the model's own
likelihood would pass anything the novelty check passed.)

**Headline:** the pooled harmful-mislabel rate, with all tells. It is reported
beside the structural rate, per held-out profile, and beside P8.1's model
scored by the same three outcomes.

### 4. Downstream

A fingerprint mismatch lowers a merge's confidence only when both sides are
confident, in-distribution labels. A side answered `unknown`, for any of the
three reasons, has no effect.

### 5. What gets reported, and what follows

§12 gets the revised LOPO table beside P8.1's, plus the in-distribution cost
of the novelty check: accuracy when answered and the unknown rate on the
known-profile test sets, with and without it.

**Display rule, fixed now.** If the pooled harmful-mislabel rate with all
tells is above 0.10, the console's fingerprint display goes behind a config
flag, `features.fingerprint.console_display`, defaulting to off. §12 then
says so plainly. The API keeps answering either way, since what is computed
is not in question, only whether a reader sees it by default.

### Result (appended after the pre-registered run; nothing above was changed)

The first run under the rules above, `python -m eval.report` (§12):

| pooled over five hold-outs | unknown | shared pattern | harmful mislabel |
| --- | --- | --- | --- |
| P8.1, all tells | 0.052 | 0.144 | 0.804 |
| open-set, all tells | 0.574 | 0.090 | **0.336** |
| P8.1, structure only | 0.006 | 0.160 | 0.833 |
| open-set, structure only | 0.578 | 0.108 | 0.315 |

The P8.1 rows reproduce P8.1's unknown counts exactly (1138 and 138 of
21758), so the baseline is the same model and rule scored three ways. Where
the novelty check works, it works well: held-out legacy/naive goes to 0.999
unknown and held-out CoinJoin to 0.936. Where it does not: held-out Core-like
is harmfully named Electrum-like 0.455 of the time, held-out Electrum-like
is harmfully named Core-like 0.560 of the time, and held-out batch
withdrawals are called CoinJoins 0.264 of the time. Cost on known profiles
(cross-topology, all tells): unknown 0.060 → 0.070, accuracy when answered
unchanged at 0.976.

**The harmful-mislabel rate, 0.336, is above the pre-registered 0.10.** Per
the display rule, `features.fingerprint.console_display` stays `false`: the
console shows a notice in place of fingerprints, and the API still answers.

