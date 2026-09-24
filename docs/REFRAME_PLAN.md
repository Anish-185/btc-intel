# Reframe plan — origination classification as the primary ML task

Status: **plan only, no code written.** Written after a full read of the repo at
commit `HEAD` on 2026-09-24.

## 0. Two corrections to the framing, before the plan

**There is no Elliptic++ classifier in this repo.** `grep -ri elliptic` hits
`docs/vendor_notes.md` (a read-only review of a vendored reference repo) and two
docstrings in `engines/gnn/`. Nothing loads Elliptic data, features or labels.
The thing currently occupying the "is this illicit?" slot is three engines over
*our own synthetic labels*: `engines/rules/` (deterministic, unlabelled),
`engines/anomaly/` (unsupervised), `engines/gnn/` (supervised on
`generator/`'s ground truth). So "demote Elliptic++ to a secondary evidence
channel" resolves to: demote `engines/gnn/` + `fusion/stacker.py`'s composite
from headline to evidence channel. If an actual Elliptic++ channel is wanted, it
is new work, not a demotion, and it will not run air-gapped without the dataset
shipped in the bundle (~1 GB). Flagged, not assumed.

**Origin estimation already exists and is measured.** `engines/propagation/`
rebuilds a per-txid propagation tree from relay records and ranks candidate
origin IPs with three published estimators, with a pre-registered protocol
(`docs/origin_eval_protocol.md`), a measured ceiling, cost weights, an
abstention flag and an eval section. What does **not** exist is the thing this
reframe actually asks for:

| exists today | this reframe needs |
| --- | --- |
| unsupervised *ranking* of IPs within one txid | supervised *binary classifier* on a `(txid, peer_ip)` pair |
| one output row per txid | one output row per observed relay record |
| heuristic confidence (`share × (1-e^-n/3)`) | a calibrated probability with reliability curve |
| scored by top-1 accuracy against a ceiling | scored by PR-AUC, ECE, and cost-weighted abstention |

The lazy path is therefore **not** a new estimator. It is: keep the three
estimators and make their scores *features* of a supervised per-peer model. The
tree builder, the IP intelligence, the cost weights and the abstention
discipline are all reused as-is.

## 1. Module-by-module disposition

`KEEP` = untouched. `EXTEND` = additive change, existing callers unaffected.
`DEMOTE` = code unchanged, its position in the narrative and the UI changes.
`REPLACE` = superseded.

### Ingest / data
| Module | Verdict | Why |
| --- | --- | --- |
| `generator/net.py` | **EXTEND** | The gossip simulator is the only source of labelled origin/forward pairs anywhere in this project, and it already records `true_origin_ip` *and* `observed_origin_ip` per txid in `ground_truth.json`. Needs one addition: per-hop provenance (was this hop the originator's first announcement, or a forward), so labels are exact rather than derived by IP equality. |
| `generator/typologies.py`, `inject.py`, `writers.py`, `main.py` | **KEEP** | Typologies are blockchain-shaped; origination is network-shaped. Orthogonal. |
| `ingest/parsers.py`, `schema.py`, `pipeline.py` | **KEEP** | `RawTransaction` already carries `src_ip`, `dst_ip`, `src_port`, `dst_port`, `timestamp` per relay record — the exact grain the new model needs. No schema change. Crucially, ingest already *preserves* the multi-row relay structure (4565 rows / 1247 txids in the current processed set); only `graph/builder.iter_transactions` collapses it. |
| `ingest/geoip.py`, `ingest/ip_intel.py` | **KEEP** | `IpIntel.classify()` → four classes with evidence is the single most useful feature the new model has. Used as-is. |

### The origin work that already exists
| Module | Verdict | Why |
| --- | --- | --- |
| `engines/propagation/tree.py` | **KEEP** | `build_trees()` is the grain conversion the new feature extractor needs. `PropagationTree.undirected_tree()`, `first_seen`, `earliest()` all reused verbatim. |
| `engines/propagation/estimators.py` | **KEEP, reposition** | The three estimators become **feature generators**, not competing predictors. `first_timestamp`, `rumor_centrality` and `timestamp_weighted_centrality` each produce a per-IP score; those three numbers become three columns of the new feature table. `apply_class_weights`, `is_anonymized_entry`, `attribution_confidence_of`, `confidence_of`, `low_confidence_origin` all keep their current callers and their current meaning. |
| `engines/propagation/pipeline.py` | **KEEP** | Still writes `tx_origins.parquet`. The new pipeline writes a *different* file; nothing reads across. |
| `eval/origin.py`, `docs/origin_eval_protocol.md`, `docs/detection_unit_protocol.md` | **EXTEND** | The ceiling, the two denominators, the four outcome classes and the pre-registered `cost_weights` apply unchanged to a classifier. Add the classifier as a fourth row beside the three estimators, on the same protocol, so the comparison is apples to apples and the estimators are the baseline the model has to beat. |

### The "is it illicit?" stack
| Module | Verdict | Why |
| --- | --- | --- |
| `engines/rules/detectors.py`, `schema.py` | **KEEP** | Deterministic, explainable, unlabelled, and per the README already "what an investigator should see first". Untouched. |
| `engines/anomaly/detector.py` | **KEEP** | Already carries weight zero in the stacker (0.175 AUC, below chance). Nothing to do. |
| `engines/gnn/*` | **DEMOTE** | This is the headline that moves. Code unchanged, but: README section moves below origination, the `⚠️ labels are synthetic` caveat stays, and it stops being the thing quoted as the ML contribution. Still an optional torch extra, still fused. |
| `fusion/stacker.py`, `explain.py`, `taint.py`, `ordering.py`, `pipeline.py`, `incremental.py` | **DEMOTE (stacker) / KEEP (rest)** | The composite risk score remains the alert queue's sort key — it is what makes the queue usable. What changes is the claim: the composite is *risk triage*, the origination model is *the primary ML result*. `SIGNALS` does **not** gain an origination column: origination answers *who*, not *how risky*, which is the same reason `correlation_score` is deliberately excluded (`fusion/stacker.py:58`). Origination surfaces beside an alert as attribution evidence, exactly where leads already go. |
| `engines/correlation/scorer.py` | **EXTEND** | This is where origination output actually lands. It currently counts distinct transactions per (cluster, IP). It should count *distinct transactions the model says this IP originated*, weighted by calibrated probability, instead of raw observations. One substitution inside `raw_confidence`; the ownership-claim guard test stays. |

### Graph, features, API, console, ops
| Module | Verdict | Why |
| --- | --- | --- |
| `graph/builder.py`, `clustering.py`, `entity_graph.py` | **KEEP** | Blockchain-grain, unaffected. Note `iter_transactions()` collapses relay rows per txid — the new pipeline must read the parquet directly, not through this. |
| `features/engineer.py` | **KEEP** | Entity/tx grain, not relay grain. `unique_broadcast_ips` and `unique_asns` stay. Do **not** add relay features here — a third grain in a two-grain module is how that file stops being readable. |
| `api/app.py` | **EXTEND** | Add `GET /transactions/{txid}/origination`; extend `/stats` with the new model's status block (trained / untrained / degraded). `GET /transactions/{txid}/propagation` keeps its current shape and gains a per-node probability field. Existing response keys unchanged — the console reads them. |
| `api/graph.py`, `redteam.py`, `monitor.py`, `case_report.py`, `format_id.py` | **KEEP** | Red team already scores origin honestly (rank of the true IP, null when unobservable); it gains the classifier's probability in the same block. |
| `web/src/pages/Transaction.tsx`, `Entity.tsx` | **EXTEND** | Per-peer originate/forward probabilities on the propagation view. No new page. |
| `custody.py` | **KEEP** | Add capture-session and model-fit as ledger event types via the existing append API — no change to the module. |
| `offline/*`, `tests/test_offline_guarantee.py` | **EXTEND — read §4** | The p2p sensor is the first module in this repo that legitimately opens a socket. This collides head-on with the offline guarantee. |
| `eval/report.py`, `eval/results.md` | **EXTEND** | One new section. Every number still comes from `python -m eval.report` and nowhere else. |

**Nothing is REPLACE.** The reframe is additive; that is the point of it being cheap.

## 2. New package layout

Requested under `src/`. Note the conflict first: this repo is flat-packaged
(`pyproject.toml` `[tool.hatch.build.targets.wheel] packages = ["generator",
"ingest", ...]`), and every import in the codebase and every `python -m` in the
README assumes top-level packages. A `src/` layout means a `pyproject` change,
a different import root for new code only, and two conventions living side by
side forever. **Recommendation: flat `p2p/` and `origination/` beside the
existing nine packages** — same cost, one convention. The layout below is the
requested `src/` version; drop `src/` from every path to get the recommendation.

```
src/
  p2p/
    __init__.py
    sensor.py         # the only socket in the repo; see §4
    capture.py        # append-only capture storage + reader
    relay_features.py # (txid, peer_ip) feature table
  origination/
    __init__.py
    labels.py         # ground_truth.json -> per-(txid, peer) originated/forwarded
    model.py          # fit / infer / persist
    calibrate.py      # probability calibration + cost-weighted abstention
    pipeline.py       # CLI: python -m origination.pipeline
```

Five modules, one CLI. Nothing else.

### `p2p/sensor.py`
Connects to Bitcoin peers, speaks enough of the wire protocol to receive `inv`
and `tx`, and records `(timestamp, peer_ip, peer_port, txid, message_type,
direction)`. Nothing else — no wallet, no block validation, no relaying (a node
that relays becomes a participant in what it is measuring). Writes through
`capture.py` and never parses or scores. This is the one module that cannot run
air-gapped and must not be importable from anything that does.

**Calibration knobs, not constants:** connection count, per-peer timeout,
clock-skew offset per peer, `inv`-vs-`tx` arrival debounce window. A real
capture host's clock drifts and a real peer's `inv` arrives before its `tx`;
timing features are worthless if the skew is not tunable.

### `p2p/capture.py`
Append-only storage for raw observations: one parquet per session under
`data/capture/<session_id>/`, plus a `session.json` recording start/end, the
peer set, the sensor version and a SHA-256 per file. Session ids and hashes
land in the custody ledger, so a capture is evidence with provenance rather
than a file that appeared. Reader side exposes one function returning a frame
with the **same column names** as `ingest`'s canonical schema, so everything
downstream is indifferent to whether rows came from a live capture or an NTRO
dump.

### `p2p/relay_features.py`
The grain change, and the module that carries the actual research content. In:
the relay frame + `IpIntel`. Out: one row per `(txid, peer_ip)` with columns in
four groups —

* **timing** — rank of first sighting within the txid, Δt to the txid's first
  sighting, Δt to the peer's own median lag across all txids (a peer that is
  *always* late is a relay; a peer that is early *once* is interesting).
* **topology** — in/out degree in the observed tree, subtree size, whether the
  peer appears only as `src_ip` and never as `dst_ip` (a strong origin signal),
  and the three existing estimator scores from `engines.propagation.estimators`.
* **peer history** — distinct txids this peer was seen on, distinct txids it was
  *first* on, ratio between them. This is what actually separates a relay from
  an originator, and it is cross-txid, which no current module computes.
* **intelligence** — the four `IpIntel` classes, `asn`, `high_risk_asn`,
  `anonymized_entry_point`.

Pure function of its inputs, no model, no config-mutating state.

### `origination/labels.py`
`ground_truth.json`'s `transactions[txid]` already carries `true_origin_ip`,
`observed_origin_ip` and `broadcast` ("home" / Tor / hosting). Label per
`(txid, peer_ip)`: `1` if the peer is the true origin, `0` if it was observed
but is not, and **excluded** (not `0`) when the true origin is absent from the
observed tree — training a classifier on a positive-free txid teaches it that
nothing originates anything. The exclusion rate *is* the ceiling already
measured in `eval/origin.ceiling_both()`; reuse that function rather than
recomputing it.

### `origination/model.py`
Non-negative logistic regression first, for the reason already written into
`fusion/stacker.py`: the coefficients are part of the deliverable, and
`fusion/explain.py`'s SHAP values are exact on a linear model rather than
approximated. `NonNegativeLogistic` in `fusion/stacker.py` is reused directly if
its sign constraint holds for these features, and dropped if it does not — some
origination features are legitimately negative evidence (high forward count
means *less* likely to have originated), which is a real difference from the
suspicion-signal stacker. **Decide by measurement, in the eval section, not
here.** Gradient boosting only if it beats logistic by a margin worth the
explainability loss; chronological split, never random, matching
`engines/gnn`'s existing discipline.

Prediction is per `(txid, peer)`. Top-1-within-txid is then derived, which makes
it directly comparable to the three estimators on the existing protocol.

### `origination/calibrate.py`
Two jobs the existing confidence heuristic does not do:
1. **Calibration** — isotonic (or Platt on small samples) fitted on a held-out
   chronological slice, plus a reliability curve and ECE in the eval report. A
   probability that is quoted to an analyst has to mean what it says.
2. **Abstention** — pick the threshold that maximises expected value under the
   `cost_weights` already pre-registered in
   `config.yaml: engines.propagation.origin_filter.cost_weights`
   (`wrong_uninvolved_third_party: -3.0`, `abstained: 0.0`). Those weights were
   committed before this model existed, which is exactly what makes the
   threshold choice non-circular. Do not invent new weights.

## 3. Interfaces between new and existing code

Every arrow is one-directional and additive. New code imports existing code;
existing code gains at most one optional read of a new artifact.

| # | Boundary | Contract | Breakage risk |
| --- | --- | --- | --- |
| 1 | `capture.py` → `ingest/` | Capture reader emits the canonical column names from `config.yaml: schema`. Live capture becomes just another input directory. | None. New file, existing parsers untouched. |
| 2 | `relay_features.py` → `engines/propagation/tree.py` | Imports `build_trees`, `PropagationTree`. Read-only. | None, unless `PropagationTree`'s fields change — they must not. |
| 3 | `relay_features.py` → `engines/propagation/estimators.py` | Calls the three estimator functions for feature columns. Read-only. | None. Their signatures are `(tree, cfg) -> dict[ip, score]` and stay. |
| 4 | `relay_features.py` → `ingest/ip_intel.py` | `load_intel()` + `IpIntel.classify(ip, asn)`. Read-only. | None. |
| 5 | `labels.py` → `eval/datasets.py`, `eval/origin.py` | `Dataset.ground_truth()`, `ceiling_both()`. Read-only, and **test-and-eval-side only** — labels must never be importable from a serving path, same rule `ingest` already enforces by excluding `ground_truth.json` by name. | Enforce with a test mirroring `tests/test_no_vendor_imports.py`. |
| 6 | `origination/model.py` → `fusion/stacker.py` | Optional reuse of `NonNegativeLogistic`. If the sign constraint is wrong for these features, no import at all. | Low. If reused, do not edit that class — subclass or copy. `tests/test_fusion.py` guards it. |
| 7 | `origination/pipeline.py` → new artifact | Writes `data/processed/tx_origination.parquet`, one row per `(txid, peer_ip)`: `txid, peer_ip, p_originated, p_calibrated, abstained, rank_in_tx, features_hash, model_version`. **Separate file from `tx_origins.parquet`** — the existing per-txid artifact keeps its schema and its consumers. | None. Nothing reads it until (8) and (9). |
| 8 | `engines/correlation/scorer.py` ← origination | Optional read: if `tx_origination.parquet` exists, `raw_confidence` counts probability-weighted originated transactions instead of raw observations; if absent, current behaviour exactly. Ownership-claim wording and `test_module_never_claims_ownership` unchanged. | Medium — this is the only existing *scoring* path that changes. `eval/correlation_eval.py` numbers move, and `eval/results.md` §6 must be regenerated, not hand-edited. Gate it behind a config flag defaulting to off until the eval shows it is an improvement. |
| 9 | `api/app.py` ← origination | New route `GET /transactions/{txid}/origination`. `/transactions/{txid}/propagation` gains per-node `p_originated` (additive key). `/stats` gains an `origination` status block. All existing keys unchanged. | Low. The console's `web/src/api/types.ts` is additive; `useApi` tolerates unknown keys. |
| 10 | `custody.py` ← `capture.py`, `model.py` | New event types via the existing append API: `capture_session_started/ended`, `origination_model_fitted`. No signature change. | None. Hash-chain verification is event-type agnostic. |
| 11 | `config.yaml` | New top-level `p2p:` block (sensor knobs, capture dir) and `origination:` block (feature windows, model paths, calibration method, threshold). Reuses `engines.propagation.origin_filter.cost_weights` rather than duplicating it. | None. `config.get()` is path-based. |
| 12 | `pyproject.toml` | New packages registered. `src/` layout additionally needs a package-dir mapping; flat layout needs two list entries. Sensor deps (`python-bitcoinlib` or hand-rolled wire parsing — prefer hand-rolled, the subset needed is small) go in a **new optional extra `sensor`**, never in base deps, so the air-gapped install stays as small as it is. | Low, but `offline/build_wheelhouse.sh` must learn the new extra or the bundle silently omits it. |
| 13 | `tests/test_offline_guarantee.py` | `p2p/sensor.py` added to `ONLINE_BY_DESIGN` with a reason. See §4 — this is the one that needs a decision, not a patch. | **High if done carelessly.** |

## 4. The offline collision — the one real problem

`tests/test_offline_guarantee.py` greps every file we wrote for sockets and
HTTP, in the source *and* in the built console, and `offline/airgap_check.sh`
runs the whole system inside a network namespace with nothing but loopback. That
guarantee is a headline claim of this project. A p2p sensor opens sockets to the
internet by definition.

Adding `p2p/sensor.py` to `ONLINE_BY_DESIGN` is one line and is **the wrong
shape**: the two existing entries are *build-time scripts that run on a
different machine*, and the exemption's whole meaning is "nothing that ships to
the air-gapped host reaches the network". A sensor is a runtime component.
Quietly widening the allowlist turns a precise claim into a vague one.

The honest framing, and what the plan commits to:

* The system splits into a **collection host** (online, runs `p2p/sensor.py`,
  produces capture files) and an **analysis host** (air-gapped, runs everything
  else, reads capture files). This is the same split `offline/fetch_intel.sh`
  and `build_wheelhouse.sh` already establish, and the same split NTRO would
  actually operate.
* `ONLINE_BY_DESIGN` gains `p2p/sensor.py` with the reason stated as
  *collection host only, never installed on the analysis host*, and
  `offline/install.sh` must **not** install the `sensor` extra.
* A new test asserts no module outside `p2p/sensor.py` imports it, and that
  nothing in the analysis-side packages imports `p2p.sensor` — the air gap
  becomes an import boundary that is tested, not a sentence in a README.
* `offline/airgap_check.sh` keeps running the analysis host with zero
  exemptions. That is the claim worth having.

Alternative if a single-host demo is required: the sensor reads a pcap or a
`bitcoind` debug log from disk instead of a socket, and stays fully offline. That
loses live capture and keeps every guarantee. Worth deciding before writing
`sensor.py`, because it is the difference between one socket and none.

## 5. Order of work

1. `generator/net.py` per-hop provenance + `origination/labels.py`. Without exact
   labels nothing downstream can be measured, and the labels are free.
2. `p2p/relay_features.py` + one eval row: the three existing estimators, scored
   as per-peer *classifiers* on the existing protocol. This is the baseline the
   model must beat, and it is achievable with zero new modelling.
3. `origination/model.py` + `calibrate.py` + eval section with PR-AUC, ECE,
   reliability curve, and cost-weighted abstention against the pre-registered
   weights.
4. API route + console field.
5. `engines/correlation/scorer.py` swap, behind the config flag, only if (3)
   shows the model is better than the `first_timestamp` baseline it replaces.
6. `p2p/sensor.py` + `capture.py` last. It is the module with the most
   operational risk and the least effect on whether the ML result is any good —
   and steps 1–5 are all measurable on generated data without it.

Steps 1–3 are the reframe. Everything after is delivery.
