# Exit points

`analysis/exit_point.py` takes a seed (an address, an entity, or an actor),
traces its funds forward, and ranks candidate cash-out points: clusters the
tag store (`intel/`, docs/TAGSTORE.md) tags **exchange/VASP**.

**It is an investigative lead, not proof of identity or ownership.** It says
where traced value went under stated taint models. It does not say who
controls the receiving cluster. That is what a request to the service is for.

## Tracing

The tracing is `fusion.taint.trace`, beside the `propagate` that computes the
taint signal. Both follow the same rules:
* outgoing edges only;
* never back through a cycle;
* never across an entity-graph edge made only of CoinJoins (`mix_count ==
  count`, set from `clustering.is_coinjoin`).

It runs over the entity graph (`graph/entity_graph.py`), which is
cluster-level. An address seed is traced from the cluster that holds it.

Two taint models:

| model | an entity that received tainted value `a` forwards… |
| --- | --- |
| haircut (proportional) | `a × ext_out / max(ext_in, ext_out)`, split across its outputs by value |
| poison (any contact) | every output in full: an upper envelope, each edge counted once |

FIFO is not offered. It needs per-output ordering that the entity graph does
not keep, so it would be a second tracer over the wallet graph. The spec
allowed FIFO only if cheap, and it is not.

**CoinJoins stop the trace.** Where value reaches an edge made only of mixes,
the result records *funds entered a CoinJoin* (from which cluster, how much,
which transaction) and goes no further. It does not guess which output was
the seed's. An edge that holds a CoinJoin *and* an ordinary payment between
the same two clusters is followed, as `propagate` has always done. The hop's
reasoning then says that the edge includes CoinJoins.

**Tagged exchanges stop the trace too.** What an exchange sends out is other
customers' money.

**An actor is traced from each member cluster separately.** An actor join
(docs/ACTORS.md) says that two clusters share a peer identity. It is not a
payment, and tracing never crosses it. Each member gets its own trace and its
own candidates.

### Cut-offs (config `exit_point`)

| key | value | why |
| --- | --- | --- |
| `max_hops` | 8 | Generator layering reaches its sink within 5 hops, and peel chains mostly collapse into the collector's own cluster. Most illicit funds reach a service within a handful of hops; past 8, every trace reaches everyone. Value still in flight at the limit is reported. |
| `min_share` | 0.1% | Haircut: an entity whose *summed* tainted inflow at a hop is under 0.1% of the seed's outflow is not followed. It is summed per entity rather than per edge, because layering splits into many small branches and merges them again. A per-edge 1% floor never reached the merge. |
| `min_value_btc` | 0.001 | Poison has no fractions to prune on, so dust and fee-sized edges are dropped. |
| `paths_per_entity` | 3 | The k best paths shown per candidate. |
| `sink_min_share` | 5% | An untagged cluster keeping at least this share of the flow is shown as an untagged sink. |

## Ranking

A candidate is a cluster with an exchange/VASP tag that the trace reached.
Its score is **flow share × path confidence**, where:
* flow share is the traced value it received over the seed's outflow;
* path confidence is the product, along its best path, of every receiving
  cluster's merge confidence (`Clustering.confidence`) and, under haircut,
  every hop's taint fraction.

Candidates are ordered by the haircut score, then the poison score. The k best
paths are kept per model.

An untagged cluster that keeps a large share of the flow is listed as an
**untagged sink**, by cluster id only. It is never named as a service. A
sink carrying non-service tags (a ransomware tag, say) is listed as "sink
(tagged, not a service)", with its tags.

## The investigator packet

`GET /exit-points/{address|entity|actor}/{subject}/packet` renders a PDF
through the case-report path (`api/case_report.render_packet`). Its first page
states three things:
* it is an investigative lead, not proof of identity or ownership;
* whether any tag behind it is simulated, and if so that simulated tags are
  simulated;
* that the tag bundles are sealed (tamper-evident), not signed.

Then, per candidate:
* cluster id;
* each tag with its source, collection date and bundle;
* receiving addresses and the time window;
* traced amount under each model;
* every path, hop by hop, with the reasoning for each hop;
* the sha256 of the candidate's record.

The packet ends with the untagged sinks, the tag bundles' manifest hashes and
the evidence seal (dataset hashes and ledger head). Every packet generated
is recorded in the custody ledger (`export.exit_point_packet`), with its
sha256.

## On the demo dataset

The served demo bundle (`intel.importers.demo`, docs/TAGSTORE.md) tags every
operation's true cash-out wallet as a simulated exchange/VASP. A trace from a
demo operation therefore ends in ranked candidates rather than only untagged
sinks, and every one of them says `source: simulated`. That is a demo
convenience with the same upper-bound caveat as the evaluation, not evidence
that ranking works.

## Surfaces

* `GET /exit-points/{address|entity|actor}/{subject}` returns the trace as JSON.
* The entity and actor pages have a **Trace to cash-out** panel, which runs on
  request and links the packet.

## Evaluation

Section 16 of `eval/results.md`. It uses generator ground truth, is marked
simulated, and is labelled an **upper bound**. The generator never pays an
exchange with illicit money, so the evaluation builds an in-memory tag store
(never `data/tags`) that tags each operation's true cash-outs as
exchange/VASP, beside the real generator exchanges as decoys. It reports
top-1 and top-3 per typology and taint model, and how often tracing stops at
a CoinJoin rather than producing a candidate through it.

Generator layering carries only the largest branches forward and leaves most
of its value in unspent intermediate outputs. The merge's sink therefore
receives only a few percent of the source's outflow, and often falls below
`sink_min_share` as an untagged sink. Tagged, it is still reached.

On the shifted datasets, layering is deeper, and reach falls to 37% (haircut)
and 49% (poison). The missed sinks sit 7 to 11 entity hops from the source:
some are past `max_hops`, and the rest fall under the haircut floor after
repeated fan-outs. The cut-offs were set before the evaluation and were not
retuned on it.
