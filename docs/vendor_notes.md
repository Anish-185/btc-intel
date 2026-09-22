# Vendor reference notes

Four reference repos are cloned into `vendor/` (gitignored, never imported — see
`CONTRIBUTING.md`). We read them for ideas; anything we use gets reimplemented in
our own modules, against `config.yaml`, with our own tests, under our MIT license.

**The gap none of them fill:** every repo below is purely *ledger-side*. They model
value flow — addresses, transactions, amounts, timing, graph topology. None of them
touch the network layer: peer IPs, first-relay node, ASN, geolocation, hosting-provider
fingerprints, Tor/VPN exit correlation. SIH26146 needs blockchain evidence *joined to*
network-layer observations (our `data/geoip/` + `engines/correlation/`), so for each
repo the IP/network side has to be built by us from scratch. Noted again per-repo below.

Clone commands used:

```sh
git clone --depth 1 https://github.com/IBM/Multi-GNN vendor/Multi-GNN
git clone --depth 1 https://github.com/IBM/AMLSim vendor/AMLSim
git clone --depth 1 https://github.com/citp/BlockSci vendor/BlockSci
git clone --depth 1 https://github.com/maxfroggatt/Explainable-Bitcoin-Transaction-Detection \
    vendor/Explainable-Bitcoin-Transaction-Detection
```

---

## 1. IBM/Multi-GNN

**What it does.** Reference implementation for *Provably Powerful GNNs for Directed
Multigraphs* (AAAI 2024) and the IBM AML transaction papers. Four GNN classes
(`GINe`, `GATe`, `PNA`, `RGCN` in `models.py`) plus four adaptations that make a
plain GNN work on a directed transaction *multigraph*: edge updates via MLPs
(`--emlps`), reverse message passing (`--reverse_mp`), ego IDs on centre nodes
(`--ego`), and port numbering on parallel edges (`--ports`). Trained on the IBM
AML Kaggle transaction set; edge-level classification (is this transfer laundering?).

**License.** Apache-2.0. Permissive but *not* our MIT — attribution and a NOTICE
obligation come with any copied code, which is exactly why we reimplement instead.

**Adapt vs. read.**
- *Adapt (reimplement in `engines/gnn/`):* the multigraph adaptations, which are the
  genuinely useful part for Bitcoin. Port numbering and reverse message passing in
  `data_util.py` (`ports()`, `to_adj_edges_with_times()`, `time_deltas()`) map almost
  directly onto our address graph, where the same address pair transacts repeatedly.
  Edge-level rather than node-level classification is also the right framing for us.
- *Read only:* the model classes themselves (we'd use standard PyG layers), the
  argparse/training scaffolding, the Kaggle-specific `format_kaggle_files.py`.

**How it differs from what we need.** Multi-GNN assumes a *bank-account* ledger —
stable account identities, one sender and one receiver per transaction, labelled
laundering patterns supplied by the dataset. Bitcoin gives us neither: identity is
per-address and must be clustered first (`graph/`), transactions are many-to-many
UTXO with change outputs, and we have no labels, so a supervised edge classifier is
one engine among several rather than the whole system. It is also online-first
(conda, Kaggle download) where we must run air-gapped. And, critically, its graph has
exactly one kind of node — an account. Ours needs a second node type carrying
network-layer attributes (relaying IP, ASN, country, hosting/Tor flags) attached to
the addresses that a node first broadcast; Multi-GNN has no notion of that at all,
so the heterogeneous address↔IP graph and the features over it are ours to design.

---

## 2. IBM/AMLSim

**What it does.** Multi-agent simulator that generates synthetic AML datasets. Python
(`scripts/transaction_graph_generator.py`) builds an account/transaction graph from
parameter files (`paramFiles/1K/accounts.csv`, `degree.csv`, `alertPatterns.csv`,
`transactionType.csv`), then a Java/MASON simulator steps it over time to emit
transaction logs. Ground truth is explicit: "alert patterns" (fan-in, fan-out, cycle,
bipartite, stack, gather-scatter) are injected on purpose and labelled.

**License.** Apache-2.0. Java dependencies (MASON etc.) carry their own licenses —
another reason this stays outside our build.

**Adapt vs. read.**
- *Adapt (reimplement in `generator/`):* the overall design — a degree-sequence-driven
  background graph plus deliberately injected labelled typologies, driven by CSV/JSON
  parameter files. That is exactly the shape our synthetic generator needs so that
  `eval/` has ground truth to score against. The typology catalogue itself (fan-in/out,
  cycles, gather-scatter, stacked layering) transfers to Bitcoin with renaming.
- *Read only:* everything Java/MASON, the JanusGraph and MySQL plumbing, and the
  pinned-ancient Python stack (`networkx==1.11`, `matplotlib==2.2.3`, Python 3.7) —
  incompatible with our 3.11 + networkx 3.x baseline.

**How it differs from what we need.** AMLSim simulates *bank* transfers: agents have
persistent account IDs and balances, transfers are one-to-one, and there is no UTXO
model, no change addresses, no mining fees, no address reuse behaviour. Our generator
has to produce Bitcoin-shaped data — multi-input/multi-output transactions, peeling
chains, mixer/CoinJoin structure, change outputs a clustering heuristic can trip over —
or our `graph/` and `engines/rules/` will be tested against the wrong physics. Beyond
that, AMLSim emits no network layer whatsoever: no broadcasting peer, no IP, no ASN,
no propagation timing. Since our whole differentiator is correlating blockchain flow
with network-layer observations, our generator must additionally simulate a peer
topology — which IP first relayed which transaction, with realistic geolocation, VPN/Tor
masking and timing jitter — so that `engines/correlation/` can be evaluated at all.
That layer has no counterpart in AMLSim.

---

## 3. citp/BlockSci

**What it does.** Princeton's blockchain analysis platform: a custom append-only
in-memory blockchain database in C++ with Python bindings, built for fast full-chain
traversal (the paper claims a full input/output sweep in ~1 second). The parts that
matter to us are `include/blocksci/heuristics/` and `src/heuristics/` — change-address
detection (`PeelingChainChange`, `PowerOfTenChange`, `OptimalChangeChange`,
`AddressTypeChange`, `LocktimeChange`, `AddressReuseChange`, `ClientChangeAddressBehavior`,
and the set union/intersection/difference combinators over them), transaction-type
identification (`tx_identification.cpp` — CoinJoin detection etc.), and taint tracking
(`taint.cpp`), plus multi-input-ownership address clustering in `include/blocksci/cluster/`.

**License.** **GPL-3.0.** Strongly copyleft — linking or copying would force our whole
deliverable to GPL. This repo is the sharpest example of why the no-import rule exists:
we read the *heuristics as published research* (they are described in the USENIX
Security paper) and write our own implementations. Note also: **unmaintained since
November 2020**, so it is a reference, never a runtime.

**Adapt vs. read.**
- *Adapt (reimplement in `graph/` and `engines/rules/`):* the change-address heuristic
  family and the idea of composing them with set operations, common-input-ownership
  clustering, CoinJoin/mixer transaction identification, and taint propagation as a
  scoring mechanism. Our `config.yaml` already has the switches
  (`graph.common_input_ownership`, `graph.change_detection`).
- *Read only:* the entire storage engine, C++ parser, and fluent query interface — we
  ingest pre-extracted dumps into pandas/networkx and will never parse raw blocks.

**How it differs from what we need.** BlockSci is a *query engine*, not a detection
system: it gives an analyst fast primitives and leaves scoring, ranking and reporting
to them, whereas SIH26146 needs an opinionated end-to-end pipeline that ends in a risk
score and an investigator-facing explanation. It also assumes a full node's chain data
on a large machine; we ingest bounded case-sized dumps offline. And its world stops at
the ledger: BlockSci knows what BlockSci can read from blocks, and a block contains no
sender IP. Peer-level intelligence — which node relayed a transaction first, from which
ASN, through which hosting provider or Tor exit — is invisible to it by construction.
Our `ingest/` therefore has to carry a second evidence stream alongside the chain data,
and our clustering has to fuse IP-derived co-occurrence with BlockSci-style ledger
heuristics, which is a join BlockSci never had to define.

---

## 4. maxfroggatt/Explainable-Bitcoin-Transaction-Detection

**What it does.** A compact, well-disciplined scikit-learn pipeline over the Elliptic
Bitcoin dataset (203k transactions, 165 anonymised features, licit/illicit/unknown
labels). `src/elliptic_preprocessing.py` drops `unknown` and binarises labels;
`src/train_model.py` compares Random Forest / Extra Trees / HistGradientBoosting with
class-weight variants, splits *chronologically* (train steps 1–29, validate 30–34,
test 35–49), picks a decision threshold on validation only, retrains on train+val and
scores once on the untouched test period; `src/explain_shap.py` produces global SHAP
summaries and per-prediction waterfall plots. Reported: 98.1% accuracy, 98.0% illicit
precision, 71.9% illicit recall.

**License.** MIT — the same as ours, so this is the one repo where copying would be
legally cheap. We still reimplement, for consistency with the vendor rule and because
its code is bound to Elliptic's column layout.

**Adapt vs. read.**
- *Adapt (reimplement in `eval/`, `engines/anomaly/`, `fusion/`):* the evaluation
  discipline, which is the real value here — chronological rather than random splits,
  threshold selection on validation only, imbalance-aware metrics (balanced accuracy,
  average precision, PR curve) instead of accuracy, and a single final test pass. Also
  the SHAP explanation layer: an NTRO analyst needs per-transaction reasons, not a bare
  score, so per-prediction attribution belongs in our `fusion/` output.
- *Read only:* the Elliptic-specific preprocessing and the model bake-off itself.

**How it differs from what we need.** It is a flat tabular classifier: it consumes the
165 pre-computed features Elliptic ships and, as its own README concedes, does not model
the edge list at all — the graph is discarded. We build the graph ourselves and treat it
as the primary evidence (`graph/`, `features/`, `engines/gnn/`). It is also fully
supervised, depending on Elliptic's proprietary labels, which do not exist for an NTRO
case; our system must work from rules, unsupervised anomaly detection and correlation,
with supervision as at most one contributing signal. Its features are anonymised, so its
SHAP output names feature *indices* — useless as evidence — while ours must attribute to
named, defensible attributes ("funds passed through a mixer", "broadcast from an ASN
previously seen in case X"). And Elliptic's 165 features are entirely chain-derived:
there is no IP, ASN or geolocation column anywhere in the dataset, so nothing in this
pipeline — features, model or explanations — has any network-layer dimension. Adding it
is ours to do, and it is also what makes our explanations investigator-grade rather than
index-numbered.

---

## Summary table

| Repo | License | Reimplement from it | Read only | Has network/IP layer |
| --- | --- | --- | --- | --- |
| Multi-GNN | Apache-2.0 | Multigraph GNN adaptations: ports, reverse MP, edge MLPs, ego IDs | Model classes, training scaffolding | No |
| AMLSim | Apache-2.0 | Parameter-driven generator with injected labelled typologies | Java/MASON simulator, JanusGraph, legacy pins | No |
| BlockSci | **GPL-3.0** | Change-address heuristics, common-input clustering, CoinJoin ID, taint | C++ storage engine, chain parser, fluent API | No |
| Explainable-BTC-Detection | MIT | Temporal split + threshold discipline, imbalance metrics, SHAP explanations | Elliptic-specific preprocessing, model bake-off | No |

---

## Front-end graph libraries (web/)

Checked before install, the same way the vendored research repos were. Versions
are what `package.json` pins; licences are read out of each package's own
metadata, not from its README.

| Package | Version | Licence | Verdict |
| --- | --- | --- | --- |
| `cytoscape` | 3.34.3 | MIT | bundled |
| `cytoscape-fcose` | 2.2.0 | MIT | bundled (force layout) |
| `cytoscape-dagre` | 2.5.0 | MIT | bundled (flow tree) |
| `cytoscape-expand-collapse` | 4.1.1 | MIT | bundled (entity clusters) |
| `cytoscape-popper` | 4.0.1 | MIT | bundled (tooltip anchoring) |
| `cytoscape-cxtmenu` | 3.5.0 | MIT | bundled (context menu) |
| `tippy.js` | 6.3.7 | MIT | bundled (tooltips) |
| `@popperjs/core` | 2.11.8 | MIT | bundled (tippy's positioning engine) |
| `dagre`, `layout-base`, `cose-base` | — | MIT | transitive, bundled |
| **`cytoscape-svg`** | 0.4.0 | **GNU GPL-3.0** | **not installed — see below** |

### Why `cytoscape-svg` is not in the build

The brief asked for it, and the licence check is what caught it: `cytoscape-svg`
is GPL-3.0. btc-intel is MIT (`LICENSE`), and GPL-3.0 is a copyleft licence —
bundling it into the shipped front-end would put the distributed work under
GPL-3.0 terms, which is not something a build script should decide on a
project's behalf. This is the same call already made for BlockSci above: read
the published behaviour, write our own.

SVG export is therefore implemented in
`web/src/components/InvestigationGraph/svgExport.ts` — about a hundred lines
that walk the live Cytoscape model (node positions, sizes, shapes, colours,
labels; edge endpoints and widths) and write an SVG document directly. It has
two advantages beyond the licence: the output uses our own design tokens rather
than a screenshot of them, and the same function serves the PDF case report, so
a report embeds the analyst's actual view.

If the GPL terms are ever acceptable for a particular deployment — an internal
NTRO build that is never distributed, say — swapping our exporter for the
package is a two-line change. The decision belongs to whoever ships it, which
is why it is written down here rather than assumed.
