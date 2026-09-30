# Relay feature schema — grain `(txid, peer_ip, capture_id)`

Produced by `features/relay.py`; written to `features.relay_path`
(`data/processed/features_relay.parquet`). One row per **candidate peer per
transaction per capture**.

```sh
python -m features.relay --input data/capture/2026-09-24-node1 \
    --observer-ip 198.51.100.2
```

This is the third grain in `features/`. The other two —
`features.parquet` (entity) and `features_tx.parquet` (transaction) — are derived
from the blockchain. This one is derived from the network, and it is the input a
supervised origination model needs: not "is this transaction suspicious" but
"did this peer originate it or merely forward it".

## Candidate set

Candidates for a transaction are exactly **the peers that announced it**
(`inv`, or `tx` — receiving the body is possession too), minus the observer's own
addresses. The observer cannot be the origin of its own observations. Outbound
announcements are our own and are dropped.

A peer that announced the same transaction twice (an `inv` and then the `tx`) is
**one** candidate, timed from its earlier announcement. `announcements_of_txid`
records how many raw announcements the window held.

`candidate_count` is carried on every row. `degenerate` is set when it is 0 or 1:
with one candidate there is nothing to rank, so the row must not be presented to
a model as if a choice had been made.

## Two classes of causality

The blanket rule "no feature may use information observed after the announcement
it describes" would forbid the announcement rank, every delta against the
transaction's own distribution, and every estimator score — which is the entire
signal. So the rule is applied at two boundaries, and each column below is
labelled with the class it belongs to:

| class | may read | tested by |
| --- | --- | --- |
| **strict** | only events strictly **before** this announcement's timestamp | appending later events leaves the row byte-identical |
| **window** | only announcements **of this transaction**, at the moment its observation window closes | appending events of other transactions leaves the row byte-identical |

Every peer-history feature is **strict**, because that is where leakage would be
fatal: a peer aggregate computed over the whole capture encodes how often that
peer *will* be first, which is most of the way to the label.

The **window** features read announcements that arrive after the one the row
describes, and that is deliberate and safe: they are the same information
`engines/propagation`'s estimators already work from, and it is what an operator
holds at the moment they ask the question. What they may never read is any other
transaction, past or future — a window feature that did would leak the same way a
whole-capture aggregate does.

`tests/test_relay_features.py` asserts both, and
`test_the_causality_check_can_actually_fail` inserts an *earlier* announcement and
asserts the features do change — a causality test that cannot fail proves nothing.

## Null semantics

Three different meanings, never conflated:

* **`NaN` in a strict feature** — there was no history yet. A peer's first
  announcement in a capture has no earlier interval and no earlier first-rate.
  Not zero: zero would say "this peer has never been first", which is a
  measurement, while `NaN` says "we have not looked at it yet".
* **`NaN` + an indicator column** — the quantity is not derivable from this input
  at all. Only `connection_age_s` / `connection_age_known`.
* **null in an enrichment column** — the GeoIP database is absent or has no
  record. `asn_source` says which (`geoip` / `none`).

Counts in the null column below are from the two synthetic fixture bundles
(246 rows); they illustrate which columns are nullable, not a property of a real
capture.

---

## Grain

| column | dtype | null | class | meaning |
| --- | --- | --- | --- | --- |
| `txid` | str | never | — | Resolved txid. **Only** resolved txids: see Quarantine. |
| `peer_ip` | str | never | — | The candidate. Never the observer. |
| `capture_id` | str | never | — | Which capture this row was observed in. |

## Vantage

Arrival deltas are measured against one observer's clock and one observer's peer
set, so **every row carries its vantage** and two captures are not pooled without
`--allow-cross-vantage`.

| column | dtype | null | class | meaning |
| --- | --- | --- | --- | --- |
| `observer_ip` | str | never | — | The observer, lowest address if it has several. |
| `observer_ips` | str | never | — | All of them, comma-separated. |
| `direction` | str | never | — | `inbound` / `outbound` as **inferred** by the capture reader — from which end of a pcap flow was local, or from the verb on a debug.log line. Never an observed fact about the peer. |
| `direction_basis` | str | never | — | How the observer's address was established: `explicit` (passed to the build), `label_file` (recorded by the broadcaster), `config:p2p.local_ips`. There is deliberately no inference step: a pcap's flows reveal the local address and a debug.log never does, so guessing would make the column mean different things per format. |
| `direction_confidence` | float64 | never | — | What share of `direction` is evidence rather than assumption, from `p2p.direction_confidence`. |
| `capture_source` | str | never | — | `<format>:<file>` the row came from. |

## Timing — window class

The causality argument for each: all four read only announcements **of this
transaction**, within the window that closes before the row is emitted. None
reads any other transaction. That is what the shuffle and append tests assert.

| column | dtype | null | class | meaning and causality |
| --- | --- | --- | --- | --- |
| `announce_ts` | float64 | never | window | Epoch seconds of this peer's earliest announcement of this txid. Self-describing: it *is* the event. |
| `announce_rank` | int64 | never | window | 1 = first to announce. Reads the other candidates' times, none from another transaction. |
| `is_first` | bool | never | window | `announce_rank == 1`. The single strongest naive signal, and the reason the strict class exists — a peer's *historical* first-rate must not be computed the same way. |
| `candidate_count` | int64 | never | window | Candidates for this txid. |
| `announcements_of_txid` | int64 | never | window | Raw announcements in the window, before collapsing a peer's repeats. |
| `delta_vs_first_s` | float64 | never | window | Seconds after the first announcement. 0.0 for the first. |
| `delta_vs_median_s` | float64 | never | window | Signed seconds against the window's median announcement time. Reads later announcements by construction — window class, not strict. |
| `delta_z` | float64 | never | window | `delta_vs_first_s` standardised by the window's own mean and stdev. 0.0 when a single candidate makes the stdev zero. Same argument as above. |
| `window_span_s` | float64 | never | window | Last minus first announcement of this txid. |

## Timing — strict class (peer history)

Computed by streaming announcements in timestamp order and recording each row's
values **before** the peer's state is updated with that announcement. No row can
see its own announcement or any later one. This is the class the append test is
really aimed at.

| column | dtype | null | class | meaning and causality |
| --- | --- | --- | --- | --- |
| `peer_txids_before` | int64 | never | strict | Distinct transactions this peer announced earlier in this capture. 0 on its first. |
| `peer_firsts_before` | int64 | never | strict | How many of those it was first on. A transaction's first announcement is known the moment it happens, so this needs no lookahead. |
| `peer_fraction_first_before` | float64 | `NaN` when `peer_txids_before == 0` | strict | The ratio. The most label-adjacent feature in the matrix, and the reason the strict boundary is enforced rather than argued about. |
| `peer_announce_rate_per_min` | float64 | `NaN` before any elapsed time | strict | Earlier transactions per minute since this peer was first seen. Distinguishes a busy relay from a quiet residential node. |
| `peer_mean_interval_s` | float64 | `NaN` with fewer than 2 earlier | strict | Mean gap between this peer's earlier announcements. |
| `peer_median_interval_s` | float64 | `NaN` with fewer than 2 earlier | strict | Median of the same. |
| `peer_stdev_interval_s` | float64 | `NaN` with fewer than 2 earlier; 0.0 with exactly 2 | strict | Regularity: a node relaying everything has a tighter distribution than one announcing its own occasional transactions. |
| `peer_first_seen_age_s` | float64 | never (0.0 on first sighting) | strict | Seconds since this peer's first appearance in this capture. The causal **lower bound** on connection age that the event stream does support. |

## Peer context

| column | dtype | null | class | meaning |
| --- | --- | --- | --- | --- |
| `peer_port` | int64 | never | — | Remote port. |
| `non_standard_port` | bool | never | — | Not `p2p.port`. A node on a non-default port is not running a stock listener. |
| `is_ipv6` | bool | never | — | Address contains `:`. |
| `is_onion` | bool | never | — | `.onion` address. A peer reached over Tor has no meaningful arrival timing relative to clearnet peers. |
| `transport_v2` | bool | never (`False` when unknown) | — | The event arrived over BIP-324 encrypted transport, as recorded by the capture reader. Informational; the model does not read it. |
| `unreadable_flows` | Int64 | null unless the capture is a pcap | capture-wide | Port-8333 flows in the pcap that carried payload and never decoded — consistent with BIP-324 v2. Read by `analysis.validity` (V2_PASSIVE_TAP). |
| `user_agent` | object | null when no handshake was captured | capture-wide | The peer's subver string. **The one deliberate exception to causality**: a client version does not change within a capture, so learning it from a handshake logged after an announcement reveals nothing about that announcement's timing or origin. |
| `user_agent_class` | str | never (`unknown`) | capture-wide | Family: `core`, `btcd`, `bcoin`, `libbitcoin`, `bitcoinj`, `knots`, `gocoin`, `other`, `unknown`. |
| `services` | int | yes | capture-wide | Service bits from the peer's `version` message (pcap decode, or a .btcap `services` field). bitcoind's debug.log never logs them, so a debug.log capture leaves this null: unknown, not zero. Not a model input; read by the peer profile (`engines/correlation/profile.py`). |
| `ip_class` | str | never | — | From `ingest.ip_intel`: `known_bitcoin_relay`, `tor_exit`, `hosting_vpn`, `residential_or_unknown`. |
| `is_tor_exit` | bool | never | — | `ip_class == "tor_exit"`, broken out because it changes what an attribution may claim. |
| `connection_age_s` | float64 | **always null** | — | Seconds between connecting to this peer and the announcement. The reader's event stream carries announcements, not connection lifecycle, so this is not derivable from any of the three supported inputs. Emitted null with an indicator rather than approximated. |
| `connection_age_known` | bool | never (always `False`) | — | The indicator. It exists so a model can distinguish "young connection" from "unknown", and so the column becomes usable without a schema change if the reader ever emits connection events. |

## Enrichment

From `ingest.geoip.GeoIp.lookup` — the same local-`.mmdb`, no-network path
`ingest/` uses. No new enrichment code, and a missing database degrades to nulls
rather than failing.

| column | dtype | null | class | meaning |
| --- | --- | --- | --- | --- |
| `geo_country` | object | null without the country DB | — | ISO country code. |
| `asn` | object | null without the ASN DB | — | Autonomous system number. |
| `asn_org` | object | null without the ASN DB | — | Its name. |
| `high_risk_asn` | bool | never | — | `geoip.high_risk_asns` — hosting/VPN/Tor-adjacent. |
| `asn_source` | str | never | — | `geoip` or `none`. Says whether a null means "no record" or "no database". |

## Estimator features

The outputs of the three existing estimators in
`engines/propagation/estimators.py`, as per-candidate scores and ranks. The
estimators and `build_trees` are imported, not reimplemented; the only addition
is that the observer is struck from the candidate list.

| column | dtype | null | class | meaning |
| --- | --- | --- | --- | --- |
| `est_first_timestamp_score` | float64 | never | window | Class-weighted first-sighting score. |
| `est_first_timestamp_rank` | int64 | never | window | 1 = best candidate. |
| `est_rumor_centrality_score` | float64 | never | window | Shah & Zaman (2011), class-weighted. **On a single-observer capture the tree is a star and every leaf is symmetric**, so this carries little: see `docs/GROUND_TRUTH.md` §1. |
| `est_rumor_centrality_rank` | int64 | never | window | As above. |
| `est_timestamp_weighted_centrality_score` | float64 | never | window | Fanti & Viswanath (2017), class-weighted. |
| `est_timestamp_weighted_centrality_rank` | int64 | never | window | As above. |

All six are **window** class: they read the transaction's whole observed tree,
and nothing from any other transaction.

## Flags

| column | dtype | null | class | meaning |
| --- | --- | --- | --- | --- |
| `degenerate` | bool | never | window | `candidate_count <= 1`. Nothing to rank; the abstention machinery should treat these as abstentions rather than as predictions. |
| `scope_out` | bool | never | window | No candidate could plausibly be the sender: either no candidates at all, or every candidate is in `engines.propagation.low_confidence_classes` (a public relay, which forwards other people's traffic and is never a plausible origin). This is the zero-ceiling case of `docs/GROUND_TRUTH.md` §1 in feature form — a model must abstain here, not learn from it. |
| `wtxid_unresolved` | bool | never (always `False`) | — | Present so the column exists in both outputs. Unresolved rows are in the quarantine file, never here. |

## Quarantine

Rows still identified by a **wtxid** go to `features.relay_quarantine_path`, in
`ingest/`'s quarantine shape (`source_file`, `row`, `reason`, `raw`), and are
never merged into the matrix. Since BIP-339 a node announces by wtxid, which is
not the txid for any segwit transaction; merging the two identifiers would split
one transaction's announcements across two grains, or pool two transactions under
one. Resolution comes from the `tx` message in the same capture, or from a
ground-truth label file — `features.relay.build` applies a bundle's label file
automatically.

## Refusals

| condition | behaviour |
| --- | --- |
| timestamps lack sub-second resolution | `PreflightError`. The threshold is `eval.ground_truth.min_subsecond_share` and the check is `eval.ground_truth.preflight.subsecond_share` — one copy of the number, not two. Every timing feature would be a tie. |
| observer address unknown | `VantageError`. No row could carry a vantage, and inbound/outbound would be guesswork. |
| several captures, different observers, no `--allow-cross-vantage` | `VantageError`. `delta_vs_first_s` would mean two different things in one column. |
