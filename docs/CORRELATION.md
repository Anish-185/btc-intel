# Correlation, both directions

`engines/correlation/` holds one engine that runs in two directions over the
same evidence.

| direction | question | code | API |
| --- | --- | --- | --- |
| forward | which peer broadcast for this cluster? | `scorer.py` | `/transactions/{txid}/propagation`, `/transactions/{txid}/origination`, an alert's `leads` |
| reverse | what did this peer, or this ASN, do on the network? | `profile.py` | `/peers/{peer}/profile`, `/asns/{asn}/profile` |

Neither direction attributes anything to a person. The forward direction
produces probabilistic leads (see `scorer.py`'s docstring). The reverse
direction produces a profile of observed network behaviour. It says "peer X"
and "cluster C" and never who operates either.

## Two sources, and where each comes from

| source | grain | origins from | vantage |
| --- | --- | --- | --- |
| relay matrix (`features.relay_path`) | one row per candidate peer per txid per capture | the origination model (`origination/`), per capture | single observer: the node that wrote the capture |
| relay-hop dataset (`ingest.output_path`) | one row per observed send, src → dst | `engines.propagation` | multi-point relay log; the observers are the receiving nodes |

A profile reads both and labels every part with its source. The two are never
merged into one timeline. For example, timing intervals are measured within
one vantage and never across two.

## What a peer profile holds

| part | contents | source |
| --- | --- | --- |
| `header` | `simulated_only`, the provenance of every vantage, and a sentence. A profile built only from `fixture` or `simulated` data says so. | capture sources (`synthetic-fixture:`, `sim:`), `ingest.provenance` |
| `originated` | Every transaction the origination model names this peer as origin of **and does not withhold**. Each carries its calibrated probability, calibration basis, validity verdict, tier and `answer`. Counts are given per tier, and QUALIFIED and ANNOTATE claims are never folded into PASS. A COINJOIN claim is a `broadcasting_peer` with `input_ownership: not attributable`, and a TOR_ONION claim is an `onion_identity`. | relay matrix |
| `withheld` | Transactions where the peer ranked first but `eval.origin.flagged_at` withheld the answer, each with its reason code (below). These are not originated. | relay matrix |
| `propagation_origin` | A count of hop-dataset transactions whose `engines.propagation` origin is this peer. These are not origination claims. They reach the profile only through correlation leads. | relay-hop dataset |
| `relayed` | Transactions announced without being named origin: a count by source and a sample of `relayed_sample`. | both |
| `timing` | Announce rate, active hours (UTC, 24 bins) and inter-announcement mean, median, sd, min and max. Below `min_timing_observations` there is only a sentence saying so. | both, per vantage |
| `clients` | User-agent and service-flag history with first and last seen and captures. Service bits come from a pcap `version` message or a `.btcap` field. debug.log never records them, so there they are unknown, not zero. | relay matrix |
| `linked_clusters` | Clusters linked by `origination`, `correlation lead` or `both`, each with a confidence and an evidence chain (below). | both |
| `excluded_links` | Claims that were deliberately not turned into links, and why (`COINJOIN`, `NO_STRUCTURE`). | — |
| `network` | IP, ASN, AS org, country and IP class from `ingest/` enrichment. **Absent on an onion identity.** | both |
| `vantage` | Every capture and observer the peer was seen from, with direction, provenance, count and first/last seen. | both |

An ASN profile aggregates every peer seen with an address in that ASN.
`totals` sums the members, and `members` gives each peer's own counts and
links to its profile. Onion identities are never members, because they have
no ASN.

### Linking a peer to a cluster

* **origination**: a claimed origin of a transaction links the peer to the
  clusters of that transaction's inputs (`graph/`'s clustering). Confidence is
  `raw_confidence(sum of calibrated probabilities)`, the same saturating rule
  the forward scorer uses.
* **correlation lead**: the forward scorer's `(cluster, IP)` lead for this
  peer. Confidence is its `final_score`.
* **both**: both bases hold for the same cluster. The link's confidence is the
  stronger of the two. They read overlapping evidence, so they are not
  combined as if independent. `by_basis` shows each one.

Every link carries `evidence`: one item per transaction, with the raw rows it
rests on (relay-matrix rows keyed by `capture_id, txid, peer`, or hop-dataset
rows by row index) and the input addresses that place it in the cluster. The
chain is raw rows → transaction → input addresses → cluster.

## Honesty constraints, and where each is enforced

| constraint | enforced in | tested in |
| --- | --- | --- |
| No statement or implication of real-world identity; wording is "peer X" / "cluster C" | `profile.py` sentences; `web/src/pages/Peer.tsx` | `test_no_profile_states_or_implies_real_world_identity`, `peer.test.tsx` |
| A COINJOIN-qualified origination never yields a cluster link | `_linked_clusters`: excluded if the answer is a broadcasting peer, if the verdict lists COINJOIN, **or** if `graph.clustering.is_coinjoin` says so from the structure, whatever the verdict | `test_a_coinjoin_never_links_a_cluster` (validity layer on and off), `test_a_coinjoin_the_verdict_missed_still_links_no_cluster` |
| Every linked cluster has an evidence chain back to raw rows | `_linked_clusters` | `test_every_linked_cluster_traces_back_to_raw_rows` |
| Too few observations for a timing signature: say so | `timing_signature` | `test_too_few_observations_get_a_sentence_not_a_signature` |
| Simulated or fixture only: say so in the header | `peer_profile`, `asn_profile` | `test_simulated_or_fixture_only_profiles_say_so` |
| An onion identity carries no IP, ASN or country field (P6.1's TOR_ONION rule) | `peer_profile` never builds `network` for it; evidence rows use `peer`, not `ip` | `test_an_onion_identity_never_carries_an_ip_asn_or_country` (a recursive key check) |
| QUALIFIED and ANNOTATE are never collapsed into plain attributions | `_claim`; the console's `ClaimRow` | `test_originated_keeps_every_tier_and_never_counts_a_withheld_answer`, `peer.test.tsx` |

### The timing threshold

`engines.correlation.profile.min_timing_observations: 20`. The standard error
of a standard deviation estimated from *n* intervals is about
sd/√(2(n−1)). That is 16% at 20 announcements and 50% at 3. An active-hours
histogram over 24 bins built from fewer than 20 events is mostly empty bins,
which reads as a schedule that isn't there. The value was set from that
arithmetic and has not been tuned on any profile.

## Round trip

`profile.origination_answers` computes one answer per `(capture_id, txid)`:
`OriginationModel.decide`, the validity verdict, then `flagged_at` at the
model's own cutoff. Both `/transactions/{txid}/origination` (shown on the TXID
page) and a profile's `originated` read that one frame, so the two directions
cannot disagree. `test_round_trip_every_claimed_origin_shows_on_its_txid_page`
checks it through the API anyway. For every claim in a profile, the
transaction's own page names the same peer, in the same capture, with the
same tier and the same answer. The forward-to-reverse test checks the other
way round.

## Abstention reason codes

`eval.origin.abstention_reasons` gives each withheld answer exactly one code,
in `flagged_at`'s own order:

1. the verdict's leading reason, when its tier is withheld (`DEGENERATE`,
   `NOT_REACHABLE`; in `binary` mode any non-PASS reason);
2. `RELAY_AT_TOP`: a known public relay ranked first;
3. `BELOW_CUTOFF`: calibrated confidence under the cutoff.

A row has a code exactly when `flagged_at` flags it (tested). The profile's
`withheld.by_reason` uses these codes. So does the eval report's abstention
breakdown (section 10, *Why each answer was withheld*), which gives each
policy's counts per code on the variant and base corpora and every test set,
cross-topology included, beside `acc if answered`.

## Surface

* `GET /peers/{peer}/profile`: an IP or a `.onion`. Returns 404 if the peer is
  in no source.
* `GET /asns/{asn}/profile`: `64500` or `AS64500`.
* `GET /transactions/{txid}/origination`: the per-capture answers the TXID
  page shows.
* **Every profile lookup is written to the custody ledger**
  (`lookup.peer_profile` / `lookup.asn_profile`), found or not, with the
  subject and the sealed dataset hashes. Which peers an investigation asked
  about is part of the record.
* Console: `/peers` (start from an IP, onion or AS number), `/peers/:peer` and
  `/asns/:asn`. Cross-links run both ways. The profile links each transaction
  to `/tx/:txid` and each cluster to `/entities/:id`. The TXID page links its
  origin, runner-ups and per-capture answers to `/peers/:peer`. An entity's
  leads link to `/peers/:peer`.

## Limits

* The served relay matrix is one demo capture, `p2p/demo_capture.py`, which
  folds the served relay-hop log into a single capture observed by a
  collector. Its txids are the served dataset's, so origination, correlation
  leads and clusters describe the same transactions. It is not a node's
  capture: the origination model was trained on single-observer captures, so
  its confidences on this pooled view are out of distribution. The TXID page
  shows them beside `engines.propagation`'s estimate, not instead of it.
  Rebuild it with `python -m p2p.demo_capture` followed by `python -m
  features.relay --input data/processed/demo_capture --observer-ip
  198.51.100.250`.
* The two synthetic fixture captures (`tests/fixtures/ground_truth`) are no
  longer served; they remain the ground-truth fixtures.
* An ASN profile's totals are sums over unrelated peers. The per-peer rows are
  the evidence; the totals are only an index.

Coverage of each profile part over the served data and a corpus is section 11
of `eval/results.md`.
