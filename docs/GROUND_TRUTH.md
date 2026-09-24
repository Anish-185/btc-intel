# Ground truth on real relay data — capture setup and pre-registered protocol

Every origin accuracy figure elsewhere in this project is measured against
`generator/`'s simulator, so it describes the simulator. This document is the
protocol for measuring the same thing where the truth is known *and* the data is
real: two signet nodes, one broadcasting from an address we wrote down before the
run, the other capturing.

**Pre-registration.** This file was committed with the harness
(`eval/ground_truth/`) and before any signet number existed, for the same reason
`docs/origin_eval_protocol.md` was committed before the topology fix: so the rule
cannot be written around the result. Everything below — what counts as correct,
how ties break, which rows are reported, what a zero ceiling means — is fixed
here in advance.

---

## 1. The finding that shapes the whole design

State it first, because it is structural and it is not a disappointment to be
buried at the end:

> With a **single observer**, the non-adjacent condition has a ceiling of **zero**.

An observer learns an address only by being connected to it. If the broadcaster
is two hops away, its address never appears in any announcement the observer
receives — so the true origin is not among the candidates, and no estimator,
however good, can select it. The adjacent condition has a ceiling of 1.0 and is
the trivial upper bound. There is no third possibility for one vantage point.

That is why both conditions are mandatory and why they are **never pooled**:
averaging an upper bound with an impossibility produces a number that describes
neither. And it is why the honest conclusion of a single-observer study is about
the *evidence*, not the estimator — which is what the relay-delay noise floor
(§6) measures.

Multi-observer capture is the escape, and is out of scope here: several
observers at different points in the network see different first-hops, and the
intersection carries positional information a single star does not. The harness
is built so that adding observers is a change to the capture, not to the scorer.

---

## 2. Two signet nodes

Signet, not mainnet: broadcasting a hundred transactions to measure ourselves is
fine on a test network and antisocial on a real one. Signet also has few enough
nodes that topology can be controlled, which is the entire point of the two
conditions.

### BROADCASTER — known address, controlled cadence

`bitcoin.conf`:

```ini
signet=1
[signet]
server=1
listen=1
# The address that goes in the label file as true_origin_ip. Bind explicitly so
# there is no doubt which interface the transactions left from.
bind=203.0.113.9
# Do not let the node pick its own peers when the condition depends on which
# peers it has. See §3.
connect=<the peer this condition requires>
```

### OBSERVER — capture, microsecond timestamps, wide

```ini
signet=1
[signet]
server=1
listen=1
debug=net
# Without this, timestamps are whole seconds. Announcements of the same
# transaction arrive milliseconds apart, so whole seconds cannot order them at
# all and preflight refuses the capture.
logtimemicros=1
# The observer wants as many vantage points as it can get.
maxconnections=125
```

Optionally also capture the wire, which is the only way to resolve wtxid
announcements without the label file:

```sh
sudo tcpdump -i any 'tcp port 38333' -s 0 -w /srv/capture/observer.pcap
```

(Signet's P2P port is 38333, not 8333 — set `p2p.port` in `config.yaml` to match,
or the pcap reader will discard every packet.)

---

## 3. Forcing and verifying each condition

**Forcing** is done with `connect` / `addnode` on the broadcaster, and
**verifying** is done with `getpeerinfo` — the harness refuses to broadcast
unless the two agree, because a run that claims non-adjacency while peered with
the observer measures the trivial bound and would be filed as the real result.

### (a) adjacent — the trivial upper bound

```ini
# broadcaster's [signet] section
connect=198.51.100.2:38333        # the observer, and nothing else
```

Verify:

```sh
bitcoin-cli -chain=signet getpeerinfo | jq -r '.[].addr'   # the observer is listed
```

### (b) non-adjacent — the real result

At least one hop between them. Two ways, in order of preference:

1. **Relay through a third node you control.** Broadcaster `connect=` the relay
   only; relay peers with the observer; observer must *not* peer back to the
   broadcaster.
2. **Public signet peers.** Broadcaster `connect=` two public signet nodes that
   are not the observer, and the observer `connect=` different ones.

Verify — and this is the check that matters, on **both** nodes:

```sh
# on the broadcaster: the observer must NOT appear
bitcoin-cli -chain=signet getpeerinfo | jq -r '.[].addr' | grep -c 198.51.100.2   # 0

# on the observer: the broadcaster must NOT appear, inbound or outbound
bitcoin-cli -chain=signet getpeerinfo | jq -r '.[].addr' | grep -c 203.0.113.9    # 0
```

`eval.ground_truth.broadcast.verify_condition` performs the broadcaster half
automatically from `getpeerinfo` and records the result in the label file;
preflight rejects a capture whose recorded check failed. The observer half is
manual and must be done before the run — an inbound connection from the
broadcaster silently converts condition (b) into condition (a).

---

## 4. The run

```sh
# on the BROADCASTER
python -m eval.ground_truth.broadcast \
    --n 50 --interval 20 --jitter 5 \
    --address <a signet address of your own> \
    --true-origin-ip 203.0.113.9 \
    --observer-ip 198.51.100.2 \
    --condition non_adjacent \
    --out data/ground_truth/2026-09-24-non_adjacent.labels.json
```

Jitter is deliberate: transactions on an exact cadence are separable by their
arrival pattern alone, which would flatter any timing estimator.

The label file records, per transaction: `txid`, `wtxid`, `raw_hex`,
`true_origin_ip`, `broadcast_wall_clock`, `topology_condition`.

**Why `wtxid` and `raw_hex` are in there.** Since BIP-339 a node announces by
wtxid, which is not the txid for any segwit transaction. A `debug.log` capture
sees only the wtxid and cannot know which transaction it belonged to. The
broadcaster holds the raw bytes, so it computes both identifiers — that is what
`resolve_from_labels` uses to recover those rows, and the recovery rate is
reported in the results.

### Sealing and transfer

Stop the capture, then on the collection host:

```sh
mkdir -p bundle && cp ~/.bitcoin/signet/debug.log* /srv/capture/*.pcap \
    data/ground_truth/2026-09-24-non_adjacent.labels.json bundle/
python -m p2p.manifest seal bundle --note "observer node, 20 min, non_adjacent"
```

Carry it across, then `python -m p2p.manifest verify <bundle>` on the analysis
host. See `docs/CAPTURE.md` for the full transfer discipline.

---

## 5. Preflight — four refusals, no warnings

`eval.ground_truth.preflight.check` **refuses** a capture that fails any of the
following, reporting every failure at once. None of them warn and continue: a
warning in a log is not a number an investigator will decline to quote.

| refusal | why it is fatal |
| --- | --- |
| timestamps lack sub-second resolution (< 50% of events carry a fractional second) | announcements arrive milliseconds apart; whole seconds cannot order them |
| unresolved wtxid rows above 5% *after* label-side resolution | those rows name a different identifier than the txid rows and cannot be grouped with them |
| `local_ips` unset, or an address that is both local and a peer | inbound/outbound would be inverted, which inverts the entire signal |
| `topology_condition` unrecorded, or its recorded check failed | the two conditions are different measurements and neither row can hold an unlabelled run |

Thresholds live in `config.yaml` under `eval.ground_truth`.

---

## 6. What is measured, and how

Reported **per condition**, never pooled. Five rows:

| row | what it is |
| --- | --- |
| 1 | **first-spy baseline** — earliest sighting wins, no class weighting, no abstention. The floor: what naive analysis does. |
| 2–4 | the three estimators from `engines/propagation/estimators.py`, **unchanged**: `first_timestamp`, `rumor_centrality`, `timestamp_weighted_centrality` |
| 5 | reserved for the supervised origination model (`docs/REFRAME_PLAN.md` step 3), marked **PENDING** until it exists |

Per row: top-1 and top-3, each with a **Wilson 95% interval** (not the normal
approximation — at n = 50 and p near 1 that reports bounds above 1.0), the
abstention rate, accuracy given no abstention with its own interval, the ceiling
(how often the true origin was observed at all), and the cost-weighted score.

**Reused, not reinvented.** Abstention is `engines.propagation.low_confidence_origin`;
the four outcome classes and their pre-registered costs
(`correct_actionable` +1, `correct_infrastructure` +0.3,
`wrong_uninvolved_third_party` −3, `abstained` 0) are
`engines.propagation.origin_filter.cost_weights`, applied through
`eval.origin.cost_score`. The ceiling is the same quantity `eval.origin.ceiling_both`
measures on simulated data. If those change, these numbers change with them,
which is the point.

**The floor is scored without abstention.** Under the shared rule it posts a
100% abstention rate — an artifact of confidence being the winner's share of an
unweighted score vector, not caution — and reporting that would make the floor
look careful when it is the opposite.

**The observer is excluded as a candidate.** It cannot be the origin of its own
observations. This is the one place the scorer deviates from `estimate_all`,
which has no reason to exclude anything on a third-party dump.

### The relay-delay noise floor

Two questions the accuracy table cannot answer:

1. The observed distribution of **inter-peer announcement deltas** for the same
   txid — median, p90, p99. This is the signal a timing estimator has to work
   with.
2. The **timing ceiling**: the share of multi-peer transactions where the true
   origin announced *first and by more than the observer's clock resolution*. No
   estimator that reads only timing can exceed it, however it weights what it
   reads. Where the deltas approach the clock resolution, the ceiling falls, and
   the bottleneck is the capture rather than the algorithm.

---

## 7. Offline / demo mode

```sh
python -m eval.report      # section 9
```

A deterministic run over `generator/`'s 500-node gossip simulation, producing
the same table shape with `condition="simulated"` and the seed and sizes from
`config.yaml`'s `eval:` block.

**It cannot be confused with a signet run**, by three mechanisms:

* the condition label is `simulated`, never `adjacent` or `non_adjacent`;
* the section's **first line states the data source**, and says outright when no
  signet capture is present;
* a bundle becomes a signet row only if its label file says `source: "signet"`.
  The test fixtures live in the same directory and say
  `source: "synthetic-test-fixture"`, so they are skipped and listed as skipped.

**It is not a substitute for a signet run.** The simulation is observed at many
relays, so its trees carry positional structure a single-observer capture does
not have — which is exactly the difference §1 is about. Rumor centrality has
something to rank on there and nothing to rank on here.

---

## 8. Status of the signet rows

At the time of writing this environment has **no `bitcoind`, no `bitcoin-cli`
and no network access**, so no signet capture has been taken. Both signet rows
are reported as **PENDING** and the only measured rows come from the simulation.
The two sealed bundles under `tests/fixtures/ground_truth/` are **synthetic**,
say so in their `source` and in their manifest note, and exist to exercise the
manifest → preflight → scoring path end to end; their numbers are illustrative of
the mechanism, never of Bitcoin.

To fill the rows: follow §2–§4 on two signet nodes, drop the sealed bundle into
`eval.ground_truth.fixtures_dir`, and re-run `python -m eval.report`. Nothing
else changes — the harness is the deliverable, the numbers are the run.
