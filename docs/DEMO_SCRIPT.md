# Demo script

Eight minutes, one command, one case. `scripts/demo.sh` drives the real API
in-process over the served demo dataset and prints one line per step. Every
number said aloud is either on that line or in [`docs/CLAIMS.md`](CLAIMS.md).
If a number is in neither, do not say it.

Everything shown is **simulated**: the served dataset is generator seed 41
(200 actors, 1200 transactions), and every tag is `source="simulated"`. Say
so first. Do not let a judge find it.

---

## T-10 minutes: preflight

```sh
scripts/demo.sh --preflight
```

This hashes every file the demo reads against `scripts/demo_pins.json`,
re-verifies the tag bundle's seal, checks that `unshare -rn` works, and dry-runs
steps 1-8 into a throwaway ledger. The output must end in **READY**. If it does
not, each FAIL line names the file:

| FAIL on | Usually | Fix |
| --- | --- | --- |
| a `data/raw/*` or `data/processed/*` hash | a red-team injection from the console (it appends to the served dataset until someone presses **Reset**), a re-run of the generator or pipeline, or `offline/airgap_check.sh` (which overwrites `data/raw`) | `POST /redteam/reset` (the console's **Reset**) restores the canonical dataset: generator seed 41, 200 actors, 1200 transactions. Then rebuild what is derived from it, in this order: `python -m p2p.demo_capture`, `python -m features.relay --input data/processed/demo_capture --observer-ip 198.51.100.250`, `python -m p2p.manifest seal data/processed/demo_capture`, `python -m fusion.pipeline`. Re-pin only if the change was deliberate |
| `demo_capture/*` alone | the capture was rebuilt, or changed after sealing | the same rebuild, from `python -m p2p.demo_capture` on |
| the tag bundle | the bundle was edited or removed | re-import it (docs/TAGSTORE.md) |
| `unshare -rn` | user namespaces disabled on this machine | step 9 still runs, and says it did not get a namespace. Say that out loud |
| the dry run digest | an answer changed | run `scripts/demo.sh` and read which line moved |

After a deliberate rebuild, `scripts/demo.sh --pin` records the new state.

**Do not use the console's red team on the demo machine after preflight**, or
press **Reset** afterwards. An injection that is never reset leaves the served
dataset out of step with the capture built from it. That has happened once
already.

Run the demo with `--pause`, so each step waits for Enter:

```sh
scripts/demo.sh --pause
```

Each run writes a **fresh** custody ledger and the packet PDF under
`data/processed/demo/`. The case ledger (`data/processed/custody.jsonl`) is
never touched, so the chain on screen holds only this run.

---

## The eight minutes

Timings are cumulative. The script itself takes about 17 seconds, and the rest
is talking. Each step has what to say and a fallback line in case it fails
live. A failed step prints `FAILED: …` and the demo goes on to the next one.

### 0:00 Opening (30 s)

> "Everything you are about to see runs on this laptop with no network, on
> simulated data from our own generator. Every number comes with the condition
> it was measured under. Where we measured something that did not work, we will
> say so."

### 0:30 Step 1: seed (45 s)

`address 3f5c84…a561 sits in entity 35a930…4e53 (4 wallets): peel_chain + ransomware_collector, alert 1 of 197, risk 1.000`

> "We start from one address, a ransomware collector. Clustering puts it in an
> entity of four wallets, and two rule detectors fired on it: a victim fan-in
> and a peeling chain. It sits at the top of a queue of 197 alerts."

**Fallback:** "The seed is the top alert in the queue. We'll pick it up again at
step 6."

### 1:15 Step 2: capture (45 s)

`demo_capture verifies against its seal (manifest ae80da…ce8e, …); replayed 1875 announcements of 1200 transactions from 545 peers`

> "Network evidence arrives as a capture file, sealed with a SHA-256 manifest on
> the collection host. Before we read it, we check that it has not changed since
> sealing. That check is the first entry in the custody ledger. Then we replay
> it: 1875 announcements, 1200 transactions, 545 peers."

**Fallback:** "If the seal did not verify, the system would refuse the capture.
That refusal is the behaviour we want, and it goes in the ledger too."

### 2:00 Step 3: origin (60 s)

`tx cd08f0…eae9: candidates 117.200.191.191, 159.65.253.218; model names 117.200.191.191 at calibrated p=0.964, tier PASS; generator truth 117.200.191.191 (agrees)`

> "One of the collector's own peel transactions was announced by two peers. The
> origination model names one of them. The 0.964 is a calibrated probability,
> fitted on held-out captures, and the validity layer passes the answer.
> Because this is simulated, we can check it against the generator's truth, and
> here it agrees. It does not always. On unseen topologies, the model answers
> about one transaction in five, and it is right about 91% of the time when it
> does."

(Those figures are CLAIMS.md O3.)

**Fallback:** "The model's answer for this transaction was a PASS naming the
first announcer, and generator truth agreed."

### 3:00 Step 4: tiers (75 s)

`PASS … | QUALIFIED COINJOIN 50bccb…8c28 -> broadcaster 49.36.190.244 only, inputs not attributable | ABSTAIN NOT_REACHABLE 058ee8…25f2 (corpus capture …): answered=False, all 8 announcers are listed relays`

> "A probability alone is not enough. We also ask whether the answer can be
> about this transaction at all. There are three outcomes. PASS is what you
> just saw. For a CoinJoin the answer is QUALIFIED: we name who broadcast it,
> and we say explicitly that the inputs belong to many people. And when every
> peer that announced a transaction is a public relay, the true sender is not
> among the candidates at all. The ceiling is zero, so the system abstains and
> says why."

> "The abstain example comes from our evaluation corpus. The demo capture pools
> many vantage points, so it never produces this case."

**Fallback:** "PASS, QUALIFIED, ABSTAIN. Evaluation section 10 has every
verdict and the reason behind each."

### 4:15 Step 5: peer (45 s)

`117.200.191.191: 1 originated claim(s) (PASS 1); pivots to cluster(s) 35a930…4e53 (both, 0.38); simulated only`

> "Now go the other way and start from the IP. Its profile makes one PASS claim,
> and it links back to the collector's cluster through two independent bases,
> the origination model and a correlation lead. The link is an association to
> investigate, with confidence 0.38. It is not an attribution. The profile is
> stamped simulated. That lookup is now in the ledger as well."

**Fallback:** "The profile links this IP to the seed's cluster. Every lookup
is recorded."

### 5:00 Step 6: queue and actor (50 s)

`197 entity alerts (the default queue); #1 35a930…4e53 risk 1.000 | actor A-302: 1 cluster + 3 peers, drill-down 85c694f8832f… -> relay-hop dataset row, 117.200.191.191 at 04:46:59`

> "The default queue is one alert per entity. We also built an actor view,
> which joins clusters to the peers that broadcast for them. We tested it
> against the entity queue over ten datasets of about thirty operations each,
> and it improved triage on no measure we took. It wrongly merged 8-10% of
> alerted multi-cluster actors. So the entity queue is the default, and actors
> are a view. Here is the collector as an actor: one cluster and three peers.
> Every link drills down to the raw row that supports it."

**Fallback:** "The entity queue is the default because the actor queue did not
earn it. That is section 13."

### 5:50 Step 7: cash-out (60 s)

`from the seed: 4 ranked candidates; #1 bc1q71…5a2b "simulated cash-out point of operation C000531" (source simulated), haircut share 14.9% over 1 hop(s) | from bc1q67…7555: 0 candidates, stopped: funds entered CoinJoin 076776…7a7f`

> "Where did the money go? We trace forward under two taint models and rank the
> clusters that the tag store lists as services. The top candidate took 14.9% of
> the seed's outflow. Its tag says simulated because it is: our generator never
> pays a real exchange, so the demo bundle marks the true cash-outs itself. The
> second trace starts from a CoinJoin participant. It stops at the mix and
> reports that the funds entered a CoinJoin. It does not guess which output was
> theirs."

**Fallback:** "Tracing ranks tagged services by traced share times path
confidence, and it stops at CoinJoins. On deeper layering it reaches the
cash-out only 37-49% of the time, and we know why (CLAIMS.md F6)."

### 6:50 Step 8: packet (30 s)

`…packet.pdf (6,962 bytes, sha256 …) | packet PDF sealed at ledger entry 4; fresh ledger: 4 entries, chain intact: capture_imported, lookup.peer_profile, actor.view, export.exit_point_packet`

> "All of that goes into an investigator packet. Its first page says it is a
> lead and not proof of ownership, that its tags are simulated, and that the tag
> bundles are sealed, not signed. The PDF's hash is in the ledger. The ledger
> for this run holds four entries, one per thing we did, and the chain is
> intact."

Open the PDF if there is time. Its path is on the line.

**Fallback:** "The packet endpoint is covered by tests. The ledger records its
hash on every export."

### 7:20 Step 9: air gap (40 s)

`tests/test_offline_guarantee.py: 7 passed … | steps 1-8 rerun inside a network namespace (interfaces: lo): output identical (digest …)`

> "Last, the air-gap claim. This test reads every file we wrote and fails on any
> network call. Then steps 1 to 8 run again inside a network namespace that has
> only loopback, a real air gap, and the output is identical."

**Fallback:** if `unshare` is unavailable, the line says so. Say: "No namespace
on this machine, so this rerun proves determinism, not isolation.
`offline/airgap_check.sh` is the full isolation check."

### 8:00 Close

> "Four things we will not claim: that this is real data, that the tags are
> intelligence, that the tag bundles are signed, or that a trace is proof of
> ownership. Everything else is in the claims sheet, with its source."

---

## Questions to expect

| Question | Answer, and where it is |
| --- | --- |
| "Is this real?" | No. It is simulated throughout, and no real signet capture has been scored yet. The signet rows in §9 are PENDING (CLAIMS.md, Known limits). |
| "How accurate is origin inference?" | Quote O3 and give the condition: unseen topologies, simulated, and it answers about one transaction in five. Never quote the 0.755 top-1 on the demo capture (CLAIMS.md, Numbers not to quote). |
| "Why did it say 100% on the red team?" | It did not. With tags, 30/30 is an upper bound, because every operation was tagged (CLAIMS.md). The number to quote is 20 of 30, at the tags-off figure in CLAIMS.md D5. |
| "Is the bundle signed?" | No. It is sealed: tamper-evident, with no keys. |
| "What about VPNs?" | A VPN or cloud address that is not on a list counts as residential. That is a known limit. |

---

## Appendix: the console, if there is time

`offline/run_offline.sh` serves the console at `http://127.0.0.1:8000/app/`.
Look at the top of the page. A red banner saying *"The API is a different
build"* means an old server holds the port. Kill the pid it names and start
again. Useful pages:

- `/alerts`: the queue. Across 197 alerts the fused score takes only 5 distinct
  values at three decimals, and all of the top 50 display 1.000. The
  tiebreakers (`fusion/ordering.py`) order them from evidence (CLAIMS.md F2).
- `/entities/<id>`: gauge, then reason, then evidence, and the investigative
  leads on their own surface.
- `/custody`: the case ledger (not the demo's fresh one) and **Verify again**.
- `/redteam`: let a judge inject a typology. A miss shows every engine's score
  against the threshold. **Reset** restores the dataset.

| Symptom | Cause, usually | Fix |
| --- | --- | --- |
| Red banner: different build | an old uvicorn holds the port | `kill <pid>` from the banner, then `offline/run_offline.sh` |
| "Could not load" on every page | the pipeline has not run | `python -m fusion.pipeline` |
| Graph is empty | the focus node is not in this dataset | `Ctrl K` and pick from the queue |
