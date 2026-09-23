# Demo script

Fifteen minutes, one case, nothing typed that has not been typed before. The
point of the demo is not that the system finds things — it is that every number
it shows can be questioned on the spot.

---

## T-10 minutes: the two checks

Do these before anyone is watching. Both exist because both have failed live.

```sh
offline/run_offline.sh --check        # port 8000 free? if not, it prints who has it
offline/run_offline.sh                # start the API, stamped with the commit
npm --prefix web run build            # stamps the same commit into the bundle
npm --prefix web run preview          # or: npm --prefix web run dev
```

Then open the console and **look at the top of the page**. If a red banner says
*"The API is a different build"* or *"The API is not answering"*, the browser is
talking to a server from an earlier session — the exact failure that once ate an
hour of debugging. Kill the pid the launcher names, start it again, reload.

Full list: `offline/OFFLINE_CHECKLIST.md`.

---

## 1. Overview — "what is in this case" (2 min)

Open `/`.

- The header field is drawn procedurally; nothing is fetched. Say that early —
  it is the offline claim in visual form.
- Four numbers: entities, alerts, mean risk, transactions. Read the sub-labels
  aloud; they say what each number is *of*.
- **Where to start** lists the top cases. Click one only if asked; otherwise go
  to the queue.

If origin estimation is degraded, the notice on this page says so. Do not skip
it — a system that hides its own limits is the thing this project argues
against.

## 2. Alert queue — "what do I work on next" (3 min)

Open `/alerts`.

- Point at the **saturation notice** if it is showing: every alert scores
  1.000, so the fused score separates alerts from everything else but cannot
  rank them against each other. Say it plainly. It is the most honest thing on
  the screen.
- Sort by risk, filter by pattern, then narrow with the minimum-risk slider.
- Confirm one alert and reject another. Both are recorded to
  `feedback.parquet` for recalibration; the rejected row dims and keeps its
  place rather than vanishing.
- Every identifier here is middle-truncated by one shared formatter
  (`web/src/lib/formatId.ts`, and its Python twin for the PDF). Hover for the
  full value; the copy button copies the whole thing.

## 3. A case — "why is this here" (4 min)

Click a row.

- **Gauge, then reason, then evidence** — that is the reading order, and it is
  deliberate: the score is the least interesting part.
- The reason comes from `fusion/explain.py` and names the actual numbers that
  fired.
- Scroll to **Investigative leads**. This is the moment to slow down: the leads
  sit on their own surface, worded *associated with*, with a caution chip when
  the origin estimate behind them is weak. Attribution is not suspicion, and
  the interface is built so the two cannot be confused.
- **Export case report** produces the one-page PDF. Ids in it are cut exactly
  as they are on screen, so a reader can match report to console.

## 4. Investigation graph — "who else is involved" (4 min)

Press **Investigate →** on the case page, or `Ctrl K` and paste an address.

- Wallets are circles, transactions are diamonds, IPs are hexagons. Wallets are
  joined *through* transactions: a three-input, four-output transaction would
  otherwise imply twelve wallet pairs that no payment ever made.
- Double-click a node to expand it. **Watch what does not happen:** nothing
  already on screen moves. Only the new nodes are laid out.
- Switch the layout to **flow tree** and trace forward four hops. The toolbar
  reports how many branches the amount threshold pruned.
- Turn on **simplify connectors** to show the wallet-to-wallet view, and point
  out the edge labels: each says how many transactions it stands for, because
  that view is lossy and says so.
- **Save** the view. The id it returns can be passed to the report endpoint
  (`?investigation=<id>`), so the PDF carries the graph the analyst actually
  built.

## 5. Live monitor — "it is still running" (2 min)

Open `/monitor` and press **Start watching**, then **Simulate an arrival**.
Within a couple of seconds a file appears in the feed with the rows it
contributed and any alerts it raised. Press simulate again while the first is
still on screen: the second arrival lands underneath it.

What to say: the batch pipeline answers *analysis*; this answers *monitoring*.
It folds the new transactions into the graph already in memory rather than
re-running everything, and nothing is retrained. Drop the same file in twice
and it contributes nothing the second time — worth doing if a judge asks.

## 6. Chain of custody — "would this stand up" (2 min)

Open `/custody`. Every action is there in order — the ingest, the pipeline run,
the arrivals just demonstrated, any verdict given on the alert queue. Press
**Verify again**: the chain is intact and every sealed file still matches.

What to say: each entry carries the hash of the one before it, so an edited
entry breaks every later one. Export a case report from any alert and the PDF
carries the ledger head and the dataset hashes, while the ledger carries the
PDF's hash. Say the limitation out loud before a judge finds it — this build
has no authentication, so the ledger records *what* was done, not *who* did it.

## 7. Red team — "make it fail" (2 min, optional)

Open `/redteam` and hand the keyboard over. A judge picks a typology, sets the
parameters, and injects it; the system re-runs incrementally and reports
whether it caught the pattern — and when it does not, it shows every engine's
score against the threshold instead of hiding the miss. The scoreboard keeps
every run of the session. **Reset** restores the pre-demo dataset.

---

## If something breaks

| Symptom | Cause, usually | Fix |
| --- | --- | --- |
| Red banner: different build | an old uvicorn holds the port | `kill <pid>` from the banner or the launcher, then `offline/run_offline.sh` |
| Red banner: not answering | API not started, or an old build with no `/version` | `offline/run_offline.sh` |
| "Could not load" on every page | the pipeline has not run | `python -m fusion.pipeline` |
| Graph is empty | the focus node is not in this dataset | `Ctrl K` and pick from the queue instead |
| Graph drawn tiny in a corner | should not happen — fits are deferred until the panel has a size | press `F`, and tell someone |

## What to say when asked "is this real?"

The data is synthetic and the labels come from our own generator, so every
model number is a measurement of our simulator, not of Bitcoin. That is stated
in `eval/results.md` beside each table, and the stacker carries the same warning
in its metrics. What is real is the structure: the clustering heuristics, the
propagation model, the graph, and the reasoning the interface makes an analyst
walk through.
