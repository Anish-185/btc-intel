# Offline checklist

Run this on the machine that will be demonstrated, **with its network
interface down**. Every item is either something that has actually gone wrong
once, or something a judge will ask you to prove.

Turning the network off for real, pick one:

```sh
sudo ip link set eth0 down          # or wlan0 — whatever `ip -brief link` names
nmcli networking off                # NetworkManager, reversible with `on`
unshare -rn sh -c 'ip link set lo up; …'   # no root needed: a namespace with only loopback
```

The last one is what the automated run below uses. It is a real kernel network
namespace with no interface but loopback, so a stray request fails the same way
it would on an air-gapped box — without taking your own machine off the
network.

---

## 0. The bundle arrived intact

- [ ] `offline/wheelhouse/` has wheels in it, `offline/bundle.json` exists.
- [ ] **The Python versions match.** `python3 -V` on this machine against
      `python_version` in `offline/bundle.json`. Wheels are tagged with the
      interpreter version; a mismatch fails with pip's least helpful error
      ("no matching distribution found") and nothing else. `install.sh` checks
      this first and says so in a sentence.
- [ ] `./offline/install.sh` finishes, reporting the package count, the model
      weights it copied, and the intel snapshot date.
- [ ] It warns about GeoIP, or lists the two `.mmdb` files. Missing is
      acceptable — see `offline/GEOIP_SETUP.md` for what degrades.

## 1. Nothing reaches out — checked in the source, not assumed

- [ ] `python -m pytest tests/test_offline_guarantee.py -q` passes. It greps
      every `.py`, `.sh`, `.ts` and `.tsx` we wrote for `requests.get`,
      `urlopen`, `httpx`, `socket`, `curl`, `wget`, and for any `fetch()`,
      `EventSource` or `WebSocket` given a URL that is not same-origin — plus
      the built bundle in `web/dist`. Two scripts are allowed to use the
      network and are named in the file with the reason:
      `offline/fetch_intel.sh` and `offline/build_wheelhouse.sh`, both of which
      run on the *online* machine.
- [ ] `config.yaml` has `offline: true`. `offline/pipeline.py` asserts it and
      so does that test.

  > What this proves and what it does not: our code makes no network calls.
  > A *dependency* still could — `torch-geometric` pulls in `requests`, for
  > instance, though nothing we call uses it. That is why the real check is
  > the one you are doing now: running with the interface down.

## 2. The pipeline, on this machine's data

```sh
.venv/bin/python -m generator.main --n-actors 60 --n-transactions 400 --output data/raw --formats csv
.venv/bin/python -m ingest.pipeline --input data/raw/
.venv/bin/python -m fusion.pipeline
```

- [ ] All three finish. Ingest reports rows, transactions and how many were
      quarantined; fusion reports entities, alerts and the stacker's AUC.
- [ ] `data/processed/final_alerts.json` exists, is newer than the parquet it
      came from, and has alerts in it.
- [ ] Both runs appear in the custody ledger: `python -m custody log`.

## 3. The server — one process, API and console

- [ ] `offline/run_offline.sh --check` says the port is free. If it does not,
      it prints the pid, start time and command of whatever holds it; `kill`
      that, or use `PORT=8010`.
- [ ] `offline/run_offline.sh` starts and prints the console URL.
- [ ] `curl -s 127.0.0.1:8000/version` answers.
- [ ] `curl -s -o /dev/null -w '%{http_code}\n' 127.0.0.1:8000/` is **307** — it
      redirects to `/app/`.

## 4. The dashboard

- [ ] `http://127.0.0.1:8000/app/` loads in a browser with the network down.
- [ ] **The build banner is absent.** The console compares its compiled-in
      commit with `/version`; a red banner means the page and the server are
      different builds. **If it is on screen, stop — nothing below it can be
      trusted.** Rebuild (`npm --prefix web run build`) and restart with the
      launcher, or check `commit` in `offline/bundle.json`.
- [ ] Click through Overview → Alert queue → a case → Investigation graph.
      **The graph renders nodes and edges**, not an empty canvas.
- [ ] **Reload the page while on the alert queue.** It must come back as the
      console, not as JSON. (The console is served from `/app/` precisely
      because `/alerts`, `/entities/…` and `/custody` are also API paths.)
- [ ] Live monitor: press *Start watching*, then *Simulate an arrival*. Within
      a few seconds the file appears in the feed with the rows it contributed.
- [ ] Chain of custody: *Verify again* reports the chain intact.
- [ ] The browser's network tab shows requests to `127.0.0.1:8000` **only**.
      No fonts from Google, no CDN, no telemetry.

## 5. The PDF

- [ ] From any case, *Export case report* downloads a PDF that opens.
- [ ] It carries the entity, the reason, the evidence, the neighbourhood
      figure, and the evidence seal at the foot (ledger head plus the SHA-256
      of the data it was made from).
- [ ] `python -m custody log` shows an `export.case_report` entry whose
      `report_sha256` matches `sha256sum` of the file you just downloaded.

## 6. The suite

- [ ] `.venv/bin/python -m pytest -q` passes with the network down.

---

## Running all of it at once

`offline/airgap_check.sh` does everything above that can be automated — the
pipeline, the API, the console's routes and assets, the graph endpoint, the PDF
(including checking it really is a PDF), the live monitor, the custody
verification, the source scan and the suite — inside a namespace with no
network:

```sh
unshare -rn sh -c 'ip link set lo up; ./offline/airgap_check.sh'
```

It prints PASS/FAIL per item and exits non-zero if anything failed. It does not
replace opening the console in a browser: no script can tell you the graph
*looks* right.

## Known limits, said out loud

* **GeoIP is manual.** MaxMind requires an account; `offline/GEOIP_SETUP.md`
  explains what is lost without it (country and ASN columns null) and what is
  not (everything else).
* **The bundle is built for one Python version and one platform.** Rebuild with
  `--python-version` / `--platform` for a different target.
* **`data/` travels with the bundle** if you tar the working tree. That is
  convenient for a demo and wrong for real case data — exclude it, or clear it,
  before handing a bundle to anyone.
* **The models are trained on synthetic data** from `generator/`. Every metric
  in `eval/results.md` says so, and the case report repeats it on the page.

## During the demo

- [ ] Keep `offline/run_offline.sh`'s output visible. It prints the commit it
      started with — the same string the banner would complain about.
- [ ] If the red build banner appears mid-demo, something restarted the API.
      Stop, restart with the launcher, reload the page.
