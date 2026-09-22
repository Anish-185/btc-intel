# Offline checklist

Run through this on the machine that will be demonstrated, with its network
cable out. Every item is a thing that has actually gone wrong once.

## Before anything else

- [ ] **`config.yaml` has `offline: true`.** `offline/pipeline.py` asserts it;
      the assert is there because a single stray fetch turns an air-gapped
      claim into a false one.
- [ ] **Intel snapshots are on disk.** `data/intel/` holds the Bitnodes and Tor
      exit lists fetched earlier by `offline/fetch_intel.sh`. Nothing fetches
      them at run time; a missing file degrades classification, it does not
      reach out.
- [ ] **GeoIP databases are present** (`data/geoip/*.mmdb`) or accept that the
      country and ASN columns will be empty — the pipeline says so in its log
      rather than failing.

## The two checks that cost us an hour each

- [ ] **Port 8000 is free, and you started the server with the launcher.**

      ```sh
      offline/run_offline.sh --check     # prints "port 8000 is free", or the owner
      offline/run_offline.sh             # starts it, stamped with the commit
      ```

      `run_offline.sh` refuses to start a second server and prints the pid,
      start time and command line of whatever holds the port. The failure it
      prevents: an old uvicorn keeps the port, the new one exits into a log
      nobody is reading, and the browser spends the next hour talking to a
      build from before the fix.

      If the port is held by a process you want gone: `kill <pid>` and run it
      again. To run beside it instead: `PORT=8010 offline/run_offline.sh`.

- [ ] **The console and the API are the same build.**

      ```sh
      curl -s 127.0.0.1:8000/version          # {"commit": "...", "started_at": ..., "routes": N}
      grep -o '"[0-9a-f]\{7\}"' web/dist/assets/index-*.js | head   # the compiled-in commit
      ```

      The console does this comparison itself on every page load and shows a
      red banner when the two differ, or when `/version` does not answer at
      all. **If that banner is on screen, stop and fix it — nothing below it
      can be trusted.** Rebuild the front end (`npm --prefix web run build`)
      and restart the API with the launcher.

## The front end

- [ ] **`npm --prefix web run build` succeeds**, and
      **`npm --prefix web run check:offline` says "no external requests in
      dist"**. It lists the URLs that exist only as strings inside library
      licence banners; read the list, do not skim past a new entry.
- [ ] **Fonts are local.** IBM Plex ships from `@fontsource` in
      `dist/assets/`. No `<link>` to Google Fonts anywhere.
- [ ] Open the console with the network down and click through Overview →
      Alert queue → a case → Investigation graph. Nothing should hang.

## The data

- [ ] `data/processed/final_alerts.json` exists and is newer than the parquet
      it came from. If not: `python -m fusion.pipeline`.
- [ ] `npm --prefix web run check:contrast` passes — it reads the tokens and
      checks every colour pair against WCAG AA.
- [ ] `python -m pytest -q` passes.

## During the demo

- [ ] Keep `offline/run_offline.sh`'s output visible in a terminal. It prints
      the commit it started with, which is the same string the banner would
      complain about.
- [ ] If the red build banner appears mid-demo, it means something restarted
      the API. Stop, restart with the launcher, reload the page.
