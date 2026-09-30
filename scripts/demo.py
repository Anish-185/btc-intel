"""The stage demo, one command: scripts/demo.sh (docs/DEMO_SCRIPT.md).

Drives the real API in-process (FastAPI's TestClient: no port, no server, no
socket) over the served demo dataset, one line per step:

  1 seed       a ransomware-collector address, and the entity it sits in
  2 capture    the sealed relay capture verifies against its manifest; replayed
  3 origin     candidate peers, calibrated probability, validity tier
  4 tiers      PASS; QUALIFIED CoinJoin (broadcaster only); ABSTAIN unreachable
  5 peer       start from an IP, pivot to its clusters
  6 queue      the entity alert queue, and one actor drilled down to evidence
  7 cash-out   a ranked tagged candidate; a trace stopped at a CoinJoin
  8 packet     the investigator packet PDF, sealed in a fresh custody ledger
  9 air gap    the offline guarantee test live, then 1-8 again with no network

Every run writes to its own fresh ledger under data/processed/demo/, never to
the case ledger, so the chain shown on stage holds only this run.

    scripts/demo.sh               # the demo
    scripts/demo.sh --pause       # wait for Enter between steps
    scripts/demo.sh --preflight   # before going on stage: every artifact and hash
    scripts/demo.sh --pin         # after a deliberate rebuild: re-pin the hashes

Everything shown is simulated: the served dataset is generator seed 41, and
every tag in the demo bundle is source="simulated".
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import warnings
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
os.chdir(ROOT)
sys.path.insert(0, str(ROOT))
warnings.filterwarnings("ignore")
logging.disable(logging.WARNING)

import config
from api.format_id import format_id as short

PINS = ROOT / "scripts" / "demo_pins.json"
DEMO_DIR = Path("data/processed/demo")

# --- the case the demo walks through (all in the served dataset, seed 41) ------
SEED = "3f5c84f9837c78be7fab0aa3cd01c2a561"       # ransomware collector C000531
ORIGIN_TX = "cd08f05a8b23fe68986454444414a7c8ffa155137793bd844b897fec3f08eae9"  # its peel
COINJOIN_TX = "50bccba8322c865bd0bb2021f7fb3b2df336854d4a4ef7ac6888ad03fa168c28"
PEER = "117.200.191.191"
ACTOR = "A-302"
MIXED_SEED = "bc1q672a86e0d4ca137fa64db84ffd4e3e0ea37555"   # a CoinJoin participant
CAPTURE_DIR = Path("data/processed/demo_capture")
# ABSTAIN / NOT_REACHABLE does not occur in the served capture (a pooled
# collector always sees a non-relay). This held-out capture of the origination
# corpus (origination/manifest.json) is where it does: every peer that
# announced the transaction is a listed public relay (eval/results.md §9).
CORPUS_DIR = Path("data/processed/eval/origination/3f2d3bbe9a1f7088")
UNREACHABLE_CAPTURE = "relay_hub-n600-r0.04-g0-c10"
UNREACHABLE_TX = "058ee8046bee8702f9300a3673b427893da6b982b6ae5abfb851fdfe1ced25f2"


def artifacts(cfg: dict) -> list[Path]:
    """Every file the demo reads. --preflight hashes each against the pins."""
    tags = Path(cfg["tags"]["store_dir"])
    return [Path(p) for p in (
        Path(cfg["ingest"]["input_dir"]) / "transactions.csv",
        Path(cfg["ingest"]["input_dir"]) / "ground_truth.json",
        Path(cfg["ingest"]["input_dir"]) / "node_intel.json",
        cfg["ingest"]["output_path"], cfg["fusion"]["alerts_json"],
        cfg["fusion"]["actors_json"], cfg["fusion"]["model_path"],
        cfg["features"]["relay_path"], cfg["origination"]["model_path"],
        cfg["features"]["fingerprint"]["model_path"],
        CAPTURE_DIR / "demo-hoplog.btcap", CAPTURE_DIR / "manifest.json",
        CORPUS_DIR / "matrix.parquet",
        *sorted(tags.glob("*/manifest.json")),
        *sorted(Path("data/intel").glob("*")))]


# --- the steps -----------------------------------------------------------------
class Demo:
    """One run: a fresh ledger, one in-process client. Each step returns the
    line to print and the part of it that must be identical on a rerun (no
    timestamps, file hashes of generated PDFs, or ledger paths)."""

    def __init__(self, ledger: Path):
        self.cfg = config.load()                 # lru_cached: every module shares it
        self.cfg["custody"]["ledger_path"] = str(ledger)
        from fastapi.testclient import TestClient

        from api.app import app
        self.client = TestClient(app)
        self.ledger = ledger

    def get(self, path: str):
        response = self.client.get(path)
        if response.status_code != 200:
            raise RuntimeError(f"GET {path} -> {response.status_code}: {response.text[:200]}")
        return response

    def seed(self):
        from api.app import _features
        entity = _features()[1].entity_of(SEED)
        e = self.get(f"/entities/{entity}").json()
        line = (f"address {short(SEED)} sits in entity {short(entity)} "
                f"({len(e['wallets'])} wallets): {' + '.join(e['pattern_types'])}, "
                f"alert {e['queue_position']['rank']} of {e['queue_position']['of']}, "
                f"risk {e['scores']['risk_score']:.3f}")
        return line, line

    def capture(self):
        from p2p import manifest
        from p2p.capture_reader import read_directory
        v = manifest.verify_capture(CAPTURE_DIR, self.cfg, record=True)
        if not v["ok"]:
            raise RuntimeError(f"capture does not verify: {v}")
        events = read_directory(CAPTURE_DIR, self.cfg)
        line = (f"{CAPTURE_DIR.name} verifies against its seal (manifest "
                f"{short(v['manifest_hash'])}, {v['files']} file, nothing changed or "
                f"added); replayed {len(events)} announcements of "
                f"{len({e.txid for e in events})} transactions from "
                f"{len({e.peer_ip for e in events})} peers")
        return line, line

    def origin(self):
        import pandas as pd
        matrix = pd.read_parquet(self.cfg["features"]["relay_path"],
                                 columns=["txid", "peer_ip", "announce_rank"])
        peers = matrix[matrix.txid == ORIGIN_TX].sort_values("announce_rank").peer_ip
        a = self.get(f"/transactions/{ORIGIN_TX}/origination").json()["captures"][0]
        truth = self.truth(ORIGIN_TX)
        line = (f"tx {short(ORIGIN_TX)}: candidates {', '.join(peers)}; model names "
                f"{a['named_peer']} at calibrated p={a['probability']:.3f}, tier "
                f"{a['validity']['tier']}; generator truth {truth} "
                f"({'agrees' if truth == a['named_peer'] else 'DISAGREES'})")
        return line, line

    def tiers(self):
        import pandas as pd

        from engines.correlation.profile import origination_answers
        from origination.model import OriginationModel
        ok = self.get(f"/transactions/{ORIGIN_TX}/origination").json()["captures"][0]
        cj = self.get(f"/transactions/{COINJOIN_TX}/origination").json()["captures"][0]
        rows = pd.read_parquet(CORPUS_DIR / "matrix.parquet",
                               filters=[("capture_id", "==", UNREACHABLE_CAPTURE)])
        model = OriginationModel.load(self.cfg["origination"]["model_path"])
        no = origination_answers(model, rows, self.cfg, {})
        no = no[no.txid == UNREACHABLE_TX].iloc[0]
        line = (f"PASS {short(ORIGIN_TX)} -> {ok['answer']['ip']} | "
                f"{cj['validity']['tier']} {cj['validity']['reason']} {short(COINJOIN_TX)} -> "
                f"broadcaster {cj['answer']['ip']} only, inputs "
                f"{cj['answer']['input_ownership'].split(':')[0]} | "
                f"{no.validity_tier} {no.validity} {short(UNREACHABLE_TX)} (corpus capture "
                f"{UNREACHABLE_CAPTURE}): answered={bool(no.answered)}, all "
                f"{int(no.n_candidates)} announcers are listed relays")
        return line, line

    def peer(self):
        p = self.get(f"/peers/{PEER}/profile").json()
        links = ", ".join(f"{short(c['cluster_id'])} ({c['basis']}, {c['confidence']:.2f})"
                          for c in p["linked_clusters"])
        tiers = ", ".join(f"{k} {v}" for k, v in p["originated"]["by_tier"].items() if v)
        line = (f"{PEER}: {p['originated']['claimed']} originated claim(s) ({tiers}); "
                f"pivots to cluster(s) {links}; "
                f"{'simulated only' if p['header']['simulated_only'] else 'NOT simulated'}")
        return line, line

    def queue(self):
        q = self.get("/alerts?limit=3").json()
        top = q["alerts"][0]
        actor = self.get(f"/actors/{ACTOR}").json()
        tx = actor["drill_down"]["transactions"][0]
        evidence = next(e for lk in actor["links"] for e in lk["evidence"]
                        if e["txid"] == tx)
        row = evidence["rows"][0]
        line = (f"{q['total']} entity alerts (the default queue); #1 {short(top['entity_id'])} "
                f"risk {top['risk_score']:.3f} | actor {ACTOR}: {len(actor['members'])} "
                f"cluster + {len(actor['peers'])} peers, drill-down {tx[:12]}… -> "
                f"{row['source']} row, {row.get('peer') or row.get('src')} at "
                f"{(row.get('announce_ts') or row.get('timestamp'))[11:19]}")
        return line, line

    def cash_out(self):
        t = self.get(f"/exit-points/address/{SEED}").json()["traces"][0]
        c = t["candidates"][0]
        m = self.get(f"/exit-points/entity/{MIXED_SEED}").json()["traces"][0]
        mix = next(x for ms in m["mixes"].values() for x in ms)
        line = (f"from the seed: {len(t['candidates'])} ranked candidates; #1 "
                f"{short(c['entity_id'])} \"{c['tags'][0]['label']}\" "
                f"(source {c['tags'][0]['source']}), haircut share "
                f"{c['models']['haircut']['share']:.1%} over "
                f"{len(c['models']['haircut']['paths'][0]['hops'])} hop(s) | from "
                f"{short(MIXED_SEED)}: {len(m['candidates'])} candidates, stopped: "
                f"funds entered CoinJoin {short(mix['txids'][0])}")
        return line, line

    def packet(self):
        r = self.client.get(f"/exit-points/address/{SEED}/packet")
        pdf = r.content
        if r.status_code != 200 or not pdf.startswith(b"%PDF"):
            raise RuntimeError(f"packet: {r.status_code}")
        out = self.ledger.with_suffix(".packet.pdf")
        out.write_bytes(pdf)
        v = self.get("/custody/verify").json()
        import custody
        actions = [e["action"] for e in custody.read(self.cfg)]
        stable = (f"packet PDF sealed at ledger entry {r.headers['x-custody-entry']}; "
                  f"fresh ledger: {v['entries']} entries, chain "
                  f"{'intact' if v['chain_intact'] else 'BROKEN'}: {', '.join(actions)}")
        line = (f"{out} ({len(pdf):,} bytes, sha256 {short(hashlib.sha256(pdf).hexdigest())}) "
                f"| {stable} | {self.ledger}")
        return line, stable

    @staticmethod
    def truth(txid: str) -> str:
        gt = json.loads((Path(config.load()["ingest"]["input_dir"]) / "ground_truth.json")
                        .read_text())
        return gt["transactions"][txid]["true_origin_ip"]


STEPS = [("seed", Demo.seed), ("capture", Demo.capture), ("origin", Demo.origin),
         ("tiers", Demo.tiers), ("peer", Demo.peer), ("queue", Demo.queue),
         ("cash-out", Demo.cash_out), ("packet", Demo.packet)]


def fresh_ledger(tag: str = "") -> Path:
    DEMO_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    return DEMO_DIR / f"custody-{stamp}{tag}.jsonl"


def run_steps(ledger: Path, pause: bool = False, echo: bool = True) -> tuple[str, int]:
    """Steps 1-8. Returns the digest of their stable output and how many failed.
    A failed step prints what failed and the demo goes on: on stage the next
    step is worth more than a traceback (docs/DEMO_SCRIPT.md has the lines)."""
    demo = Demo(ledger)
    stable, failed = [], 0
    for n, (name, step) in enumerate(STEPS, 1):
        if pause:
            input(f"  [Enter] step {n}: {name} ")
        try:
            line, fixed = step(demo)
        except Exception as exc:  # noqa: BLE001 — a failed step is shown, and the demo goes on
            failed += 1
            line = fixed = f"FAILED: {type(exc).__name__}: {exc}"
        stable.append(fixed)
        if echo:
            print(f"{n} {name:<9} {line}", flush=True)
    return hashlib.sha256("\n".join(stable).encode()).hexdigest(), failed


def interfaces() -> list[str]:
    """This process's network interfaces, from its own network namespace."""
    lines = Path("/proc/self/net/dev").read_text().splitlines()[2:]
    return [line.split(":")[0].strip() for line in lines]


def air_gap(digest: str) -> None:
    test = subprocess.run([sys.executable, "-m", "pytest", "tests/test_offline_guarantee.py",
                           "-q", "-p", "no:cacheprovider"], capture_output=True, text=True, check=False)
    summary = (test.stdout.strip().splitlines() or ["no output"])[-1]
    if test.returncode:
        raise RuntimeError(f"the offline guarantee test failed: {summary}")
    unshare = shutil.which("unshare")
    cmd = [sys.executable, str(Path(__file__)), "--rerun"]
    where = "no network namespace available: same process tree, network untouched"
    if unshare and subprocess.run([unshare, "-rn", "true"], capture_output=True, check=False).returncode == 0:
        cmd = [unshare, "-rn", *cmd]
        where = "inside a network namespace"
    rerun = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if rerun.returncode:
        raise RuntimeError(f"rerun failed: {rerun.stderr.strip()[-400:]}")
    inside = json.loads(rerun.stdout.strip().splitlines()[-1])
    same = "identical" if inside["digest"] == digest else "DIFFERENT"
    print(f"9 air gap   tests/test_offline_guarantee.py: {summary} | steps 1-8 rerun {where} "
          f"(interfaces: {', '.join(inside['interfaces']) or 'none'}): output {same} "
          f"(digest {short(digest)})", flush=True)
    if same != "identical":
        raise RuntimeError("the rerun did not reproduce steps 1-8")


# --- preflight -----------------------------------------------------------------
def sha(path: Path) -> str:
    import custody
    return custody.sha256_file(path)


def pin() -> None:
    cfg = config.load()
    digest, failed = run_steps(fresh_ledger("-pin"), echo=False)
    if failed:
        raise SystemExit(f"{failed} step(s) failed; nothing pinned (run the demo to see which)")
    PINS.write_text(json.dumps({"digest": digest, "files": {
        str(p): sha(p) for p in artifacts(cfg)}}, indent=2) + "\n")
    print(f"pinned {len(artifacts(cfg))} files and digest {short(digest)} -> {PINS}")


def preflight() -> int:
    cfg = config.load()
    pins = json.loads(PINS.read_text()) if PINS.exists() else {"files": {}, "digest": None}
    bad = 0

    def report(ok: bool, what: str) -> None:
        nonlocal bad
        bad += not ok
        print(f"  {'PASS' if ok else 'FAIL'}  {what}", flush=True)

    for path in artifacts(cfg):
        if not path.exists():
            report(False, f"{path}: missing")
            continue
        digest, want = sha(path), pins["files"].get(str(path))
        report(digest == want, f"{path} {short(digest)}"
               + ("" if digest == want else f" (pinned {short(want or 'nothing')})"))
    unpinned = set(pins["files"]) - {str(p) for p in artifacts(cfg)}
    report(not unpinned, f"no pinned file has disappeared from the list {sorted(unpinned)}")

    from intel.store import load
    bundles = load(cfg).header()["bundles"]
    report(bool(bundles) and all(b["ok"] for b in bundles),
           f"tag bundles re-verify against their seals: {[b['name'] for b in bundles]}")
    report(all(b.get("simulated") for b in bundles), "every tag bundle is marked simulated")
    report(bool(shutil.which("unshare"))
           and subprocess.run(["unshare", "-rn", "true"], capture_output=True, check=False).returncode == 0,
           "unshare -rn works (step 9's network namespace)")
    try:
        digest, failed = run_steps(fresh_ledger("-preflight"), echo=False)
        report(not failed and digest == pins["digest"],
               f"steps 1-8 dry run, {failed} failed, digest {short(digest)}"
               + ("" if digest == pins["digest"] else f" (pinned {short(pins['digest'] or '')})"))
    except Exception as exc:  # noqa: BLE001 — a failed dry run is the answer, not a crash
        report(False, f"steps 1-8 dry run: {type(exc).__name__}: {exc}")
    print(f"\n{'READY' if not bad else f'NOT READY: {bad} check(s) failed'}")
    return 1 if bad else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="scripts/demo.sh", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--preflight", action="store_true", help="check every artifact and hash")
    ap.add_argument("--pin", action="store_true", help="record the current artifacts' hashes")
    ap.add_argument("--pause", action="store_true", help="wait for Enter before each step")
    ap.add_argument("--rerun", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    if args.pin:
        pin()
        return 0
    if args.preflight:
        return preflight()
    if args.rerun:                               # step 9's child: quiet, one JSON line
        digest, failed = run_steps(fresh_ledger("-airgap"), echo=False)
        print(json.dumps({"digest": digest, "failed": failed, "interfaces": interfaces()}))
        return 0
    print("btc-intel demo — simulated data throughout (generator seed 41, simulated tags)\n")
    digest, failed = run_steps(fresh_ledger(), pause=args.pause)
    if args.pause:
        input("  [Enter] step 9: air gap ")
    try:
        air_gap(digest)
    except Exception as exc:  # noqa: BLE001 — shown like steps 1-8
        failed += 1
        print(f"9 air gap   FAILED: {exc}", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
