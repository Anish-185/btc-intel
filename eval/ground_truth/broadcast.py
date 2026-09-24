"""Broadcast N signet transactions from a known address, and label them.

Runs on the **collection host**, beside a signet `bitcoind`. It is the only file
in this package that touches anything outside the repository, and it reaches
bitcoind through `bitcoin-cli` on loopback — never the network directly. Nothing
on the analysis side imports it, and a test asserts that, for the same reason
`p2p/` keeps its capture reader socket-free: the air gap is a property of the
import graph, not a sentence in a document.

    python -m eval.ground_truth.broadcast \
        --datadir ~/.bitcoin --n 50 --interval 20 \
        --true-origin-ip 203.0.113.9 --condition non_adjacent \
        --observer-ip 198.51.100.2 \
        --out data/ground_truth/2026-09-24-non_adjacent.labels.json

WHY THE WTXID IS COMPUTED HERE
A capture taken from a node's `debug.log` sees `got inv: wtx <hash>`, and a
wtxid is not a txid for any segwit transaction (BIP-339). A log-only capture
therefore cannot say which transaction an announcement was about. The
broadcaster holds the raw transaction, so it can compute both identifiers and
put them in the label file — which is what lets `resolve_from_labels` recover
those rows later. This is the whole reason the label file carries `raw_hex`.
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from p2p.capture_reader import txids_of

log = logging.getLogger(__name__)

#: The two topology conditions, reported separately and never pooled. See
#: docs/GROUND_TRUTH.md for how each is forced and verified.
CONDITIONS = ("adjacent", "non_adjacent")

#: What produced a label file. The report prints this verbatim in its first
#: line, so a simulated or fixture run can never be read as a signet result.
SOURCES = ("signet", "simulated", "synthetic-test-fixture")


def _cli(datadir: str | None, network: str, args: list[str],
         runner=subprocess.run) -> str:
    """One bitcoin-cli call. `runner` is injectable so the label-file logic is
    testable on a machine with no bitcoind — which is every machine in CI."""
    command = ["bitcoin-cli", f"-chain={network}"]
    if datadir:
        command.append(f"-datadir={datadir}")
    command += args
    done = runner(command, capture_output=True, text=True, check=False)
    if done.returncode != 0:
        raise RuntimeError(f"bitcoin-cli {' '.join(args)} failed: {done.stderr.strip()}")
    return done.stdout.strip()


def peer_addresses(datadir: str | None = None, network: str = "signet",
                   runner=subprocess.run) -> list[dict]:
    """`getpeerinfo`, trimmed to what the topology check needs.

    The adjacency condition is *verified*, not assumed: whether the observer is
    in this list is the difference between the two rows of the result table.
    """
    peers = json.loads(_cli(datadir, network, ["getpeerinfo"], runner) or "[]")
    return [{"addr": p.get("addr"), "id": p.get("id"), "subver": p.get("subver"),
             "inbound": p.get("inbound")} for p in peers]


def verify_condition(condition: str, observer_ip: str | None, peers: list[dict]) -> dict:
    """Is the broadcaster actually peered with the observer, or actually not.

    A run whose claimed topology does not match `getpeerinfo` is the one failure
    that would silently turn the real result into the trivial one, so it is
    checked at broadcast time, recorded in the label file, and checked again in
    preflight.
    """
    if condition not in CONDITIONS:
        raise ValueError(f"condition must be one of {CONDITIONS}, not {condition!r}")
    addresses = {str(p.get("addr", "")).rsplit(":", 1)[0].strip("[]") for p in peers}
    adjacent = observer_ip in addresses if observer_ip else None
    expected = condition == "adjacent"
    ok = adjacent is not None and adjacent == expected
    return {"condition": condition, "observer_is_a_peer": adjacent,
            "peers": len(peers), "as_claimed": ok,
            "detail": ("verified against getpeerinfo" if ok else
                       "observer_ip not given — condition unverified" if adjacent is None
                       else f"claimed {condition} but observer_is_a_peer={adjacent}")}


def send_one(datadir: str | None, network: str, address: str, amount: float,
             runner=subprocess.run) -> dict:
    """Send one transaction and return its two identifiers and its raw bytes."""
    txid = _cli(datadir, network, ["sendtoaddress", address, f"{amount:.8f}"], runner)
    sent_at = datetime.now(timezone.utc)
    raw_hex = _cli(datadir, network, ["getrawtransaction", txid], runner)
    computed_txid, wtxid = txids_of(bytes.fromhex(raw_hex))
    if computed_txid != txid:
        # Either the node returned a different transaction or our serialisation
        # is wrong. Both are fatal to a ground-truth run: a label file whose
        # txid does not match its raw_hex labels the wrong transaction.
        raise RuntimeError(f"txid mismatch: node says {txid}, raw_hex hashes to "
                           f"{computed_txid}")
    return {"txid": txid, "wtxid": wtxid, "raw_hex": raw_hex,
            "broadcast_wall_clock": sent_at.isoformat(timespec="microseconds")}


def intervals(n: int, interval: float, jitter: float, seed: int) -> list[float]:
    """Controlled, reproducible gaps between broadcasts.

    Jitter is deliberate: transactions sent on an exact cadence are separable by
    their arrival pattern alone, which would flatter any timing estimator.
    """
    rng = random.Random(seed)
    return [max(0.0, interval + rng.uniform(-jitter, jitter)) for _ in range(max(0, n - 1))]


def run(n: int, address: str, true_origin_ip: str, condition: str, out: Path,
        datadir: str | None = None, network: str = "signet", amount: float = 0.0001,
        interval: float = 20.0, jitter: float = 5.0, seed: int = 41,
        observer_ip: str | None = None, runner=subprocess.run, sleep=time.sleep) -> dict:
    """Broadcast, label, write. Returns the label document."""
    peers = peer_addresses(datadir, network, runner)
    topology = verify_condition(condition, observer_ip, peers)
    if not topology["as_claimed"]:
        raise RuntimeError(
            f"refusing to broadcast: {topology['detail']}. Fix the peering first — "
            "docs/GROUND_TRUTH.md explains how to force each condition")

    gaps = intervals(n, interval, jitter, seed)
    transactions = []
    for i in range(n):
        record = send_one(datadir, network, address, amount, runner)
        record.update(true_origin_ip=true_origin_ip, topology_condition=condition)
        transactions.append(record)
        log.info("%d/%d %s", i + 1, n, record["txid"])
        if i < len(gaps):
            sleep(gaps[i])

    document = {
        "source": "signet",
        "network": network,
        "topology_condition": condition,
        "true_origin_ip": true_origin_ip,
        "observer_local_ips": [observer_ip] if observer_ip else [],
        "topology_check": topology,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "transactions": transactions,
    }
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(document, indent=2) + "\n")
    return document


# --- the label file, read back on the analysis side ----------------------
def load_labels(path) -> dict:
    """Read a label file and reject one that cannot support a measurement."""
    document = json.loads(Path(path).read_text())
    if document.get("source") not in SOURCES:
        raise ValueError(f"label file has no recognised source: {document.get('source')!r} "
                         f"(expected one of {SOURCES})")
    if not document.get("transactions"):
        raise ValueError("label file carries no transactions")
    return document


def truth_of(labels: dict) -> dict[str, str]:
    """txid -> the address that really originated it."""
    fallback = labels.get("true_origin_ip")
    return {t["txid"]: t.get("true_origin_ip") or fallback
            for t in labels["transactions"]}


def wtxid_map(labels: dict) -> dict[str, str]:
    """wtxid -> txid, for the rows a log-only capture could not resolve."""
    return {t["wtxid"]: t["txid"] for t in labels["transactions"]
            if t.get("wtxid") and t.get("txid")}


def resolve_from_labels(events: list, labels: dict) -> dict:
    """Rewrite `inv_wtx` rows using the broadcaster's own wtxid -> txid map.

    This is the step a capture cannot do for itself: the observer saw only a
    wtxid, and only the sender knew which transaction it belonged to.
    """
    mapping = wtxid_map(labels)
    before = sum(1 for e in events if e.message_type == "inv_wtx")
    recovered = 0
    for event in events:
        if event.message_type == "inv_wtx" and event.txid in mapping:
            event.txid = mapping[event.txid]
            event.message_type = "inv"
            recovered += 1
    return {"unresolved_before": before, "recovered": recovered,
            "unresolved_after": before - recovered,
            "recovered_share": round(recovered / before, 4) if before else 0.0}


def main(argv=None) -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    ap = argparse.ArgumentParser(prog="eval.ground_truth.broadcast", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--n", type=int, default=50)
    ap.add_argument("--address", required=True, help="a signet address to pay (your own)")
    ap.add_argument("--true-origin-ip", required=True, help="this broadcaster's address")
    ap.add_argument("--condition", choices=CONDITIONS, required=True)
    ap.add_argument("--observer-ip", default=None,
                    help="the observer's address; required to verify the condition")
    ap.add_argument("--out", required=True)
    ap.add_argument("--datadir", default=None)
    ap.add_argument("--network", default="signet")
    ap.add_argument("--amount", type=float, default=0.0001)
    ap.add_argument("--interval", type=float, default=20.0)
    ap.add_argument("--jitter", type=float, default=5.0)
    ap.add_argument("--seed", type=int, default=41)
    args = ap.parse_args(argv)
    document = run(args.n, args.address, args.true_origin_ip, args.condition, Path(args.out),
                   args.datadir, args.network, args.amount, args.interval, args.jitter,
                   args.seed, args.observer_ip)
    print(json.dumps({"transactions": len(document["transactions"]),
                      "condition": document["topology_condition"],
                      "topology_check": document["topology_check"],
                      "out": args.out}, indent=2))


if __name__ == "__main__":
    main()
