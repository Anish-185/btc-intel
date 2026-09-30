"""A demo capture derived from the served relay-hop dataset.

    python -m p2p.demo_capture
    python -m features.relay --input data/processed/demo_capture \
        --observer-ip 198.51.100.250

The served dataset is a multi-point relay log: rows of sends between nodes,
src -> dst, sampled at `relay_observation_rate`. This folds it into ONE
capture: the observer is the collection itself (a TEST-NET address standing
for the collector, not a node), and each node seen sending a transaction is a
candidate peer, timed from its first send. Per transaction that is the same
candidate set `engines.propagation` ranks on the TXID page.

Why pooled and not per node: the gossip simulation delivers each transaction
to a node once, so any single node's view has one candidate per transaction —
degenerate by construction, and the origination model rightly abstains on all
of it. The pooled capture is non-degenerate, and its txids are the served
dataset's, so the relay matrix, the origination model's answers and the served
clusters describe the same transactions.

What it is not: a node's capture. The origination model was trained on
single-observer captures; on this pooled view its confidences are out of
distribution, and the TXID page shows them beside `engines.propagation`'s own
estimate, not instead of it. Stamped `sim:` in `capture_source`, so every
profile and report built from it says it is simulated.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

import config
from graph.builder import load

#: The collector's address: TEST-NET-2, never a simulated node.
COLLECTOR = "198.51.100.250"


def capture_rows(df: pd.DataFrame) -> list[dict]:
    """Each sender's first send of each txid, as an announcement to the collector."""
    first = df.sort_values("timestamp", kind="stable").drop_duplicates(["txid", "src_ip"])
    return [{"txid": str(r.txid), "message_type": "inv", "peer_ip": str(r.src_ip),
             "peer_port": int(r.src_port), "wall_clock_ts": pd.Timestamp(r.timestamp).timestamp(),
             "direction": "inbound", "capture_source": "sim:demo-hoplog"}
            for r in first.itertuples()]


def write(df: pd.DataFrame, out: Path) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    rows = capture_rows(df)
    path = out / "demo-hoplog.btcap"
    path.write_text("# derived from the served relay-hop dataset (simulated); "
                    "see p2p/demo_capture.py\n" + "".join(json.dumps(r) + "\n" for r in rows))
    return {"path": str(path), "observer": COLLECTOR, "events": len(rows),
            "transactions": len({r["txid"] for r in rows})}


def main(argv=None) -> None:
    cfg = config.load()
    ap = argparse.ArgumentParser(prog="p2p.demo_capture", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", default=cfg["ingest"]["output_path"])
    ap.add_argument("--output", default=str(Path(cfg["ingest"]["processed_dir"]) / "demo_capture"))
    args = ap.parse_args(argv)
    print(json.dumps(write(load(args.input, cfg), Path(args.output)), indent=2))


if __name__ == "__main__":
    main()
