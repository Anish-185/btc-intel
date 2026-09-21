"""CLI for origin estimation.

    python -m engines.propagation.pipeline --input data/processed/transactions.parquet \
        --output data/processed/tx_origins.parquet
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

import config
from graph.builder import load
from ingest.ip_intel import load_intel

from .estimators import ESTIMATORS, estimate_all

log = logging.getLogger(__name__)


def run(input_path=None, output=None, intel_dir=None, node_intel=None,
        estimator: str | None = None, cfg: dict | None = None) -> dict:
    cfg = cfg or config.load()
    df = load(input_path, cfg)
    intel = load_intel(intel_dir, node_intel or cfg["ingest"]["input_dir"], cfg)
    origins, status = estimate_all(df, intel, cfg, estimator)

    output = Path(output or cfg["engines"]["propagation"]["output_path"])
    output.parent.mkdir(parents=True, exist_ok=True)
    origins.to_parquet(output, index=False)

    if status["degraded"]:
        log.warning("DEGRADED MODE: %s", status["reason"])
    return {"transactions": len(origins),
            "estimator": estimator or cfg["engines"]["propagation"]["estimator"],
            "degraded_mode": status,
            "by_class": origins["ip_class"].value_counts().to_dict() if len(origins) else {},
            "mean_confidence": round(float(origins["confidence"].mean()), 4) if len(origins) else 0.0,
            "intel": {"known_relays": len(intel.relays), "tor_exits": len(intel.tor),
                      "hosting_asns": len(intel.hosting_asns)},
            "output": str(output)}


def main(argv=None) -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    cfg = config.load()
    ap = argparse.ArgumentParser(prog="engines.propagation.pipeline", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", default=cfg["ingest"]["output_path"])
    ap.add_argument("--output", default=cfg["engines"]["propagation"]["output_path"])
    ap.add_argument("--intel-dir", default=cfg["intel"]["dir"])
    ap.add_argument("--node-intel", default=cfg["ingest"]["input_dir"])
    ap.add_argument("--estimator", choices=sorted(ESTIMATORS), default=None)
    args = ap.parse_args(argv)
    print(json.dumps(run(args.input, args.output, args.intel_dir, args.node_intel,
                         args.estimator), indent=2))


if __name__ == "__main__":
    main()
