"""parse -> validate -> enrich -> parquet.

    python -m ingest.pipeline --input data/raw/ --output data/processed/transactions.parquet

Bad records are quarantined with a reason, never dropped silently and never
allowed to kill the run. Output is one row per *relay observation*, so a txid
may appear several times — graph/ collapses that.
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

import pandas as pd

import config

from .geoip import COLUMNS as GEO_COLUMNS
from .geoip import GeoIp, enrich
from .parsers import PARSERS, parse
from .schema import RawTransaction, validate

log = logging.getLogger(__name__)
QUARANTINE_COLUMNS = ["source_file", "row", "reason", "raw"]
GROUND_TRUTH = "ground_truth.json"  # hidden labels — must never be ingested
NOT_DATA = {GROUND_TRUTH, "node_intel.json", "manifest.json"}


def resolve_input(path, fmt: str | None = None, cfg: dict | None = None) -> tuple[Path, str]:
    """A directory holds the same data in several formats — pick exactly one."""
    cfg = cfg or config.load()
    p = Path(path)
    if p.is_file():
        return p, (fmt or p.suffix.lstrip(".").lower())
    fmt = fmt or cfg["ingest"]["format"]
    if fmt not in PARSERS:
        raise ValueError(f"unknown format {fmt!r}; have {sorted(PARSERS)}")
    # ground_truth.json lives beside the data but is NOT input — it holds the labels
    candidates = [c for c in sorted(p.glob(f"*.{fmt}")) if c.name not in NOT_DATA]
    preferred = [c for c in candidates if c.stem == "transactions"]
    candidates = preferred or candidates
    if not candidates:
        raise FileNotFoundError(f"no .{fmt} file in {p} (set ingest.format or pass --format)")
    if len(candidates) > 1:
        raise ValueError(f"several .{fmt} files in {p}: {[c.name for c in candidates]} — pass one")
    return candidates[0], fmt


def run(input_path, output=None, quarantine=None, fmt: str | None = None,
        geo: GeoIp | None = None, cfg: dict | None = None) -> dict:
    cfg = cfg or config.load()
    src, fmt = resolve_input(input_path, fmt, cfg)
    output = Path(output or cfg["ingest"]["output_path"])
    quarantine = Path(quarantine or cfg["ingest"]["quarantine_path"])

    # ponytail: whole file in memory — fine to a few million rows; chunk by
    # row group if a real NTRO dump ever outgrows RAM.
    good, bad = [], []
    for n, record in parse(src, fmt, cfg):
        model, reason = validate(record)
        if model is None:
            bad.append({"source_file": src.name, "row": n, "reason": reason,
                        "raw": json.dumps(record, default=str)})
            continue
        row = model.model_dump()
        row["src_ip"] = str(row["src_ip"])
        row["dst_ip"] = str(row["dst_ip"])
        good.append(row)

    df = pd.DataFrame(good)
    if df.empty:  # keep the column contract even for an all-bad input
        df = pd.DataFrame(columns=list(RawTransaction.model_fields))
    enrich(df, geo or GeoIp(cfg), cfg=cfg)

    for path, frame in ((output, df), (quarantine, pd.DataFrame(bad, columns=QUARANTINE_COLUMNS))):
        path.parent.mkdir(parents=True, exist_ok=True)
        frame.to_parquet(path, index=False)

    summary = {"input": str(src), "format": fmt, "rows": len(df), "quarantined": len(bad),
               "transactions": int(df["txid"].nunique()) if len(df) else 0,
               "enriched": int(df["asn"].notna().sum()) if len(df) else 0,
               "output": str(output), "quarantine": str(quarantine)}
    if bad:
        top = pd.Series([b["reason"] for b in bad]).value_counts().head(5)
        summary["quarantine_reasons"] = top.to_dict()
    return summary


def main(argv=None) -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    cfg = config.load()
    ap = argparse.ArgumentParser(prog="ingest.pipeline", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", default=cfg["ingest"]["input_dir"])
    ap.add_argument("--output", default=cfg["ingest"]["output_path"])
    ap.add_argument("--quarantine", default=cfg["ingest"]["quarantine_path"])
    ap.add_argument("--format", dest="fmt", choices=sorted(PARSERS),
                    help=f"default: ingest.format in config.yaml ({cfg['ingest']['format']})")
    args = ap.parse_args(argv)
    print(json.dumps(run(args.input, args.output, args.quarantine, args.fmt), indent=2))


if __name__ == "__main__":
    main()
