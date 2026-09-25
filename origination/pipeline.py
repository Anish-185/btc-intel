"""CLI for the supervised origination model.

    python -m origination.pipeline corpus              # build or reuse the corpus
    python -m origination.pipeline evaluate            # fit, score, save the model
    python -m origination.pipeline predict \\
        --input data/processed/features_relay.parquet  # score a real relay matrix

`evaluate` prints the section-9 rows; eval/results.md itself is only ever
written by `python -m eval.report`.
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

import pandas as pd

import config

from . import corpus, evaluate
from .model import OriginationModel


def main(argv=None) -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    cfg = config.load()
    o = cfg["origination"]
    ap = argparse.ArgumentParser(prog="origination.pipeline", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["corpus", "evaluate", "predict"])
    ap.add_argument("--rebuild", action="store_true", help="regenerate the corpus")
    ap.add_argument("--workers", type=int, default=None)
    ap.add_argument("--model", default=o["model_path"])
    ap.add_argument("--input", default=cfg["features"]["relay_path"])
    ap.add_argument("--output", default=o["output_path"])
    args = ap.parse_args(argv)

    if args.command == "corpus":
        directory = corpus.build(cfg, rebuild=args.rebuild, workers=args.workers)
        print(json.dumps({"corpus": str(directory),
                          **json.loads((directory / "summary.json").read_text())}, indent=2))
    elif args.command == "evaluate":
        result = evaluate.run(cfg, args.rebuild, args.workers)
        path = result["model"].save(args.model)
        for role, table in result["tables"].items():
            print(f"\n{evaluate.TEST_SETS[role]} (condition=simulated)")
            print(table.to_string(index=False))
        print("\n" + json.dumps({"verdict": result["verdict"], "split": result["split"],
                                 "reliability": result["reliability"],
                                 "model": str(path)}, indent=2, default=str))
        print("\n" + result["omissions"])
    else:
        model = OriginationModel.load(args.model)
        out = model.predict(pd.read_parquet(args.input), cfg)
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        out.to_parquet(args.output, index=False)
        print(json.dumps({"rows": len(out), "output": args.output,
                          "abstained_by_construction": int((out["abstain_reason"] != "").sum())},
                         indent=2))


if __name__ == "__main__":
    main()
