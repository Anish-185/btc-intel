"""Canonical evaluation datasets.

Every figure in eval/results.md comes from datasets built here, with the seed
and sizes fixed in config.yaml under `eval:`. Nothing in the report may come
from an ad-hoc run — two different ad-hoc runs is exactly how this repo ended
up quoting two different "ceiling" figures for the same statistic.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

import config
from generator.main import build_parser, generate
from ingest.pipeline import run as ingest_run


@dataclass
class Dataset:
    name: str
    directory: Path
    raw: Path
    rate: float
    shifted: bool
    seed: int

    @property
    def transactions(self) -> Path:
        return self.directory / "transactions.parquet"

    def ground_truth(self) -> dict:
        return json.loads((self.raw / "ground_truth.json").read_text())

    def watchlist(self) -> dict:
        path = self.raw / "synthetic_watchlist.json"
        return json.loads(path.read_text()) if path.exists() else {"wallets": []}

    def frame(self) -> pd.DataFrame:
        return pd.read_parquet(self.transactions)

    def describe(self) -> str:
        mode = "shifted" if self.shifted else "standard"
        return (f"{mode}, seed {self.seed}, observation rate {self.rate}, "
                f"{self.n_actors} actors, {self.n_transactions} transactions")

    n_actors: int = 0
    n_transactions: int = 0


def build(rate: float | None = None, shifted: bool = False, seed: int | None = None,
          cfg: dict | None = None, root: Path | None = None, rebuild: bool = False) -> Dataset:
    """Generate + ingest one dataset, cached on disk by its parameters."""
    cfg = cfg or config.load()
    e = cfg["eval"]
    rate = e["default_rate"] if rate is None else rate
    seed = e["seed"] if seed is None else seed
    root = Path(root or e["work_dir"])
    name = f"{'shifted' if shifted else 'standard'}-r{rate}-s{seed}"
    directory = root / name
    raw = directory / "raw"

    dataset = Dataset(name, directory, raw, rate, shifted, seed,
                      n_actors=e["n_actors"], n_transactions=e["n_transactions"])
    if dataset.transactions.exists() and not rebuild:
        return dataset

    argv = ["--n-actors", str(e["n_actors"]), "--n-transactions", str(e["n_transactions"]),
            "--output", str(raw), "--seed", str(seed), "--formats", "csv",
            "--relay-observation-rate", str(rate)]
    if shifted:
        argv.append("--shifted")
    generate(build_parser().parse_args(argv))
    ingest_run(raw, dataset.transactions, directory / "quarantine.parquet", "csv")
    return dataset
