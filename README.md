# btc-intel

Offline Bitcoin transaction forensics system — SIH26146.

Runs fully air-gapped: no network calls at any stage (`offline: true` in `config.yaml`).

## Architecture

<!-- PASTE ARCHITECTURE SUMMARY HERE -->

## Layout

| Path | What lives here |
| --- | --- |
| `generator/` | Synthetic transaction/case data generator |
| `ingest/` | Load + normalise raw dumps into the canonical schema |
| `graph/` | Address clustering, transaction graph construction |
| `features/` | Feature extraction over the graph and tx tables |
| `engines/rules/` | Deterministic heuristics (peeling chains, mixers, dust) |
| `engines/anomaly/` | Unsupervised outlier detection |
| `engines/gnn/` | Graph neural network scoring |
| `engines/correlation/` | Cross-case / entity correlation |
| `fusion/` | Combines engine scores into one risk score |
| `api/` | Local HTTP API |
| `web/` | Local UI |
| `eval/` | Metrics, benchmarks, ground-truth comparison |
| `offline/` | Pipeline orchestration, air-gapped packaging |
| `vendor/` | Cloned reference repos — read-only, never imported (see CONTRIBUTING.md) |
| `tests/` | Our tests |
| `data/` | `raw/`, `processed/`, `geoip/` — gitignored |
| `docs/` | Design notes |

## Generating data

```sh
python -m generator.main --n-actors 5000 --n-transactions 200000 \
    --output data/raw/ --formats csv,json,xml --seed 42
```

Writes `transactions.{csv,json,xml}` — the same records in NTRO's schema — plus
`ground_truth.json`, which is **not** part of the public dataset and is read only
by `eval/`. Same seed, byte-identical output.

Typologies (`generator/typologies.py`): `normal` (the majority noise class,
including innocent NAT/VPN shared IPs), `ransomware_collector` (victim fan-in
then a peeling chain), `layering` (fan-out/fan-in, several hops),
`same_actor_cluster` (one actor, several wallets, one IP, short window) and
`coinjoin` (equal-value inputs from unrelated wallets — the trap that
common-input-ownership clustering must not fall into). Mix and parameters live
under `generator:` in `config.yaml`.

Each transaction is broadcast across a simulated 500-node P2P network
(`generator/net.py`) with exponential per-hop delays, so one txid appears in
several relay rows. `--relay-observation-rate` sets the fraction of hops that get
recorded (default 0.3); `--single-row` emits one row per txid, for testing the
fallback when NTRO's data has no multi-hop records. Some broadcasts are masked
behind Tor exits or hosting ASNs — ground truth records both the true and the
observed origin IP, so the IP-correlation engine can be scored on whether it
discounts those.

`generator.inject.inject_pattern(dataset_dir, typology, params, seed)` appends one
fresh instance of a typology to an existing dataset and updates `ground_truth.json`
— this is what red-team mode calls.

Volume scales with the gossip settings: at defaults, 200k transactions produce
~720k rows (~1.2 GB across all three formats). Turn down `gossip.max_hops_per_tx`
or `--relay-observation-rate`, or emit fewer formats, if that is too much.

## Ingesting

```sh
python -m ingest.pipeline --input data/raw/ --output data/processed/transactions.parquet
```

parse → validate → enrich → parquet. `ingest/parsers.py` reads CSV, JSON or XML and
normalises all three into `RawTransaction` (`ingest/schema.py`); field names come from
config's `schema:` map, never from code. Malformed records — bad IP, mismatched
input/output array lengths, negative amounts, bad timestamps — land in
`data/processed/quarantine.parquet` with a reason and the original record, rather than
being dropped or killing the run.

A directory holding all three formats is read once: pick with `--format`, or set
`ingest.format`. `ground_truth.json` is excluded by name, so the labels can never be
ingested as evidence.

`ingest/geoip.py` enriches each row's `src_ip` from local `.mmdb` files (paths in
config, no network) adding `geo_country`, `asn`, `asn_org` and `high_risk_asn`.
`is_high_risk_asn()` checks `geoip.high_risk_asns` — VPN/hosting/Tor-adjacent
networks the correlation engine should discount. Missing databases degrade to null
columns instead of failing.

## Graph and clustering

```python
from graph.builder import from_parquet, iter_transactions, load
from graph.clustering import cluster_wallets
from graph.entity_graph import build_entity_graph

txs = list(iter_transactions(load()))      # relay rows collapsed per txid
g = from_parquet()                          # MultiDiGraph: wallet / transaction / ip
clustering = cluster_wallets(txs)
entities = build_entity_graph(txs, clustering)
```

`graph/builder.py` builds a `MultiDiGraph` with a `node_type` of `wallet`,
`transaction` or `ip`, and edges wallet→tx (`input`), tx→wallet (`output`),
ip→tx (`broadcast`); amounts, timestamps and script type ride on the edges.

`graph/clustering.py` reimplements BlockSci's published heuristics in pure
Python — common-input-ownership, and change detection by majority vote over
`address_reuse`, `address_type`, `optimal_change` and `peeling_chain`. Each
sub-heuristic returns the outputs it *cannot rule out*, as BlockSci's do; a tie
or too few votes means no change link, because a wrong merge is permanent.
CoinJoin-shaped transactions are detected first and skipped, so unrelated
participants are never merged. Wallets are merged with union-find (`DSU`), and
`cluster_collapse_guard` flags any cluster above `graph.collapse_guard.max_cluster_wallets`
(default 500) as `suspicious_merge — needs review` rather than trusting it.

`graph/entity_graph.py` collapses that into one node per cluster for the
dashboard's link-analysis view: aggregated value, transaction counts, txids per
link, broadcast IPs and the collapse-guard flag per entity.

## Configuration

Everything tunable lives in `config.yaml` at the repo root: input schema field
names, GeoIP database paths, model paths, risk-score weights, thresholds.
No stage hardcodes these — NTRO's real field names will differ from our
synthetic ones, so remap in `config.yaml` and change nothing else.

```python
import config

config.field("tx_id")            # -> the column name in the incoming dataset
config.get("risk_weights.rules") # -> 0.35
```

## Getting started

Requires Python 3.11 and [uv](https://docs.astral.sh/uv/).

```sh
make setup         # uv sync --extra dev
make test          # pytest
make lint          # ruff
make run-pipeline  # end-to-end offline run
```

## License

MIT — see `LICENSE`. `vendor/` is excluded; each vendored repo keeps its own license.
