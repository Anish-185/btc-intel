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
