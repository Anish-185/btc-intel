# Contributing

## The `vendor/` convention

`vendor/` holds reference repositories we cloned to read. It is **not our code**
and it is **not a dependency**.

Rules:

1. **Never `import` from `vendor/`.** Not in `generator/`, `ingest/`, `graph/`,
   `features/`, `engines/`, `fusion/`, `api/`, `eval/`, `offline/`, or `tests/`.
   Nothing in `vendor/` ships or runs.
2. **Read it for ideas, then reimplement.** Understand the approach, write our
   own version in our own module, in our own style, against our `config.yaml`.
3. **Every reimplementation gets our own tests** in `tests/`. If it has no test,
   it isn't done.
4. **Our code is MIT** (`LICENSE`). Vendored repos keep their own licenses and
   are not redistributed with our build — `vendor/` contents are gitignored and
   excluded from the wheel and from lint.
5. **Credit the idea, not the code.** A one-line comment naming the source repo
   is welcome; a copied block is not. Copying code drags its license into ours.

Why: a hard wall between "things we read" and "things we ship" keeps the
license story clean for a government deliverable, and keeps the air-gapped
build reproducible from our own sources only.

To add a reference repo:

```sh
git clone --depth 1 <url> vendor/<name>
```

Then note in `docs/` what it is and what we took from it conceptually.

## Everything else

- Python 3.11, `uv` for deps, `pyproject.toml` — no `requirements.txt`.
- Read tunables from `config.yaml` via `config.py`. Never hardcode field names,
  paths, weights or thresholds.
- No network calls. The system must run air-gapped.
- Never commit anything under `data/` — no case data, no `.mmdb` files.
- `make lint && make test` before pushing.
