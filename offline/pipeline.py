"""End-to-end offline run. Stages are wired in as they land."""

import config


def main() -> None:
    cfg = config.load()
    assert cfg["offline"], "config.yaml: offline must be true — no network calls allowed"
    print(f"btc-intel pipeline — input={cfg['ingest']['input_dir']} weights={cfg['risk_weights']}")
    # ponytail: stages appended here as modules land; swap for a stage registry
    # only once wiring order actually varies per run.


if __name__ == "__main__":
    main()
