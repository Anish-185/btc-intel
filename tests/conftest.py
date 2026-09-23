"""Test-wide safety rails.

The one here that matters: **no test may write to the real custody ledger.**

`custody.record` is called from inside `ingest.pipeline.run`, `fusion.pipeline.run`
and the red-team path, which is correct — those are the moments a forensic
record has to capture. But it means every test that exercises the pipeline was
appending to `data/processed/custody.jsonl`, sealing files under
`/tmp/pytest-of-anish/...` that pytest then deleted. The result was a ledger of
522 entries, 396 of them pointing at temp files that no longer exist, and a
chain-of-custody page reporting hundreds of missing exhibits on a system where
nothing was wrong.

A forensic record full of test noise is not a forensic record. So the ledger is
redirected per test — and only when a test has not already chosen its own path,
so `test_custody.py` and `test_monitor.py` keep pointing at the files they
tamper with on purpose.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import config
import custody


@pytest.fixture(scope="session", autouse=True)
def isolate_custody_ledger(tmp_path_factory):
    """Send anything aimed at the production ledger to one file for the session.

    Session-scoped on purpose. A function-scoped version caught most of it and
    still leaked eleven entries per run, because pytest builds module- and
    session-scoped fixtures *before* any function-scoped one — so every
    `tmp_path_factory` fixture that ingests a dataset had already written to the
    real ledger before the redirect was in place.
    """
    production = Path(config.load()["custody"]["ledger_path"]).resolve()
    original = custody.ledger_path
    sink = tmp_path_factory.mktemp("custody") / "custody.jsonl"

    def redirected(cfg: dict | None = None) -> Path:
        chosen = original(cfg)
        # A test that set its own path means it; only the real one is diverted.
        return sink if chosen.resolve() == production else chosen

    with pytest.MonkeyPatch.context() as patched:
        patched.setattr(custody, "ledger_path", redirected)
        yield sink


def test_the_production_ledger_is_unreachable_from_the_suite(isolate_custody_ledger):
    """The rail itself, asserted — a fixture that silently stopped working
    would put the test noise back without anyone noticing until the demo."""
    production = Path(config.load()["custody"]["ledger_path"]).resolve()
    custody.record("ingest", {"rows": 1})
    assert custody.ledger_path().resolve() != production
    assert custody.read(), "the entry went somewhere, but not where it was asked to"
    assert isolate_custody_ledger.exists()
