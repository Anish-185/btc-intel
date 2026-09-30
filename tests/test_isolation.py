"""The suite's isolation rails, asserted where plain `pytest` collects them.

They used to live in conftest.py, where pytest never collects a test: the
rails were real, the checks of them never ran.
"""

from __future__ import annotations

from pathlib import Path

import config
import custody


def test_the_production_ledger_is_unreachable_from_the_suite(isolate_custody_ledger):
    """A fixture that silently stopped working would put the test noise back
    without anyone noticing until the demo."""
    production = Path(config.load()["custody"]["ledger_path"]).resolve()
    custody.record("ingest", {"rows": 1})
    assert custody.ledger_path().resolve() != production
    assert custody.read(), "the entry went somewhere, but not where it was asked to"
    assert isolate_custody_ledger.exists()


def test_the_production_stacker_is_unreachable_from_the_suite(isolate_stacker_model):
    from fusion import pipeline
    from fusion.stacker import Stacker

    production = Path(config.load()["fusion"]["model_path"])
    before = production.stat().st_mtime_ns if production.exists() else None
    pipeline.save(Stacker(fallback_weights={}), production)
    after = production.stat().st_mtime_ns if production.exists() else None
    assert before == after and isolate_stacker_model.exists()
