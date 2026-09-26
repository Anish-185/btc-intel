"""No test changed a production artifact.

Named to sort last, so it runs after every other module in a plain `pytest`
run (collection is alphabetical) and compares each artifact's hash with the
one conftest.py took when the session started. The rails in conftest.py
redirect the writes we know about; this catches the ones we do not.
"""

from __future__ import annotations

from conftest import artifact_hashes


def test_no_production_artifact_changed_during_the_suite(artifacts_at_start):
    now = artifact_hashes()
    changed = [path for path, digest in artifacts_at_start.items() if now[path] != digest]
    assert not changed, f"the suite modified production artifacts: {changed}"
