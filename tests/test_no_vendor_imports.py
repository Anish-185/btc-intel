"""vendor/ is read-only reference material — nothing we ship may import it."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATTERN = re.compile(r"^\s*(?:from|import)\s+vendor\b", re.MULTILINE)


def test_nothing_imports_vendor():
    offenders = [
        p.relative_to(ROOT)
        for p in ROOT.rglob("*.py")
        if "vendor" not in p.parts and PATTERN.search(p.read_text())
    ]
    assert not offenders, f"imports from vendor/: {offenders}"
