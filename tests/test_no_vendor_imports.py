"""vendor/ is read-only reference material — nothing we ship may import it."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATTERN = re.compile(r"^\s*(?:from|import)\s+vendor\b", re.MULTILINE)


SKIP = {"vendor", "build", "dist"}


def ours(path: Path) -> bool:
    """Our own source only — not vendor/, not an installed virtualenv."""
    return not any(part in SKIP or part.startswith(".") for part in path.parts)


def test_nothing_imports_vendor():
    offenders = [
        p.relative_to(ROOT)
        for p in ROOT.rglob("*.py")
        if ours(p.relative_to(ROOT)) and PATTERN.search(p.read_text(encoding="utf-8"))
    ]
    assert not offenders, f"imports from vendor/: {offenders}"
