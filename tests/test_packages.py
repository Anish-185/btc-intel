"""Every top-level package of ours is in the wheel.

The repo uses a flat layout — packages sit beside `config.py` rather than under
`src/` — which has one failure mode: a new sibling package works perfectly from
a checkout and is silently absent from the built wheel, because `pyproject.toml`
lists them by hand. `p2p/` was the fourth-from-last package added and the first
where an omission would have shipped a console that imports a module the
air-gapped install does not have. `origination/` followed it as a flat
sibling on the same convention, and is the first package whose runtime reads a
data file of its own (`origination/manifest.json`), so that file is asserted
to live inside the package directory, where the wheel picks it up.

So the list is asserted against the directories instead of trusted.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: Ours, but deliberately not shipped: the test suite, and read-only reference
#: clones. Anything else with an __init__.py belongs in the wheel.
NOT_SHIPPED = {"tests", "vendor"}


def declared() -> set[str]:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text())
    return set(data["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"])


def on_disk() -> set[str]:
    return {p.name for p in ROOT.iterdir()
            if p.is_dir() and not p.name.startswith(".")
            and (p / "__init__.py").exists() and p.name not in NOT_SHIPPED}


def test_every_package_is_declared_in_pyproject():
    missing = on_disk() - declared()
    assert not missing, (
        "these packages exist but are not in [tool.hatch.build.targets.wheel] "
        f"packages, so they would be missing from the wheel: {sorted(missing)}")


def test_no_declared_package_has_disappeared():
    stale = declared() - on_disk()
    assert not stale, f"declared but not on disk (or missing __init__.py): {sorted(stale)}"


def subpackages() -> set[str]:
    """Every nested package of ours, as a dotted path (e.g. `eval.ground_truth`)."""
    found = set()
    for top in on_disk():
        for init in (ROOT / top).rglob("__init__.py"):
            relative = init.relative_to(ROOT).parent
            if len(relative.parts) > 1 and not any(
                    part.startswith(".") for part in relative.parts):
                found.add(".".join(relative.parts))
    return found


def test_every_subpackage_ships_under_a_declared_parent():
    """Hatch ships a declared package's subpackages with it, so a nested package
    needs no entry of its own — but only if its top-level parent is declared and
    every directory on the way down is a real package.

    `eval/ground_truth/` was the first nested package added, and the failure it
    could have shipped is a subdirectory with no `__init__.py`: importable from a
    checkout on Python 3.3+ as a namespace package, and silently absent from the
    wheel.
    """
    parents = declared()
    orphans = sorted(name for name in subpackages() if name.split(".")[0] not in parents)
    assert not orphans, f"nested packages with no declared top-level parent: {orphans}"


def test_no_directory_of_ours_is_an_accidental_namespace_package():
    """A package directory missing `__init__.py` still imports locally and is
    then left out of the wheel. Checked for every directory holding our .py
    files, under a declared package."""
    offenders = []
    for top in declared():
        root = ROOT / top
        if not root.is_dir():
            continue
        for directory in root.rglob("*"):
            if not directory.is_dir() or any(p.startswith(".") for p in directory.parts):
                continue
            if directory.name in ("__pycache__", "fixtures"):
                continue
            if any(directory.glob("*.py")) and not (directory / "__init__.py").exists():
                offenders.append(str(directory.relative_to(ROOT)))
    assert not offenders, f"directories with .py files but no __init__.py: {offenders}"


def test_package_data_the_runtime_reads_ships_inside_its_package():
    """`origination.corpus` reads its manifest from beside itself. Outside the
    package directory it would work from a checkout and be missing from the
    wheel — the same failure as an undeclared package, one level down."""
    from origination import corpus

    assert corpus.MANIFEST.resolve().parent == (ROOT / "origination").resolve()
    assert corpus.MANIFEST.exists()
