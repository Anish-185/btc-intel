"""Tag bundles: written and sealed on a connected machine, verified and imported
on the analysis machine.

A bundle is a directory holding `bundle.json` (what it is), `tags.jsonl` (one
tag per line) and the `manifest.json` that `p2p.manifest` seals it with. There
is no second crypto path: sealing and verification are p2p.manifest's, and so
is its limit. The manifest proves the bundle is unchanged since sealing; it
does not prove who sealed it (see p2p/manifest.py and docs/TAGSTORE.md).

    python -m intel.bundle ofac  SDN.XML          --out bundles/ofac-2026-09-27
    python -m intel.bundle csv   curated.csv       --out bundles/team-list --source "..."
    python -m intel.bundle demo  data/raw          --out bundles/demo
    python -m intel.bundle import bundles/ofac-2026-09-27
    python -m intel.bundle list

Import refuses a bundle that is unsealed, altered, not a valid tag bundle, mixes
simulated and real tags, or is simulated while the case is real
(`ingest.provenance: real`). Every outcome, accepted or refused, is recorded in
the custody ledger.
"""

from __future__ import annotations

import argparse
import json
import shutil
from datetime import UTC, datetime
from pathlib import Path

import config
import custody
from p2p import manifest

from .tags import Tag

BUNDLE = "bundle.json"
TAGS = "tags.jsonl"


class BundleRefused(ValueError):
    """Import refused. The reason is recorded in the custody ledger."""


def store_dir(cfg: dict | None = None) -> Path:
    cfg = cfg or config.load()
    return Path(cfg["tags"]["store_dir"])


def write_bundle(tags: list[Tag], directory, name: str, description: str,
                 note: str | None = None) -> dict:
    """Write a bundle and seal it. Run on the connected machine."""
    directory = Path(directory)
    if directory.exists() and any(directory.iterdir()):
        raise FileExistsError(f"{directory} is not empty; a bundle is written once")
    if not tags:
        raise ValueError("a bundle holds at least one tag")
    directory.mkdir(parents=True, exist_ok=True)
    meta = {"name": name, "description": description,
            "created": datetime.now(UTC).isoformat(timespec="seconds"),
            "sources": sorted({t.source for t in tags}),
            "simulated": all(t.simulated for t in tags), "tags": len(tags)}
    (directory / BUNDLE).write_text(json.dumps(meta, indent=2) + "\n")
    (directory / TAGS).write_text("".join(json.dumps(t.as_dict(), sort_keys=True) + "\n"
                                          for t in tags))
    manifest.seal_capture(directory, note or description)
    return meta


def read_bundle(directory) -> tuple[dict, list[Tag]]:
    """The bundle's metadata and tags, validated. Raises ValueError if invalid."""
    directory = Path(directory)
    meta = json.loads((directory / BUNDLE).read_text())
    tags = [Tag.from_dict(json.loads(line))
            for line in (directory / TAGS).read_text().splitlines() if line.strip()]
    simulated = {t.simulated for t in tags}
    if len(simulated) > 1:
        raise ValueError("the bundle mixes simulated and real tags")
    if simulated and meta.get("simulated") is not simulated.pop():
        raise ValueError("bundle.json's `simulated` disagrees with its tags' sources")
    if meta.get("tags") != len(tags):
        raise ValueError(f"bundle.json says {meta.get('tags')} tags, tags.jsonl holds {len(tags)}")
    return meta, tags


def check(directory, cfg: dict) -> tuple[dict, dict, list[Tag]]:
    """Seal, then contents, then case fit. Raises BundleRefused with the reason."""
    directory = Path(directory)
    try:
        verified = manifest.verify_capture(directory, cfg, record=False)
    except FileNotFoundError as exc:
        raise BundleRefused(f"unsealed: {exc}") from exc
    if not verified["ok"]:
        problems = {k: verified[k] for k in ("files_changed", "files_missing",
                                             "files_added_since_sealing") if verified[k]}
        if not verified["manifest_self_consistent"]:
            problems["manifest"] = "edited after sealing"
        raise BundleRefused(f"altered since sealing: {problems}")
    try:
        meta, tags = read_bundle(directory)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise BundleRefused(f"not a valid tag bundle: {exc}") from exc
    if meta["simulated"] and cfg["ingest"].get("provenance") == "real":
        raise BundleRefused("a simulated bundle cannot enter a real case "
                            "(ingest.provenance is 'real')")
    return verified, meta, tags


def import_bundle(directory, cfg: dict | None = None) -> dict:
    """Verify a carried-in bundle and copy it into the store.

    Raises BundleRefused, after recording the refusal, if it fails any check."""
    cfg = cfg or config.load()
    directory = Path(directory)
    try:
        verified, meta, tags = check(directory, cfg)
        target = store_dir(cfg) / meta["name"]
        if target.exists():
            held = manifest.read_manifest(target).get("manifest_hash")
            if held != verified["manifest_hash"]:
                raise BundleRefused(f"a different bundle named {meta['name']!r} is already "
                                    "imported; give the new one a new name")
        else:
            shutil.copytree(directory, target)
    except BundleRefused as exc:
        custody.record("tags.bundle_refused", {"bundle": str(directory), "reason": str(exc)},
                       cfg=cfg)
        raise
    entry = custody.record("tags.bundle_imported", {
        "bundle": meta["name"], "manifest_hash": verified["manifest_hash"],
        "sources": meta["sources"], "simulated": meta["simulated"], "tags": len(tags),
        "files": [custody.seal(target / f) for f in (BUNDLE, TAGS, manifest.MANIFEST_NAME)]},
        cfg=cfg)
    return {**meta, "manifest_hash": verified["manifest_hash"], "stored_at": str(target),
            "custody": entry.get("seq")}


def main(argv=None) -> None:
    from . import importers

    cfg = config.load()
    ap = argparse.ArgumentParser(prog="intel.bundle", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["ofac", "csv", "demo", "import", "list"])
    ap.add_argument("path", nargs="?")
    ap.add_argument("--out", help="bundle directory to write (ofac, csv, demo)")
    ap.add_argument("--name", help="bundle name (default: the --out directory's name)")
    ap.add_argument("--source", help="csv: who curated the list")
    args = ap.parse_args(argv)

    if args.command == "list":
        from .store import load
        print(json.dumps(load(cfg).header(), indent=2))
        return
    if args.command == "import":
        try:
            print(json.dumps(import_bundle(args.path, cfg), indent=2))
        except BundleRefused as exc:
            raise SystemExit(f"refused: {exc}") from exc
        return
    out = Path(args.out)
    name = args.name or out.name
    if args.command == "ofac":
        tags, description = importers.ofac(args.path), f"OFAC SDN digital currency addresses from {Path(args.path).name}"
    elif args.command == "csv":
        tags, description = importers.from_csv(args.path, args.source), f"operator list {Path(args.path).name}"
    else:
        tags, description = importers.demo(args.path), "SIMULATED: derived from generator ground truth"
    print(json.dumps(write_bundle(tags, out, name, description), indent=2))


if __name__ == "__main__":
    main()
