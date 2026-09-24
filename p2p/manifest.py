"""Seal a capture bundle, and verify it on the other side of the air gap.

A capture is evidence, and it crosses an air gap on removable media — the one
moment in this system's life where a file is handled by a person and a device we
do not control. So a bundle carries a manifest: every file's SHA-256, taken on
the collection host, and one hash over the whole list. Verification on the
analysis host re-reads the files and says whether they are the same bytes.

This reuses `custody.py` rather than repeating it: `custody.seal()` already
identifies a file (path, size, mtime, hash) in the exact shape the ledger
expects, `custody.sha256_file()` already hashes larger-than-memory files, and
`custody.record()` appends the import to the same hash-chained ledger every
other consequential action lands in. Sealing a capture therefore also makes it
one of the files `custody.verify()` watches from then on.

    python -m p2p.manifest seal   data/capture/2026-09-24-node1
    python -m p2p.manifest verify data/capture/2026-09-24-node1

**Not a digital signature.** There are no keys in this build, and inventing a
keyring here would claim an authenticity guarantee nothing can back — the same
position `custody.py` takes on `actor`. The manifest hash proves the bundle is
internally consistent and unchanged since sealing; it does not prove who sealed
it. A deployment would sign `manifest_hash` with the collection operator's key,
and that one field is the whole integration point.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import config
import custody

MANIFEST_NAME = "manifest.json"


def manifest_hash(files: list[dict]) -> str:
    """One hash over every file's seal, order-independent.

    `sort_keys` and a sorted file list for the same reason `custody._digest`
    uses them: a manifest that serialised differently on a different machine
    would fail to verify on a bundle nobody had touched.
    """
    body = sorted(({"path": f["path"], "bytes": f["bytes"], "sha256": f["sha256"]}
                   for f in files), key=lambda f: f["path"])
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


def _captures(directory: Path) -> list[Path]:
    return sorted(p for p in directory.rglob("*")
                  if p.is_file() and p.name != MANIFEST_NAME)


def seal_capture(directory, note: str | None = None, cfg: dict | None = None) -> dict:
    """Hash every file in the bundle and write `manifest.json` beside them.

    Run on the collection host, once the capture has stopped growing.
    """
    directory = Path(directory)
    if not directory.is_dir():
        raise NotADirectoryError(f"{directory} is not a capture directory")
    paths = _captures(directory)
    if not paths:
        raise FileNotFoundError(f"{directory} holds no capture files")

    files = []
    for path in paths:
        sealed = custody.seal(path)
        sealed["path"] = str(path.relative_to(directory))   # portable across the gap
        files.append(sealed)

    manifest = {
        "bundle": directory.name,
        "sealed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "note": note or "",
        "files": files,
        "manifest_hash": manifest_hash(files),
        # Where the collection host's ledger stood when this was sealed. It has
        # no bearing on verification — the analysis host has a different ledger
        # — and is recorded so the two records can be lined up by hand later.
        "ledger_head_at_seal": custody.head(cfg),
    }
    (directory / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def read_manifest(directory) -> dict:
    path = Path(directory) / MANIFEST_NAME
    if not path.exists():
        raise FileNotFoundError(f"{path} — an unsealed bundle cannot be verified")
    return json.loads(path.read_text())


def verify_capture(directory, cfg: dict | None = None, record: bool = True) -> dict:
    """Re-read the bundle and compare it with its manifest.

    Four independent failures, reported separately because they mean different
    things: a file whose bytes differ, a file that is gone, a file that was
    added after sealing (which no per-file hash can catch), and a manifest whose
    own hash does not match its list (which means the manifest itself was
    edited). `ok` is the conjunction, and is the only thing an importer should
    branch on.
    """
    directory = Path(directory)
    manifest = read_manifest(directory)
    sealed = {f["path"]: f for f in manifest["files"]}

    changed, missing = [], []
    for relative, entry in sealed.items():
        path = directory / relative
        if not path.exists():
            missing.append(relative)
        elif custody.sha256_file(path) != entry["sha256"]:
            changed.append(relative)

    present = {str(p.relative_to(directory)) for p in _captures(directory)}
    added = sorted(present - set(sealed))
    consistent = manifest_hash(manifest["files"]) == manifest.get("manifest_hash")

    result = {
        "bundle": manifest.get("bundle", directory.name),
        "sealed_at": manifest.get("sealed_at"),
        "files": len(sealed),
        "files_changed": sorted(changed),
        "files_missing": sorted(missing),
        "files_added_since_sealing": added,
        "manifest_self_consistent": consistent,
        "manifest_hash": manifest.get("manifest_hash"),
        "ok": not changed and not missing and not added and consistent,
    }
    if record:
        # A failed import is recorded as loudly as a successful one: "this
        # bundle arrived altered" is the single most important thing this
        # ledger can ever hold, so it is never the branch that writes nothing.
        # Seals are re-pathed to where this host actually holds the files, so
        # custody.verify() watches them from here on.
        entry = custody.record(
            "capture_imported" if result["ok"] else "capture_import_failed",
            {"bundle": result["bundle"], "manifest_hash": result["manifest_hash"],
             "ok": result["ok"], "files_changed": result["files_changed"],
             "files_missing": result["files_missing"],
             "files_added_since_sealing": added,
             "files": [dict(f, path=str(directory / f["path"])) for f in manifest["files"]
                       if (directory / f["path"]).exists()]},
            cfg=cfg)
        result["custody"] = entry.get("hash")
    return result


def main(argv=None) -> None:
    cfg = config.load()
    default_dir = (cfg.get("p2p") or {}).get("capture_dir", "data/capture")
    ap = argparse.ArgumentParser(prog="p2p.manifest", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["seal", "verify"])
    ap.add_argument("directory", nargs="?", default=default_dir)
    ap.add_argument("--note", default=None, help="what this capture is (seal only)")
    args = ap.parse_args(argv)

    if args.command == "seal":
        result = seal_capture(args.directory, args.note)
        result["files"] = len(result["files"])
    else:
        result = verify_capture(args.directory)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if args.command == "seal" or result["ok"] else 1)


if __name__ == "__main__":
    main()
