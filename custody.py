"""Chain of custody: a tamper-evident record of what this system did.

A risk score is an investigative lead. A lead that an analyst acts on becomes
part of a case, and a case that reaches a court has to answer three questions
about every artefact in it — ISO/IEC 27037's principles, in plain words:

  * **Where did this come from?** The source file is hashed the moment it is
    read, before anything transforms it.
  * **Has it changed since?** The hash is recorded, so a later copy either
    matches or does not.
  * **Who did what to it, and when?** Every consequential action — an ingest, a
    pipeline run, an analyst's verdict, an exported report, a red-team
    injection — is appended here with a timestamp.

The ledger is append-only JSONL, and each entry carries the hash of the one
before it. That makes it *tamper-evident* rather than tamper-proof: anybody
with write access can still edit the file, but they cannot edit one entry and
leave the rest verifying, because every later hash was computed over the
altered one. `verify()` says where the chain first breaks.

What this is not: it is not a signature. Nothing here proves *who* wrote an
entry, because this build has no authentication — a deployment would sign each
entry with the analyst's key and the ledger would live on write-once storage.
The gap is named in `actor` rather than papered over.

    python -m custody log            # what happened, newest last
    python -m custody verify         # is the chain intact, are the files unchanged
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

import config

#: The first entry's `prev`. Sixty-four zeros: there is nothing before it.
GENESIS = "0" * 64

_LOCK = threading.Lock()


def ledger_path(cfg: dict | None = None) -> Path:
    cfg = cfg or config.load()
    return Path(cfg["custody"]["ledger_path"])


def sha256_file(path) -> str:
    """The hash of a file, read in chunks — a dump can be larger than memory."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def seal(path) -> dict:
    """Identify one file: name, size, hash, and when the filesystem says it
    last changed. Recorded at acquisition, compared at verification."""
    path = Path(path)
    stat = path.stat()
    return {"path": str(path), "bytes": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime, timezone.utc)
                                .isoformat(timespec="seconds"),
            "sha256": sha256_file(path)}


def _digest(entry: dict) -> str:
    """An entry's hash, over its content and its predecessor's hash.

    `sort_keys` because a dict that serialises differently on a different day
    would break a chain that nobody had touched.
    """
    body = {k: entry[k] for k in ("seq", "at", "action", "actor", "detail", "prev")}
    return hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()


def read(cfg: dict | None = None) -> list[dict]:
    path = ledger_path(cfg)
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def head(cfg: dict | None = None) -> str:
    """The hash of the last entry — the state of the whole ledger in one value.

    Printed on an exported report: anyone holding the report can ask this
    system whether its ledger still ends there.
    """
    entries = read(cfg)
    return entries[-1]["hash"] if entries else GENESIS


def record(action: str, detail: dict | None = None, actor: str | None = None,
           cfg: dict | None = None) -> dict:
    """Append one entry and return it.

    Never raises into the caller's path: a demo that refuses to serve a case
    report because the audit file is read-only has turned a bookkeeping problem
    into an outage. A failure is reported in the return value instead.
    """
    cfg = cfg or config.load()
    path = ledger_path(cfg)
    try:
        with _LOCK:
            entries = read(cfg)
            entry = {
                "seq": len(entries) + 1,
                "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "action": action,
                "actor": actor or cfg["custody"]["actor"],
                "detail": detail or {},
                "prev": entries[-1]["hash"] if entries else GENESIS,
            }
            entry["hash"] = _digest(entry)
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, default=str) + "\n")
                handle.flush()
                os.fsync(handle.fileno())   # a crash must not lose the record
        return entry
    except OSError as exc:
        return {"seq": None, "action": action, "error": f"{type(exc).__name__}: {exc}"}


def verify(cfg: dict | None = None, check_files: bool = True) -> dict:
    """Re-walk the chain, and re-hash the files it claims to have read.

    Two independent questions. The chain check catches an edited or deleted
    *entry*; the file check catches an edited *dataset*. Either can fail on its
    own, so both are reported separately rather than as one verdict.
    """
    entries = read(cfg)
    latest: dict[str, dict] = {}
    broken_at, expected_prev = None, GENESIS
    for entry in entries:
        if entry.get("prev") != expected_prev or entry.get("hash") != _digest(entry):
            broken_at = entry.get("seq")
            break
        expected_prev = entry["hash"]

    changed, missing = [], []
    if check_files:
        # A file legitimately changes over a case — a dataset is re-ingested, a
        # red-team run appends to it, a reset puts it back. Each of those wrote
        # its own seal, so the question is not "does this file match every hash
        # ever recorded for it" (it cannot) but "does it match the most recent
        # one". An older seal is history, not a claim about the present.
        latest: dict[str, dict] = {}
        for entry in entries:
            for sealed in entry.get("detail", {}).get("files", []):
                latest[sealed["path"]] = sealed
        for path_str, sealed in latest.items():
            path = Path(path_str)
            if not path.exists():
                missing.append(path_str)
            elif sha256_file(path) != sealed["sha256"]:
                changed.append(path_str)
    return {
        "entries": len(entries),
        "chain_intact": broken_at is None,
        "broken_at": broken_at,
        "head": entries[-1]["hash"] if entries else GENESIS,
        "files_sealed": len(latest) if check_files else 0,
        "files_changed": sorted(set(changed)),
        "files_missing": sorted(set(missing)),
        # Each file is checked against its most recent seal, so a change here
        # means the file moved after the last action that recorded it — which
        # is a fact to explain, not proof of tampering on its own.
        "note": ("each file is compared against the most recent seal recorded for it; "
                 "a change means it was modified after the last action this ledger "
                 "knows about"),
    }


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="custody", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["log", "verify"])
    args = ap.parse_args(argv)
    if args.command == "log":
        for entry in read():
            files = entry.get("detail", {}).get("files", [])
            print(f"{entry['seq']:>4}  {entry['at']}  {entry['action']:<22} "
                  f"{entry['hash'][:12]}  {len(files)} file(s)")
    else:
        print(json.dumps(verify(), indent=2))


if __name__ == "__main__":
    main()
