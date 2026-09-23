"""The custody ledger: what it records, and what it catches.

The point of this file is the tamper tests. A ledger nobody can break is
worthless as evidence, because "intact" then means nothing — so these tests
break it on purpose, four different ways, and check that it says so.
"""

from __future__ import annotations

import json

import pytest

import config
import custody


@pytest.fixture
def ledger(tmp_path, monkeypatch):
    cfg = json.loads(json.dumps(config.load()))
    cfg["custody"]["ledger_path"] = str(tmp_path / "custody.jsonl")
    monkeypatch.setattr(config, "load", lambda *a, **k: json.loads(json.dumps(cfg)))
    return {"cfg": cfg, "path": tmp_path / "custody.jsonl", "tmp": tmp_path}


def test_an_empty_ledger_is_intact_and_says_where_it_starts(ledger):
    assert custody.head() == custody.GENESIS
    assert custody.verify() == {**custody.verify(), "entries": 0, "chain_intact": True}


def test_entries_chain_to_the_one_before(ledger):
    first = custody.record("ingest", {"rows": 10})
    second = custody.record("analysis", {"alerts": 3})
    third = custody.record("verdict", {"status": "confirmed"})

    assert [e["seq"] for e in (first, second, third)] == [1, 2, 3]
    assert first["prev"] == custody.GENESIS
    assert second["prev"] == first["hash"]
    assert third["prev"] == second["hash"]
    assert custody.head() == third["hash"]

    report = custody.verify()
    assert report["chain_intact"] and report["entries"] == 3 and report["broken_at"] is None


def test_editing_an_entry_breaks_the_chain_at_that_entry(ledger):
    custody.record("ingest", {"rows": 10})
    custody.record("verdict", {"status": "false_positive"})
    custody.record("analysis", {"alerts": 3})

    # Somebody decides the verdict should have said the other thing.
    entries = [json.loads(line) for line in ledger["path"].read_text().splitlines()]
    entries[1]["detail"]["status"] = "confirmed"
    ledger["path"].write_text("\n".join(json.dumps(e) for e in entries) + "\n")

    report = custody.verify()
    assert report["chain_intact"] is False
    assert report["broken_at"] == 2, "the break should be reported at the edited entry"


def test_editing_an_entry_and_rehashing_it_still_breaks_the_next_one(ledger):
    """The interesting case: an editor who knows how the hash is computed.

    Re-hashing the entry they changed makes *that* entry self-consistent, and
    it is the following entry's `prev` that no longer matches. This is the
    whole reason the entries are chained rather than hashed individually.
    """
    custody.record("ingest", {"rows": 10})
    custody.record("verdict", {"status": "false_positive"})
    custody.record("analysis", {"alerts": 3})

    entries = [json.loads(line) for line in ledger["path"].read_text().splitlines()]
    entries[1]["detail"]["status"] = "confirmed"
    entries[1]["hash"] = custody._digest(entries[1])          # a careful forger
    ledger["path"].write_text("\n".join(json.dumps(e) for e in entries) + "\n")

    report = custody.verify()
    assert report["chain_intact"] is False
    assert report["broken_at"] == 3, "the entry after the edited one should fail"


def test_deleting_an_entry_is_caught(ledger):
    custody.record("ingest", {"rows": 10})
    custody.record("verdict", {"status": "confirmed"})
    custody.record("analysis", {"alerts": 3})

    lines = ledger["path"].read_text().splitlines()
    ledger["path"].write_text("\n".join([lines[0], lines[2]]) + "\n")   # the middle goes

    assert custody.verify()["chain_intact"] is False


def test_a_changed_source_file_is_reported_separately_from_the_chain(ledger):
    source = ledger["tmp"] / "transactions.csv"
    source.write_text("txid,amount\nabc,1.0\n")
    custody.record("ingest", {"files": [custody.seal(source)], "rows": 1})

    clean = custody.verify()
    assert clean["chain_intact"] and not clean["files_changed"]

    source.write_text("txid,amount\nabc,9999.0\n")               # the dump is edited
    dirty = custody.verify()
    assert dirty["chain_intact"] is True, "the ledger itself was not touched"
    assert dirty["files_changed"] == [str(source)], "the changed dump must be named"

    source.unlink()
    assert custody.verify()["files_missing"] == [str(source)]


def test_only_the_most_recent_seal_of_a_file_is_checked(ledger):
    """A file that legitimately changes must not fail verification forever.

    A dataset is ingested, a red-team run appends to it, it is restored. Each
    step sealed it at a different hash. Checking against all of them would
    guarantee a failure; checking against the newest asks the right question —
    has it moved since the last thing we wrote down?
    """
    dataset = ledger["tmp"] / "transactions.csv"
    dataset.write_text("txid,amount\nabc,1.0\n")
    custody.record("ingest", {"files": [custody.seal(dataset)]})

    dataset.write_text("txid,amount\nabc,1.0\ndef,2.0\n")        # an injection appends
    custody.record("redteam.inject", {"files": [custody.seal(dataset)]})

    report = custody.verify()
    assert report["chain_intact"]
    assert report["files_changed"] == [], "an older seal must not fail the current file"
    assert report["files_sealed"] == 1, "one path, however many times it was sealed"

    dataset.write_text("txid,amount\nabc,9999.0\n")               # now edited behind our back
    assert custody.verify()["files_changed"] == [str(dataset)]


def test_a_seal_identifies_a_file_by_content(ledger):
    a, b = ledger["tmp"] / "a.csv", ledger["tmp"] / "b.csv"
    a.write_text("same")
    b.write_text("same")
    assert custody.seal(a)["sha256"] == custody.seal(b)["sha256"]
    b.write_text("different")
    assert custody.seal(a)["sha256"] != custody.seal(b)["sha256"]
    assert custody.seal(a)["bytes"] == 4


def test_a_broken_ledger_file_never_stops_the_work(ledger, monkeypatch):
    """Bookkeeping must not become an outage.

    If the ledger cannot be written — read-only medium, full disk — the caller
    gets an error in the return value and carries on serving the case. Losing
    the audit line is bad; refusing to show an analyst their case because of it
    is worse, and the error is visible either way.
    """
    def explode(*a, **k):
        raise OSError("read-only file system")

    monkeypatch.setattr(custody, "read", explode)
    entry = custody.record("ingest", {"rows": 1})
    assert entry["seq"] is None and "read-only" in entry["error"]
