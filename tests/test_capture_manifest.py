"""Sealing a capture bundle, and catching every way it can arrive wrong.

The air gap is the one leg of a capture's life where a person and a device we do
not control handle the evidence, so each of the four ways a bundle can differ
from its manifest is broken here on purpose — the same discipline
tests/test_custody.py applies to the ledger.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import custody
from p2p import manifest as m

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "capture"


@pytest.fixture
def bundle(tmp_path):
    directory = tmp_path / "2026-09-24-node1"
    directory.mkdir()
    for name in ("node1.debug.log", "node1.btcap"):
        (directory / name).write_bytes((FIXTURES / name).read_bytes())
    (directory / "nested").mkdir()
    (directory / "nested" / "second.btcap").write_text('{"txid": "ab", "message_type": "inv"}\n')
    return directory


def test_sealing_hashes_every_file_including_nested_ones(bundle):
    sealed = m.seal_capture(bundle, note="node1, 20 minutes")
    assert {f["path"] for f in sealed["files"]} == {
        "node1.debug.log", "node1.btcap", "nested/second.btcap"}
    assert all(len(f["sha256"]) == 64 for f in sealed["files"])
    assert sealed["note"] == "node1, 20 minutes"
    assert (bundle / "manifest.json").exists()
    assert sealed["manifest_hash"] == m.manifest_hash(sealed["files"])


def test_paths_are_relative_so_the_bundle_can_move(bundle, tmp_path):
    """The collection host's directory layout is not the analysis host's."""
    m.seal_capture(bundle)
    moved = tmp_path / "from-usb-stick"
    bundle.rename(moved)
    assert m.verify_capture(moved, record=False)["ok"]


def test_a_sealed_bundle_verifies(bundle):
    m.seal_capture(bundle)
    result = m.verify_capture(bundle, record=False)
    assert result["ok"] and result["files"] == 3
    assert result["files_changed"] == result["files_missing"] == []
    assert result["manifest_self_consistent"]


def test_an_edited_capture_file_is_caught(bundle):
    m.seal_capture(bundle)
    (bundle / "node1.btcap").write_text('{"txid": "ff", "message_type": "inv"}\n')
    result = m.verify_capture(bundle, record=False)
    assert not result["ok"]
    assert result["files_changed"] == ["node1.btcap"]


def test_a_deleted_capture_file_is_caught(bundle):
    m.seal_capture(bundle)
    (bundle / "nested" / "second.btcap").unlink()
    result = m.verify_capture(bundle, record=False)
    assert not result["ok"] and result["files_missing"] == ["nested/second.btcap"]


def test_a_file_added_after_sealing_is_caught(bundle):
    """No per-file hash can see this one — only the file list can."""
    m.seal_capture(bundle)
    (bundle / "extra.btcap").write_text('{"txid": "cc", "message_type": "inv"}\n')
    result = m.verify_capture(bundle, record=False)
    assert not result["ok"] and result["files_added_since_sealing"] == ["extra.btcap"]


def test_an_edited_manifest_does_not_verify_itself(bundle):
    """Rewriting a file's recorded hash makes the files agree with the manifest
    and the manifest disagree with its own hash."""
    m.seal_capture(bundle)
    path = bundle / "manifest.json"
    doc = json.loads(path.read_text())
    doc["files"][0]["sha256"] = "0" * 64
    path.write_text(json.dumps(doc))
    result = m.verify_capture(bundle, record=False)
    assert not result["ok"] and not result["manifest_self_consistent"]


def test_manifest_hash_is_independent_of_file_order(bundle):
    sealed = m.seal_capture(bundle)
    assert m.manifest_hash(list(reversed(sealed["files"]))) == sealed["manifest_hash"]


def test_an_unsealed_bundle_says_so_rather_than_passing(bundle):
    with pytest.raises(FileNotFoundError):
        m.verify_capture(bundle, record=False)


def test_sealing_an_empty_directory_is_refused(tmp_path):
    (tmp_path / "empty").mkdir()
    with pytest.raises(FileNotFoundError):
        m.seal_capture(tmp_path / "empty")


def test_a_verified_import_lands_in_the_custody_ledger(bundle):
    """The import is a consequential action, so it is recorded — and the seals
    are re-pathed to this host, so custody.verify() watches the files too."""
    m.seal_capture(bundle)
    before = len(custody.read())
    result = m.verify_capture(bundle)
    assert result["custody"], "a successful import must be recorded"
    entries = custody.read()
    assert len(entries) == before + 1
    assert entries[-1]["action"] == "capture_imported"
    assert custody.verify()["chain_intact"]
    watched = {f["path"] for f in entries[-1]["detail"]["files"]}
    assert str(bundle / "node1.btcap") in watched


def test_a_failed_import_is_recorded_as_a_failure(bundle):
    m.seal_capture(bundle)
    (bundle / "node1.btcap").write_text("tampered\n")
    result = m.verify_capture(bundle)
    assert not result["ok"]
    assert custody.read()[-1]["action"] == "capture_import_failed"
    assert result["custody"], "the failure is recorded too, not silently dropped"
    assert custody.verify(check_files=False)["chain_intact"]
