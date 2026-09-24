"""Reading real P2P captures off disk — all three formats.

The debug.log and .btcap fixtures are checked in beside this file. The pcap and
pcapng fixtures are *built* here instead: a committed binary blob is a fixture
nobody can read in a review, and building the bytes means the test states the
wire format it claims to parse rather than trusting a capture somebody took
once.

The txid check is not self-referential. The parser's hashing convention is
pinned to Bitcoin's genesis coinbase transaction — a published vector — and the
segwit case computes its expectation from the legacy serialisation this test
writes itself, never from the parser.
"""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

import pytest

from p2p import capture_reader as cr

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "capture"
TX_GENESIS = ("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b")

#: Bitcoin's genesis coinbase transaction, serialised. Its txid is the value
#: above, which is published in every block explorer — so this pins the hashing
#: convention (double SHA-256, byte-reversed) to something outside this repo.
GENESIS_RAW = bytes.fromhex(
    "01000000010000000000000000000000000000000000000000000000000000000000000000"
    "ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368"
    "616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f75742066"
    "6f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a671"
    "30b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c38"
    "4df7ba0b8d578a4c702b6bf11d5fac00000000")

MAGIC = bytes.fromhex("f9beb4d9")
NODE = "198.51.100.2"          # the capture host
PEER = "203.0.113.9"


def double_sha(data: bytes) -> str:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()[::-1].hex()


def segwit_tx() -> tuple[bytes, str, str]:
    """A one-in one-out segwit transaction, and its two identifiers.

    Built from the legacy bytes outward, so the expected txid comes from the
    serialisation this test defines and not from the code under test.
    """
    version = bytes.fromhex("02000000")
    txin = b"\x11" * 32 + bytes.fromhex("00000000") + b"\x00" + bytes.fromhex("ffffffff")
    txout = struct.pack("<q", 12_345_678) + bytes([0x19]) + bytes.fromhex(
        "76a914" + "22" * 20 + "88ac")
    locktime = bytes.fromhex("00000000")
    legacy = version + b"\x01" + txin + b"\x01" + txout + locktime
    witness = b"\x01\x02\xde\xad"                        # one item, two bytes
    wire = version + b"\x00\x01" + b"\x01" + txin + b"\x01" + txout + witness + locktime
    return wire, double_sha(legacy), double_sha(wire)


def p2p_message(command: str, payload: bytes) -> bytes:
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return (MAGIC + command.encode().ljust(12, b"\x00")
            + struct.pack("<I", len(payload)) + checksum + payload)


def inv_message(entries: list[tuple[int, str]]) -> bytes:
    payload = bytes([len(entries)])
    for kind, digest in entries:
        payload += struct.pack("<I", kind) + bytes.fromhex(digest)[::-1]
    return p2p_message("inv", payload)


def tcp_frame(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    """Ethernet + IPv4 + TCP around a payload. Checksums are not verified by
    anything we wrote, so they are left zero rather than faked."""
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1, 1, 5 << 4, 0x18, 65535, 0, 0) + payload
    total = 20 + len(tcp)
    ip = (struct.pack("!BBHHHBBH", 0x45, 0, total, 0, 0, 64, 6, 0)
          + bytes(int(o) for o in src.split(".")) + bytes(int(o) for o in dst.split(".")))
    return b"\xaa" * 12 + b"\x08\x00" + ip + tcp


def write_pcap(path: Path, packets: list[tuple[float, bytes]]) -> Path:
    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for ts, frame in packets:
        out += struct.pack("<IIII", int(ts), int(round((ts % 1) * 1e6)),
                           len(frame), len(frame))
        out += frame
    path.write_bytes(bytes(out))
    return path


def write_pcapng(path: Path, packets: list[tuple[float, bytes]]) -> Path:
    def block(kind: int, body: bytes) -> bytes:
        body += b"\x00" * (-len(body) % 4)
        length = 12 + len(body)
        return struct.pack("<II", kind, length) + body + struct.pack("<I", length)

    shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    options = struct.pack("<HH", 9, 1) + b"\x06" + b"\x00" * 3 + struct.pack("<HH", 0, 0)
    idb = block(0x00000001, struct.pack("<HHI", 1, 0, 65535) + options)
    out = bytearray(shb + idb)
    for ts, frame in packets:
        micros = int(round(ts * 1e6))
        out += block(0x00000006, struct.pack("<IIIII", 0, micros >> 32, micros & 0xFFFFFFFF,
                                             len(frame), len(frame)) + frame)
    path.write_bytes(bytes(out))
    return path


@pytest.fixture(scope="module")
def wire():
    """The stream both pcap fixtures carry: one wtxid inv, then the segwit
    transaction itself split across two TCP segments, then a txid inv."""
    raw, txid, wtxid = segwit_tx()
    tx_message = p2p_message("tx", raw)
    cut = len(tx_message) // 2
    packets = [
        (1_790_244_001.25, tcp_frame(PEER, NODE, 8333, 51000,
                                     inv_message([(cr.INV_WTX, wtxid)]))),
        (1_790_244_001.40, tcp_frame(PEER, NODE, 8333, 51000, tx_message[:cut])),
        (1_790_244_001.41, tcp_frame(PEER, NODE, 8333, 51000, tx_message[cut:])),
        (1_790_244_002.00, tcp_frame(NODE, "198.51.100.77", 51001, 8333,
                                     inv_message([(cr.INV_TX, TX_GENESIS)]))),
        (1_790_244_002.10, tcp_frame(PEER, NODE, 443, 9000, b"not bitcoin at all")),
    ]
    return {"packets": packets, "txid": txid, "wtxid": wtxid}


# --- txid computation -----------------------------------------------------
def test_genesis_txid_matches_the_published_vector():
    txid, wtxid = cr.txids_of(GENESIS_RAW)
    assert txid == TX_GENESIS
    assert wtxid == txid, "a pre-segwit transaction has one identifier, not two"


def test_segwit_txid_strips_the_witness():
    raw, expected_txid, expected_wtxid = segwit_tx()
    txid, wtxid = cr.txids_of(raw)
    assert txid == expected_txid
    assert wtxid == expected_wtxid
    assert txid != wtxid, "the fixture is pointless if the two ids coincide"


# --- 1. debug.log --------------------------------------------------------
def test_debug_log_binds_peers_agents_and_directions():
    events = cr.read_capture(FIXTURES / "node1.debug.log")
    assert cr.detect_format(FIXTURES / "node1.debug.log") == "debug_log"
    kinds = [(e.message_type, e.direction) for e in events]
    assert kinds == [("inv", "inbound"), ("inv_wtx", "inbound"),
                     ("inv", "outbound"), ("tx", "inbound")]

    first = events[0]
    assert first.txid == TX_GENESIS
    assert (first.peer_id, first.peer_ip, first.peer_port) == (1, PEER, 8333)
    assert first.user_agent == "/Satoshi:25.0.0/"
    assert first.capture_source == "debug.log:node1.debug.log"
    assert events[1].peer_ip == "198.51.100.77"


def test_the_version_lines_own_address_is_not_mistaken_for_the_peers():
    """`us=198.51.100.2:8333` sits on the same line as `peer=1`. Binding a peer
    to our own address would make every observation look locally originated,
    which is the exact error this whole pipeline exists to avoid."""
    events = cr.read_capture(FIXTURES / "node1.debug.log")
    assert NODE not in {e.peer_ip for e in events}


def test_debug_log_derives_a_clock_from_the_first_event():
    events = cr.read_capture(FIXTURES / "node1.debug.log")
    assert events[0].monotonic_or_derived_ts == 0.0
    assert events[-1].monotonic_or_derived_ts == pytest.approx(0.75, abs=1e-6)
    assert all(e.wall_clock_ts is not None for e in events)


def test_a_received_tx_line_without_a_txid_is_not_invented():
    """debug=net logs `received: tx (223 bytes) peer=1` with no identifier.
    Emitting a row for it would mean a transaction event with no transaction."""
    events = cr.read_capture(FIXTURES / "node1.debug.log")
    assert all(len(e.txid) == 64 for e in events)


# --- 2. pcap / pcapng ----------------------------------------------------
@pytest.mark.parametrize("writer", [write_pcap, write_pcapng])
def test_pcap_decodes_inv_and_tx_across_segments(tmp_path, wire, writer):
    path = writer(tmp_path / f"cap{writer is write_pcapng and 'ng' or ''}.pcap",
                  wire["packets"])
    events = cr.read_capture(path, local_ips=[NODE])
    assert cr.detect_format(path) == "pcap"

    # The tx message arrived in two halves; one event, not none and not two.
    txs = [e for e in events if e.message_type == "tx"]
    assert len(txs) == 1 and txs[0].txid == wire["txid"]
    assert txs[0].peer_ip == PEER and txs[0].peer_port == 8333
    assert txs[0].direction == "inbound"

    outbound = [e for e in events if e.direction == "outbound"]
    assert [(e.txid, e.peer_ip) for e in outbound] == [(TX_GENESIS, "198.51.100.77")]


@pytest.mark.parametrize("writer", [write_pcap, write_pcapng])
def test_wtxid_inv_is_resolved_by_the_transaction_in_the_same_capture(tmp_path, wire, writer):
    path = writer(tmp_path / "cap.pcap", wire["packets"])
    events = cr.read_capture(path, local_ips=[NODE])
    invs = [e for e in events if e.message_type.startswith("inv") and e.direction == "inbound"]
    assert len(invs) == 1
    assert invs[0].message_type == "inv", "the tx was in the capture, so this resolves"
    assert invs[0].txid == wire["txid"] != wire["wtxid"]


def test_an_unresolved_wtxid_keeps_its_marker(tmp_path, wire):
    """Without the `tx` message there is nothing to resolve against, and the
    row must say the identifier is a wtxid rather than pass it off as a txid."""
    inv_only = [wire["packets"][0]]
    path = write_pcap(tmp_path / "inv_only.pcap", inv_only)
    (event,) = cr.read_capture(path, local_ips=[NODE])
    assert event.message_type == "inv_wtx"
    assert event.txid == wire["wtxid"]


def test_non_bitcoin_traffic_and_a_desynchronised_stream_are_survived(tmp_path, wire):
    """Port 443 traffic is ignored outright; garbage prepended to a P2P flow
    must resynchronise on the next magic instead of losing the flow."""
    raw, txid, _ = segwit_tx()
    noisy = b"\xff" * 37 + p2p_message("tx", raw)
    packets = [(1_790_244_003.0, tcp_frame(PEER, NODE, 8333, 51000, noisy))]
    path = write_pcap(tmp_path / "noisy.pcap", packets)
    events = cr.read_capture(path, local_ips=[NODE])
    assert [e.txid for e in events] == [txid]


def test_the_capture_host_is_inferred_when_not_given(tmp_path, wire):
    """Every flow in a host capture has that host at one end."""
    path = write_pcap(tmp_path / "cap.pcap", wire["packets"])
    inferred = cr.read_capture(path)
    assert {e.peer_ip for e in inferred} == {PEER, "198.51.100.77"}


# --- 3. .btcap -----------------------------------------------------------
def test_btcap_reads_aliases_and_skips_unusable_lines():
    path = FIXTURES / "node1.btcap"
    events = cr.read_capture(path)
    assert cr.detect_format(path) == "btcap"
    assert len(events) == 3, "a malformed line and a line with no message type are dropped"
    assert events[1].txid == "0000000000000000000000000000000000000000000000000000000000000abc"
    assert events[1].peer_ip == "198.51.100.77"
    assert events[1].user_agent == "/bitcoinj:0.16.2/"
    assert events[1].message_type == "inv_wtx"


def test_btcap_keeps_a_monotonic_clock_it_was_given():
    """A collector that recorded a monotonic reading knows better than an offset
    derived from wall-clock times that may have been stepped mid-capture."""
    events = cr.read_capture(FIXTURES / "node1.btcap")
    assert events[0].monotonic_or_derived_ts == 12.5
    assert events[1].monotonic_or_derived_ts == pytest.approx(0.06, abs=1e-6)


def test_gzipped_captures_are_read(tmp_path):
    import gzip

    path = tmp_path / "node1.btcap.gz"
    path.write_bytes(gzip.compress((FIXTURES / "node1.btcap").read_bytes()))
    assert len(cr.read_capture(path)) == 3


# --- the bundle, and the frame the feature stage will read ---------------
def test_read_directory_merges_formats_in_time_order(tmp_path, wire):
    for name in ("node1.debug.log", "node1.btcap"):
        (tmp_path / name).write_bytes((FIXTURES / name).read_bytes())
    write_pcap(tmp_path / "node1.pcap", wire["packets"])
    (tmp_path / "manifest.json").write_text("{}")
    (tmp_path / "notes.md").write_text("not a capture")

    events = cr.read_directory(tmp_path, local_ips=[NODE])
    stamps = [e.wall_clock_ts for e in events]
    assert stamps == sorted(stamps)
    # The .btcap fixture names its own collector, which is the point of the
    # field: a bundle mixes formats and each row still says where it came from.
    assert {e.capture_source for e in events} == {
        "debug.log:node1.debug.log", "btcap:node1.btcap", "pcap:node1.pcap",
        "collector:node1"}


def test_to_frame_has_the_canonical_columns():
    frame = cr.to_frame(cr.read_capture(FIXTURES / "node1.debug.log"))
    assert list(frame.columns) == cr.COLUMNS
    assert str(frame["wall_clock_ts"].dtype).startswith("datetime64")


def test_detect_format_refuses_to_guess():
    with pytest.raises(ValueError):
        cr.detect_format(FIXTURES.parent / "capture")   # a directory is not a capture
