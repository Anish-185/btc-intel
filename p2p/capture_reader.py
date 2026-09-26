"""Real Bitcoin P2P relay observations, parsed from files on disk.

Three input formats, one output record. An operator on a collection host
produces one of these (docs/CAPTURE.md); the air-gapped analysis host reads it.

  debug.log   bitcoind run with `debug=net`. Cheap, already running on most
              nodes, and the only format that names the peer the way the node
              itself does. It logs a txid only on inv lines: a `tx` message's
              body is not written to the log, so add `debug=mempool` if the
              arrival of the transaction itself matters.
  pcap        tcpdump/dumpcap on port 8333, classic pcap or pcapng. The
              complete wire truth, including the transactions themselves, at
              the cost of decoding TCP payloads ourselves.
  .btcap      JSON Lines, one event per line, using the field names below. Our
              own format, for a collector that already knows what it saw.

WTXID RELAY, AND WHY SOME ROWS ARE NOT TXIDS
Since BIP-339 a node announces transactions by *wtxid*, which differs from the
txid for every segwit transaction. An inv that carries a wtxid is recorded with
`message_type="inv_wtx"` and the wtxid in the `txid` field — never silently as a
txid, because grouping the two together would merge observations of different
identifiers for the same transaction and quietly corrupt every per-transaction
feature. When the same capture also contains the `tx` message, we compute both
identifiers from it and rewrite the matching `inv_wtx` rows to the real txid.
Rows that never resolve keep the `inv_wtx` marker: unresolved, and saying so.
"""

from __future__ import annotations

import gzip
import hashlib
import ipaddress
import json
import logging
import re
import struct
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

import config

log = logging.getLogger(__name__)

#: Network magics we will resynchronise on: main, testnet3, signet, regtest.
#: Anything else in a capture is not a Bitcoin P2P stream we understand.
DEFAULT_MAGICS = ("f9beb4d9", "0b110907", "0a03cf40", "fabfb5da")

#: A P2P message header is 24 bytes and the protocol caps a payload at 32 MiB.
#: A larger length field means the stream is desynchronised, not that a huge
#: message is coming.
HEADER = 24
MAX_PAYLOAD = 32 * 1024 * 1024

INV_TX, INV_WTX = 1, 5          # MSG_TX, MSG_WTX inventory types


@dataclass
class RelayEvent:
    """One observation: this peer told us about this transaction, at this time."""

    txid: str
    peer_ip: str
    peer_port: int | None
    peer_id: int | None
    user_agent: str | None
    wall_clock_ts: float                 # epoch seconds, from the capture
    monotonic_or_derived_ts: float       # see note below
    message_type: str                    # inv | inv_wtx | tx
    direction: str                       # inbound | outbound
    capture_source: str                  # "<format>:<file name>"
    transport: str | None = None         # v1 | v2 (BIP-324) | None when unknown
    unreadable_flows: int | None = None  # pcap only: port-8333 flows never decoded
    services: int | None = None          # the peer's version-message service bits


#: `transport` is known from bitcoind's connect line ("transport: v2", Core
#: >= 26), from a .btcap field, and is always "v1" for pcap: a BIP-324 stream is
#: encrypted, so every message we could decode from a pcap came over v1. It is
#: what `analysis.validity` reads. A pcap cannot see *which* peers speak v2 —
#: their bytes never decode — so it records `unreadable_flows` instead: flows
#: on the P2P port that carried payload and never yielded a message. That count
#: is the evidence behind V2_PASSIVE_TAP.
#:
#: `services` is the service-flag field of the peer's `version` message: decoded
#: from a pcap, or a .btcap field. bitcoind's debug.log never writes it (the
#: version line carries only the user agent), so a debug.log capture leaves it
#: None — unknown, not zero.
#:
#: `monotonic_or_derived_ts` is the capture's own clock: a monotonic reading when
#: the source supplies one (.btcap may), otherwise seconds since the first event
#: in the file. Either way it is immune to the wall clock being stepped
#: mid-capture, which is exactly what timing features cannot survive. It is
#: comparable *within* one capture and meaningless across two.

COLUMNS = list(RelayEvent.__annotations__)


# --- shared helpers -------------------------------------------------------
def _magics(cfg: dict | None = None) -> tuple[bytes, ...]:
    values = ((cfg or config.load()).get("p2p") or {}).get("network_magics") or DEFAULT_MAGICS
    return tuple(bytes.fromhex(v) for v in values)


def _open(path: Path):
    """Captures get gzipped in transit more often than not."""
    return gzip.open(path, "rb") if path.suffix == ".gz" else open(path, "rb")


def _varint(buf: bytes, i: int) -> tuple[int, int]:
    """CompactSize at `i` -> (value, next index). Raises IndexError if short."""
    n = buf[i]
    if n < 0xFD:
        return n, i + 1
    width = {0xFD: 2, 0xFE: 4, 0xFF: 8}[n]
    return int.from_bytes(buf[i + 1:i + 1 + width], "little"), i + 1 + width


def _hash256(data: bytes) -> str:
    """Bitcoin's double SHA-256, as the hex id humans read (byte-reversed)."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()[::-1].hex()


def txids_of(raw: bytes) -> tuple[str, str]:
    """(txid, wtxid) for a serialised transaction.

    The txid is the hash of the transaction *without* witnesses, which for a
    segwit transaction is not the bytes on the wire — the witness has to be
    stripped and the remainder re-serialised. Getting this wrong produces a
    plausible-looking hash that matches nothing, so it is computed here rather
    than approximated anywhere else.
    """
    i = 4                                        # version
    legacy = bytearray(raw[:4])
    segwit = raw[4] == 0x00
    if segwit:
        i = 6                                    # marker 0x00, flag 0x01
    n_in, i = _varint(raw, i)
    start = i
    for _ in range(n_in):
        i += 36                                  # prevout: 32-byte hash + index
        script_len, i = _varint(raw, i)
        i += script_len + 4                      # script + sequence
    n_out, i = _varint(raw, i)
    for _ in range(n_out):
        i += 8                                   # value
        script_len, i = _varint(raw, i)
        i += script_len
    legacy += raw[start - _varint_width(n_in):i]  # inputs and outputs, verbatim
    if segwit:
        for _ in range(n_in):                    # skip the witness stacks
            items, i = _varint(raw, i)
            for _ in range(items):
                item_len, i = _varint(raw, i)
                i += item_len
    legacy += raw[i:i + 4]                       # locktime
    return _hash256(bytes(legacy)), _hash256(raw[:i + 4])


def _varint_width(value: int) -> int:
    return 1 if value < 0xFD else (3 if value <= 0xFFFF else (5 if value <= 0xFFFFFFFF else 9))


def _resolve_wtxids(events: list[RelayEvent], pairs: dict[str, str]) -> None:
    """Rewrite inv_wtx rows whose transaction we also saw on the wire."""
    for event in events:
        if event.message_type == "inv_wtx" and event.txid in pairs:
            event.txid = pairs[event.txid]
            event.message_type = "inv"


def _derive_clock(events: list[RelayEvent]) -> None:
    """Fill monotonic_or_derived_ts for rows that did not bring their own."""
    stamped = [e.wall_clock_ts for e in events if e.wall_clock_ts is not None]
    base = min(stamped) if stamped else 0.0
    for event in events:
        if event.monotonic_or_derived_ts is None:
            event.monotonic_or_derived_ts = round(event.wall_clock_ts - base, 6)


# --- 1. bitcoind debug.log (debug=net) -----------------------------------
#: Timestamps are ISO-8601 with microseconds on Core >= 0.17, plain otherwise.
_TS = re.compile(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2}(?:\.\d+)?)Z?")
_PEER = re.compile(r"\bpeer=(\d+)")
#: An `ip:port` on the same line as a peer id binds that peer to that address:
#: "New outbound peer connected: ... peer=3, peeraddr=1.2.3.4:8333", and the
#: disconnect line has the same shape. `peeraddr=` is preferred because the
#: version line carries *two* addresses — the peer's and, as `us=`, our own —
#: and binding a peer to our own address would make every event look local.
#: Tor addresses are matched too: v3 (56 base32 characters) and the retired v2
#: (16). They were skipped in P4, which silently dropped every onion peer's
#: events — the peers whose timing is least trustworthy vanished rather than
#: being flagged.
_HOSTPORT = (r"(\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-fA-F:]+\]"
             r"|(?:[a-z2-7]{56}|[a-z2-7]{16})\.onion):(\d{1,5})\b")
_PEERADDR = re.compile(r"\bpeeraddr=" + _HOSTPORT)
_BARE_ADDR = re.compile(r"\b" + _HOSTPORT)
_OURS = re.compile(r"\bus=")
_TRANSPORT = re.compile(r"\btransport[:=]\s*(v1|v2)\b")
_UA = re.compile(r"version message:\s*(/[^/\s]+/)")
#: The two net-debug lines that carry an identifier, and the mempool line that
#: carries the txid of a transaction actually accepted from a peer.
_INV = re.compile(r"\b(got|sending) inv:\s+(tx|wtx)\s+([0-9a-fA-F]{64})")
_ACCEPTED = re.compile(r"AcceptToMemoryPool:\s*peer=(\d+):\s*accepted\s+([0-9a-fA-F]{64})")


def _log_timestamp(line: str) -> float | None:
    m = _TS.match(line)
    if not m:
        return None
    try:
        return datetime.fromisoformat(f"{m.group(1)}T{m.group(2)}").replace(
            tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None


def parse_debug_log(path: Path, cfg: dict | None = None) -> list[RelayEvent]:
    """bitcoind's own log. Peers are numbered there, so addresses are learned
    from whichever lines mention both a peer id and an address."""
    path = Path(path)
    source = f"debug.log:{path.name}"
    addrs: dict[int, tuple[str, int]] = {}
    agents: dict[int, str] = {}
    transports: dict[int, str] = {}
    events: list[RelayEvent] = []

    with _open(path) as handle:
        for raw_line in handle:
            line = raw_line.decode("utf-8", errors="replace").rstrip("\n")
            peer_match = _PEER.search(line)
            peer_id = int(peer_match.group(1)) if peer_match else None

            if peer_id is not None:
                addr = _PEERADDR.search(line)
                if addr is None and not _OURS.search(line):
                    addr = _BARE_ADDR.search(line)
                if addr is not None:
                    addrs[peer_id] = (addr.group(1).strip("[]"), int(addr.group(2)))
                if (ua := _UA.search(line)):
                    agents[peer_id] = ua.group(1)
                if (transport := _TRANSPORT.search(line)):
                    transports[peer_id] = transport.group(1)

            ts = _log_timestamp(line)
            for verb, kind, digest in _INV.findall(line):
                events.append(_log_event(
                    digest, peer_id, addrs, agents, ts, source,
                    "inv" if kind == "tx" else "inv_wtx",
                    "inbound" if verb == "got" else "outbound"))
            for accepted_peer, digest in _ACCEPTED.findall(line):
                events.append(_log_event(digest, int(accepted_peer), addrs, agents, ts,
                                         source, "tx", "inbound"))

    for event in events:            # the connect line can follow the first inv
        event.transport = transports.get(event.peer_id)
    _derive_clock(events)
    return events


def _log_event(digest: str, peer_id: int | None, addrs: dict, agents: dict,
               ts: float | None, source: str, message_type: str,
               direction: str) -> RelayEvent:
    ip, port = addrs.get(peer_id, (None, None))
    return RelayEvent(
        txid=digest.lower(), peer_ip=ip, peer_port=port, peer_id=peer_id,
        user_agent=agents.get(peer_id), wall_clock_ts=ts,
        monotonic_or_derived_ts=None, message_type=message_type,
        direction=direction, capture_source=source)


# --- 2. pcap / pcapng ----------------------------------------------------
def _pcap_records(data: bytes) -> Iterator[tuple[float, bytes, int]]:
    """(timestamp, link-layer frame, linktype) for classic pcap."""
    endian = {b"\xd4\xc3\xb2\xa1": ("<", 1e6), b"\xa1\xb2\xc3\xd4": (">", 1e6),
              b"\x4d\x3c\xb2\xa1": ("<", 1e9), b"\xa1\xb2\x3c\x4d": (">", 1e9)}
    if data[:4] not in endian:
        raise ValueError("not a pcap file: unknown magic")
    e, divisor = endian[data[:4]]
    linktype = struct.unpack_from(e + "I", data, 20)[0]
    i = 24
    while i + 16 <= len(data):
        sec, frac, incl, _orig = struct.unpack_from(e + "IIII", data, i)
        i += 16
        yield sec + frac / divisor, data[i:i + incl], linktype
        i += incl


def _pcapng_records(data: bytes) -> Iterator[tuple[float, bytes, int]]:
    """The same, for pcapng. Only the three blocks that carry packets matter:
    section header (byte order), interface description (link type and time
    resolution) and enhanced packet block."""
    if data[8:12] == b"\x4d\x3c\x2b\x1a":
        e = "<"
    elif data[8:12] == b"\x1a\x2b\x3c\x4d":
        e = ">"
    else:
        raise ValueError("not a pcapng file: no byte-order magic")
    interfaces: list[tuple[int, int]] = []          # (linktype, ts divisor)
    i = 0
    while i + 12 <= len(data):
        block_type, length = struct.unpack_from(e + "II", data, i)
        if length < 12 or i + length > len(data):
            break
        body = data[i + 8:i + length - 4]
        if block_type == 0x00000001:                # interface description
            linktype = struct.unpack_from(e + "H", body, 0)[0]
            interfaces.append((linktype, _tsresol(body[8:], e)))
        elif block_type == 0x00000006:              # enhanced packet
            iface, hi, lo, caplen, _orig = struct.unpack_from(e + "IIIII", body, 0)
            linktype, divisor = interfaces[iface] if iface < len(interfaces) else (1, 10 ** 6)
            yield ((hi << 32) | lo) / divisor, body[20:20 + caplen], linktype
        i += length


def _tsresol(options: bytes, e: str) -> int:
    """if_tsresol (option code 9) — microseconds unless the capture says else."""
    i = 0
    while i + 4 <= len(options):
        code, length = struct.unpack_from(e + "HH", options, i)
        value = options[i + 4:i + 4 + length]
        if code == 0:
            break
        if code == 9 and value and not value[0] & 0x80:
            return 10 ** value[0]
        # ponytail: a power-of-two resolution (high bit set) is legal and never
        # seen from tcpdump/dumpcap; handle it when a capture actually uses one.
        i += 4 + length + (-length % 4)
    return 10 ** 6


#: Link layers tcpdump produces in practice -> bytes of header to skip. None
#: means "read the ethertype", because the offset alone is not enough.
_LINK_SKIP = {0: 4, 101: 0, 228: 0, 229: 0, 113: 16, 276: 20}


def _ip_payload(frame: bytes, linktype: int) -> tuple[str, str, bytes] | None:
    """(src ip, dst ip, TCP segment) or None if this is not TCP over IP."""
    if linktype == 1:                               # Ethernet
        if len(frame) < 14:
            return None
        ethertype, offset = struct.unpack_from("!H", frame, 12)[0], 14
        while ethertype in (0x8100, 0x88A8):        # VLAN tags stack
            ethertype, offset = struct.unpack_from("!H", frame, offset + 2)[0], offset + 4
        if ethertype not in (0x0800, 0x86DD):
            return None
    elif linktype in _LINK_SKIP:
        offset = _LINK_SKIP[linktype]
    else:
        return None

    packet = frame[offset:]
    if not packet:
        return None
    version = packet[0] >> 4
    if version == 4:
        if len(packet) < 20 or packet[9] != 6:      # protocol 6 = TCP
            return None
        header = (packet[0] & 0x0F) * 4
        src, dst = packet[12:16], packet[16:20]
        total = struct.unpack_from("!H", packet, 2)[0] or len(packet)
        segment = packet[header:total]
    elif version == 6:
        if len(packet) < 40 or packet[6] != 6:      # no extension-header walk
            return None
        src, dst = packet[8:24], packet[24:40]
        payload_len = struct.unpack_from("!H", packet, 4)[0]
        segment = packet[40:40 + payload_len] if payload_len else packet[40:]
    else:
        return None

    if len(segment) < 20:
        return None
    return (str(ipaddress.ip_address(src)), str(ipaddress.ip_address(dst)), segment)


def _messages(buffer: bytearray, magics: tuple[bytes, ...]) -> Iterator[tuple[str, bytes]]:
    """Complete P2P messages at the front of a flow buffer, consuming them.

    ponytail: no TCP reassembly by sequence number — payloads are appended in
    capture order. A retransmit or a reordered segment desynchronises the
    stream, which is why a bad header resynchronises on the next magic rather
    than giving up on the flow. Add seq-ordered reassembly if a real capture
    shows losses.
    """
    while len(buffer) >= HEADER:
        if bytes(buffer[:4]) not in magics:
            found = -1
            for magic in magics:
                at = buffer.find(magic, 1)
                if at != -1 and (found == -1 or at < found):
                    found = at
            if found == -1:
                del buffer[:max(len(buffer) - 3, 0)]
                return
            del buffer[:found]
            continue
        length = int.from_bytes(buffer[16:20], "little")
        if length > MAX_PAYLOAD:
            del buffer[:4]
            continue
        if len(buffer) < HEADER + length:
            return
        command = bytes(buffer[4:16]).rstrip(b"\x00").decode("ascii", errors="replace")
        payload = bytes(buffer[HEADER:HEADER + length])
        del buffer[:HEADER + length]
        yield command, payload


def _local_ip(flows: dict, given: Iterable[str] | None) -> set[str]:
    """Which address is the capturing node.

    A capture on one host has that host at one end of every flow, so the
    address common to all of them is ours. That inference is a convenience, not
    a fact: pass `local_ips` (config `p2p.local_ips`) on a span port or a host
    with several addresses, where it does not hold.
    """
    if given:
        return set(given)
    counts: dict[str, int] = {}
    for src, dst, *_ in flows:
        for ip in (src, dst):
            counts[ip] = counts.get(ip, 0) + 1
    return {max(counts, key=counts.get)} if counts else set()


def parse_pcap(path: Path, cfg: dict | None = None,
               local_ips: Iterable[str] | None = None) -> list[RelayEvent]:
    """Decode P2P messages out of a port-8333 capture."""
    path = Path(path)
    cfg = cfg or config.load()
    p2p_cfg = cfg.get("p2p") or {}
    port = int(p2p_cfg.get("port", 8333))
    magics = _magics(cfg)
    local_ips = local_ips or p2p_cfg.get("local_ips")

    with _open(path) as handle:
        data = handle.read()
    records = (_pcapng_records(data) if data[:4] == b"\x0a\x0d\x0d\x0a"
               else _pcap_records(data))

    # Two passes: the first decodes messages per flow, the second decides which
    # end of each flow is us — which needs every flow before it can be answered.
    buffers: dict[tuple, bytearray] = {}
    readable: set[tuple] = set()
    decoded: list[tuple[float, tuple, str, bytes]] = []
    for ts, frame, linktype in records:
        parsed = _ip_payload(frame, linktype)
        if parsed is None:
            continue
        src, dst, segment = parsed
        sport, dport = struct.unpack_from("!HH", segment, 0)
        if port not in (sport, dport):
            continue
        offset = (segment[12] >> 4) * 4
        payload = segment[offset:]
        if not payload:
            continue
        flow = (src, dst, sport, dport)
        buffer = buffers.setdefault(flow, bytearray())
        buffer += payload
        for command, message in _messages(buffer, magics):
            decoded.append((ts, flow, command, message))
            readable.add(flow)

    ours = _local_ip(buffers.keys(), local_ips)
    events: list[RelayEvent] = []
    pairs: dict[str, str] = {}
    handshakes: dict[str, tuple[str | None, int]] = {}
    source = f"pcap:{path.name}"
    for ts, (src, dst, sport, dport), command, payload in decoded:
        inbound = src not in ours
        peer_ip, peer_port = (src, sport) if inbound else (dst, dport)
        direction = "inbound" if inbound else "outbound"
        if command == "version" and inbound and (hello := _version_fields(payload)):
            handshakes[peer_ip] = hello
        elif command == "inv":
            for kind, digest in _inv_entries(payload):
                events.append(RelayEvent(
                    digest, peer_ip, peer_port, None, None, ts, None,
                    "inv" if kind == INV_TX else "inv_wtx", direction, source, "v1"))
        elif command == "tx":
            try:
                txid, wtxid = txids_of(payload)
            except (IndexError, KeyError, ValueError):
                log.warning("%s: undecodable tx message of %d bytes", path.name, len(payload))
                continue
            pairs[wtxid] = txid
            events.append(RelayEvent(txid, peer_ip, peer_port, None, None, ts, None,
                                     "tx", direction, source, "v1"))

    unreadable = len(set(buffers) - readable)
    for event in events:
        event.unreadable_flows = unreadable
        event.user_agent, event.services = handshakes.get(event.peer_ip, (None, None))
    _resolve_wtxids(events, pairs)
    _derive_clock(events)
    return events


def _version_fields(payload: bytes) -> tuple[str | None, int] | None:
    """(user agent, services) from a `version` payload: int32 version, uint64
    services, int64 time, two 26-byte addresses, uint64 nonce, then the user
    agent as a var_str at offset 80."""
    if len(payload) < 81:
        return None
    services = int.from_bytes(payload[4:12], "little")
    try:
        length, i = _varint(payload, 80)
    except IndexError:
        return None, services
    agent = payload[i:i + length].decode("utf-8", errors="replace") or None
    return agent, services


def _inv_entries(payload: bytes) -> list[tuple[int, str]]:
    """Transaction entries of an inv message; other inventory types ignored."""
    try:
        count, i = _varint(payload, 0)
    except IndexError:
        return []
    out = []
    for _ in range(count):
        if i + 36 > len(payload):
            break
        kind = int.from_bytes(payload[i:i + 4], "little")
        if kind in (INV_TX, INV_WTX):
            out.append((kind, payload[i + 4:i + 36][::-1].hex()))
        i += 36
    return out


# --- 3. our own .btcap JSON Lines ---------------------------------------
_ALIASES = {"time": "wall_clock_ts", "timestamp": "wall_clock_ts", "ts": "wall_clock_ts",
            "monotonic": "monotonic_or_derived_ts", "monotonic_ts": "monotonic_or_derived_ts",
            "ip": "peer_ip", "port": "peer_port", "command": "message_type",
            "subver": "user_agent", "hash": "txid",
            "service_flags": "services"}


def parse_btcap(path: Path, cfg: dict | None = None) -> list[RelayEvent]:
    """One JSON object per line. A malformed line is skipped and counted, not
    fatal: a truncated capture is the normal end of a collection run."""
    path = Path(path)
    source = f"btcap:{path.name}"
    events, skipped = [], 0
    with _open(path) as handle:
        for line in handle:
            text = line.decode("utf-8", errors="replace").strip()
            if not text or text.startswith("#"):
                continue
            try:
                raw = json.loads(text)
            except json.JSONDecodeError:
                skipped += 1
                continue
            if not isinstance(raw, dict):
                skipped += 1
                continue
            row = {_ALIASES.get(k, k): v for k, v in raw.items()}
            if not row.get("txid") or not row.get("message_type"):
                skipped += 1
                continue
            events.append(RelayEvent(
                txid=str(row["txid"]).lower(),
                peer_ip=row.get("peer_ip"),
                peer_port=int(row["peer_port"]) if row.get("peer_port") is not None else None,
                peer_id=int(row["peer_id"]) if row.get("peer_id") is not None else None,
                user_agent=row.get("user_agent"),
                wall_clock_ts=_epoch(row.get("wall_clock_ts")),
                monotonic_or_derived_ts=(float(row["monotonic_or_derived_ts"])
                                         if row.get("monotonic_or_derived_ts") is not None
                                         else None),
                message_type=str(row["message_type"]),
                direction=str(row.get("direction") or "inbound"),
                capture_source=str(row.get("capture_source") or source),
                transport=row.get("transport"),
                services=_services(row.get("services"))))
    if skipped:
        log.warning("%s: %d unusable line(s) skipped", path.name, skipped)
    _derive_clock(events)
    return events


def _services(value) -> int | None:
    """An integer, or the hex string some collectors write (`"0x409"`)."""
    if value is None or value == "":
        return None
    try:
        return int(value, 0) if isinstance(value, str) else int(value)
    except ValueError:
        return None


def _epoch(value) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


# --- dispatch ------------------------------------------------------------
FORMATS = {"debug_log": parse_debug_log, "pcap": parse_pcap, "btcap": parse_btcap}

_SUFFIXES = {".log": "debug_log", ".txt": "debug_log", ".pcap": "pcap", ".pcapng": "pcap",
             ".cap": "pcap", ".btcap": "btcap", ".jsonl": "btcap"}


def detect_format(path) -> str:
    """Extension first, then the file's own first bytes — an operator renaming
    a capture should not change what it is."""
    path = Path(path)
    if not path.is_file():
        raise ValueError(f"{path} is not a capture file "
                         "(a bundle directory goes to read_directory)")
    real = Path(path.stem) if path.suffix == ".gz" else path
    with _open(path) as handle:
        head = handle.read(8)
    if head[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1",
                    b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"):
        return "pcap"
    if real.suffix.lower() in _SUFFIXES:
        return _SUFFIXES[real.suffix.lower()]
    if head[:1] == b"{":
        return "btcap"
    raise ValueError(f"cannot tell what kind of capture {path.name} is")


def read_capture(path, fmt: str | None = None, cfg: dict | None = None,
                 **kwargs) -> list[RelayEvent]:
    """Read one capture file. `fmt` overrides detection."""
    fmt = fmt or detect_format(path)
    if fmt not in FORMATS:
        raise ValueError(f"no reader for {fmt!r}; have {sorted(FORMATS)}")
    if fmt != "pcap":
        kwargs.pop("local_ips", None)
    return FORMATS[fmt](Path(path), cfg, **kwargs)


def read_directory(directory, cfg: dict | None = None, **kwargs) -> list[RelayEvent]:
    """Every capture in a bundle, oldest event first. Unreadable files are
    logged and skipped: one corrupt file must not lose the other nine."""
    events: list[RelayEvent] = []
    for path in sorted(Path(directory).iterdir()):
        # A bundle also holds its own metadata: the manifest that seals it and,
        # for a ground-truth run, the label file. Both are JSON and would
        # otherwise be sniffed as .btcap captures and parsed as garbage.
        if not path.is_file() or path.name.endswith(("manifest.json", ".labels.json")):
            continue
        try:
            events.extend(read_capture(path, cfg=cfg, **kwargs))
        except (ValueError, OSError, struct.error) as exc:
            log.warning("skipping %s: %s: %s", path.name, type(exc).__name__, exc)
    events.sort(key=lambda e: (e.wall_clock_ts if e.wall_clock_ts is not None else 0.0))
    return events


def to_frame(events: Iterable[RelayEvent]):
    """A DataFrame with COLUMNS, for the feature stage and parquet."""
    import pandas as pd

    frame = pd.DataFrame([asdict(e) for e in events], columns=COLUMNS)
    frame["wall_clock_ts"] = pd.to_datetime(frame["wall_clock_ts"], unit="s", utc=True)
    return frame


def main(argv=None) -> None:
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    ap = argparse.ArgumentParser(prog="p2p.capture_reader", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", help="a capture file or a bundle directory")
    ap.add_argument("--format", choices=sorted(FORMATS), default=None)
    ap.add_argument("--local-ip", action="append", dest="local_ips",
                    help="this capture host's address (pcap only; inferred otherwise)")
    ap.add_argument("--output", default=None, help="write the events to parquet")
    args = ap.parse_args(argv)

    path = Path(args.path)
    events = (read_directory(path, local_ips=args.local_ips) if path.is_dir()
              else read_capture(path, args.format, local_ips=args.local_ips))
    by_type: dict[str, int] = {}
    for event in events:
        by_type[event.message_type] = by_type.get(event.message_type, 0) + 1
    if args.output:
        to_frame(events).to_parquet(args.output, index=False)
    print(json.dumps({"events": len(events), "by_message_type": by_type,
                      "transactions": len({e.txid for e in events}),
                      "peers": len({e.peer_ip for e in events if e.peer_ip}),
                      "unresolved_wtxid": by_type.get("inv_wtx", 0),
                      "output": args.output}, indent=2))


if __name__ == "__main__":
    main()
