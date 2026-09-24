# Producing a capture, and carrying it across the air gap

The analysis host never touches the network. Everything it knows about the
Bitcoin P2P network arrives as a *file*: a capture, taken on a separate
collection host, sealed, and carried across on removable media. This document is
for the operator on the collection side.

Nothing in `p2p/` opens a socket. `tests/test_offline_guarantee.py` — which greps
every file we ship for sockets, HTTP clients and external URLs — passes with
`p2p/` present and **no entry added to its allowlist**. That is deliberate: the
air gap stays a property of the code, not a promise in a README.

```
collection host (online)                    air gap        analysis host (offline)
─────────────────────────                  ─────────       ───────────────────────
bitcoind -debug=net  ─┐                        │
tcpdump port 8333    ─┼─→ capture files ─→ seal│─→ carry ─→ verify ─→ read → features
your own collector   ─┘                        │
```

## Choosing a format

| | what it costs | what you get |
| --- | --- | --- |
| **`debug.log`** (`debug=net`) | nothing — a config line on a node you already run | peer numbering and user agents as the node itself sees them; **inv lines only** — a txid, not the transaction |
| **pcap** (`tcpdump`) | disk, and root to capture | the complete wire truth, transactions included; no peer ids or user agents unless the version handshake is in the capture |
| **`.btcap`** | writing a collector | exactly the fields you choose |

Run both of the first two if you can. They are complementary: the log names
peers, the pcap carries the transactions, and `p2p.capture_reader.read_directory`
merges a directory holding both into one time-ordered event stream.

## 1. bitcoind with `debug=net`

In `bitcoin.conf` on the collection node:

```ini
debug=net
debug=mempool        # optional; see below
logtimemicros=1      # microsecond timestamps — origin estimation is timing work
```

Then `bitcoin-cli stop && bitcoind -daemon`, or `bitcoin-cli logging '["net"]'`
to turn it on without a restart.

Two things to know before relying on this format:

* **`debug=net` logs a transaction identifier only on `inv` lines.** The body of
  a `tx` message is not written to the log, so `received: tx (223 bytes) peer=1`
  carries no identifier and the reader does not emit a row for it — a
  transaction event with no transaction is worse than a missing one.
  `debug=mempool` adds `AcceptToMemoryPool: peer=N: accepted <txid>`, which is
  where the reader gets `message_type="tx"` from.
* **Announcements are by wtxid.** Since BIP-339 a modern node logs
  `got inv: wtx <hash>`, and a wtxid is not a txid for any segwit transaction.
  Those rows are marked `message_type="inv_wtx"` and are *not* silently treated
  as txids. Only a capture that also contains the transaction itself — i.e. a
  pcap — can resolve them. A log-only bundle will leave most inv rows
  unresolved, and this is the main reason to take a pcap alongside.

Collect the rotated logs too (`debug.log`, `debug.log.1`, …); the reader takes a
directory.

## 2. tcpdump / dumpcap on port 8333

```sh
# 20 minutes of P2P traffic, rotating every 100 MB, headers and payload
sudo tcpdump -i any 'tcp port 8333' -s 0 -w /srv/capture/node1-%Y%m%d-%H%M.pcap \
     -G 1200 -W 12 -Z "$USER"

# or with dumpcap, which writes pcapng and is happier running unattended
sudo dumpcap -i eth0 -f 'tcp port 8333' -b duration:1200 -b files:12 \
     -w /srv/capture/node1.pcapng
```

Both classic pcap and pcapng are read, in either byte order, with microsecond or
nanosecond timestamps.

* **`-s 0` matters.** A snap length that truncates packets truncates
  transactions, and a truncated `tx` message hashes to nothing. The reader logs
  `undecodable tx message` and carries on, but the observation is lost.
* **Link types**: Ethernet, Linux cooked capture (`-i any`), raw IP and loopback
  are handled. IPv6 is read when TCP follows the fixed header; a capture with
  IPv6 extension headers is not decoded.
* **Encrypted P2P transport (BIP-324) is opaque to this.** A v2 connection
  yields no readable messages. Captures against peers that negotiate v2 will be
  quiet, which looks identical to an idle link — check the event count against
  the node's own log before concluding the network was quiet.
* **Which end is us.** Inbound versus outbound is decided by the capture host's
  own address. Taken on the node itself, that address is the one common to every
  flow and the reader infers it. On a span port, a bridge, or a multi-homed
  host, that inference is wrong — set `p2p.local_ips` in `config.yaml` or pass
  `--local-ip` — and getting it wrong inverts direction on every row, which is
  precisely the signal the origination model is built on.

## 3. Our own `.btcap`

JSON Lines, one event per line, with the field names of `p2p.RelayEvent`. Blank
lines and `#` comments are skipped; a malformed line is counted and skipped, not
fatal, because a truncated last line is how a collection run normally ends.

```json
{"txid": "4a5e…33b", "peer_ip": "203.0.113.9", "peer_port": 8333, "peer_id": 1,
 "user_agent": "/Satoshi:25.0.0/", "wall_clock_ts": "2026-09-24T10:00:01.250Z",
 "monotonic_or_derived_ts": 12.5, "message_type": "inv", "direction": "inbound",
 "capture_source": "collector:node1"}
```

`monotonic_or_derived_ts` is the one field worth supplying by hand. It is the
capture's own clock: pass a real monotonic reading and it is used verbatim;
leave it out and the reader derives seconds since the first event in the file.
Either way it survives the wall clock being stepped mid-capture, which a
timing-based estimator does not.

Short aliases are accepted on input (`ts`, `time`, `timestamp`, `ip`, `port`,
`hash`, `command`, `subver`, `monotonic`) so a collector need not be rewritten
around our names.

## 4. Seal the bundle

Once the capture has **stopped growing**, on the collection host:

```sh
python -m p2p.manifest seal /srv/capture/2026-09-24-node1 --note "node1, 20 min, 12 peers"
```

That writes `manifest.json` beside the files: a SHA-256 per file (paths relative,
so the bundle can move), and one `manifest_hash` over the whole list. It reuses
`custody.py`'s hashing rather than repeating it.

**This is not a digital signature.** There are no keys in this build, and
`custody.py` takes the same position on `actor` rather than inventing an identity
a court would have to test. The manifest proves the bundle is unchanged since
sealing; it does not prove who sealed it. A deployment signs `manifest_hash`
with the operator's key, and that one field is the whole integration point.

## 5. Carry it across, and verify on arrival

Copy the directory — `manifest.json` included — to removable media, then on the
analysis host:

```sh
python -m p2p.manifest verify data/capture/2026-09-24-node1
```

Exit status 0 and `"ok": true` means every file matches. Four failures are
reported separately, because they mean different things:

| field | what happened |
| --- | --- |
| `files_changed` | a file's bytes differ from the seal |
| `files_missing` | a sealed file is not there |
| `files_added_since_sealing` | a file appeared after sealing — no per-file hash can see this, only the list can |
| `manifest_self_consistent: false` | the manifest itself was edited |

Either way the import is appended to the chain-of-custody ledger — as
`capture_imported` or `capture_import_failed`. A bundle that arrived altered is
the single most important thing that ledger can hold, so it is never the branch
that writes nothing. A successful import also re-paths the seals to where this
host holds the files, so `python -m custody verify` watches them from then on.

## 6. Read it

```sh
python -m p2p.capture_reader data/capture/2026-09-24-node1 \
    --output data/processed/relay_events.parquet
```

```
{
  "events": 18452,
  "by_message_type": {"inv": 17«…», "inv_wtx": 402, "tx": 1990},
  "transactions": 3117,
  "peers": 74,
  "unresolved_wtxid": 402,
  "output": "data/processed/relay_events.parquet"
}
```

`unresolved_wtxid` is the number to look at first. A large value means the
bundle announced transactions it never carried — usually a log-only bundle, or a
pcap with a snap length that truncated the `tx` messages. Those rows are
identified by wtxid, and nothing downstream may group them with txid rows.

## What this deliberately does not do

* **No live collector.** No socket, no wire handshake, no peer selection. That
  is what keeps the analysis host's air gap a tested property.
* **No TCP reassembly by sequence number.** Payloads are appended per flow in
  capture order, and a bad header resynchronises on the next network magic. A
  lossy or heavily reordered capture can drop a message; a clean host capture
  does not. Marked in the source with its upgrade path.
* **No decryption.** BIP-324 v2 transport is unreadable by design.
