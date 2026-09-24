"""Bitcoin P2P relay observations, read from disk.

Nothing in this package opens a socket. Captures are produced on a collection
host by tools that already exist (bitcoind's own debug log, tcpdump) and carried
across the air gap as files; see docs/CAPTURE.md. That split is what lets the
analysis host stay air-gapped while still seeing real network-layer evidence.

    from p2p.capture_reader import read_capture, read_directory, to_frame
    from p2p.manifest import seal_capture, verify_capture

Submodules are imported directly and not re-exported here, because both of them
are also `python -m` entry points — importing them from the package would make
every CLI run warn about a double import.
"""
