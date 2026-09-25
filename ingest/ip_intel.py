"""Classify an IP from locally cached public intelligence.

Four classes, in precedence order:

  known_bitcoin_relay     A publicly reachable Bitcoin node (Bitnodes snapshot).
                          It forwards thousands of other people's transactions,
                          so seeing it in a relay record is nearly no evidence
                          about who sent anything.
  tor_exit                A Tor exit (the Tor Project's own list). Shared by
                          thousands of unrelated users by design.
  hosting_vpn             An ASN belonging to a datacentre, cloud or VPN
                          provider. Rented, shared, and chosen to be anonymous.
  residential_or_unknown  Everything else. Not "clean" — just not known to be
                          shared, which is the only case where an IP plausibly
                          maps to a small number of people.

Every classification carries its evidence: which file said so, and why. All
inputs come from data/intel/, populated once by offline/fetch_intel.sh; nothing
here reaches the network.
"""

from __future__ import annotations

import csv
import json
import logging
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import config
from ingest.geoip import is_high_risk_asn

log = logging.getLogger(__name__)

KNOWN_RELAY = "known_bitcoin_relay"
TOR_EXIT = "tor_exit"
HOSTING = "hosting_vpn"
RESIDENTIAL = "residential_or_unknown"
CLASSES = [KNOWN_RELAY, TOR_EXIT, HOSTING, RESIDENTIAL]


@dataclass
class IpClassification:
    ip: str
    ip_class: str
    evidence: list[str] = field(default_factory=list)
    asn: int | None = None

    @property
    def is_shared_infrastructure(self) -> bool:
        return self.ip_class != RESIDENTIAL


class IpIntel:
    """Loads the cached lists once and answers classify() from memory."""

    def __init__(self, intel_dir=None, cfg: dict | None = None,
                 synthetic: dict | None = None):
        cfg = cfg or config.load()
        self.cfg = cfg
        i = cfg["intel"]
        self.dir = Path(intel_dir or i["dir"])
        self.relays: set[str] = set()
        self.tor: set[str] = set()
        self.hosting_asns: set[int] = set()
        self.sources: dict[str, str] = {}

        self._load_known_nodes(self.dir / i["known_nodes"])
        self._load_tor(self.dir / i["tor_exits"])
        self._load_hosting_asns(self.dir / i["hosting_asns"])
        if synthetic:
            self.add_synthetic(synthetic)

    # --- loading ----------------------------------------------------------
    def _load_known_nodes(self, path: Path) -> None:
        if not path.exists():
            log.warning("no Bitcoin node snapshot at %s — run offline/fetch_intel.sh", path)
            return
        data = json.loads(path.read_text())
        # Bitnodes keys are "host:port"; IPv6 arrives as "[addr]:port"
        for endpoint in data.get("nodes", {}):
            host = endpoint.rsplit(":", 1)[0]
            self.relays.add(host.strip("[]"))
        self.sources[KNOWN_RELAY] = path.name

    def _load_tor(self, path: Path) -> None:
        if not path.exists():
            log.warning("no Tor exit list at %s — run offline/fetch_intel.sh", path)
            return
        self.tor = {line.strip() for line in path.read_text().splitlines()
                    if line.strip() and not line.startswith("#")}
        self.sources[TOR_EXIT] = path.name

    def _load_hosting_asns(self, path: Path) -> None:
        """The curated list, merged with the starter list in config.yaml."""
        self.hosting_asns = set(self.cfg["geoip"]["high_risk_asns"])
        if not path.exists():
            log.warning("no hosting ASN list at %s — using config.yaml only", path)
            return
        for row in csv.reader(path.read_text().splitlines()):
            if row and row[0].strip().upper() not in ("ASN", ""):
                try:
                    self.hosting_asns.add(int(row[0].strip().lstrip("AS")))
                except ValueError:
                    continue
        self.sources[HOSTING] = path.name

    def add_synthetic(self, node_intel: dict) -> None:
        """Honour a generated dataset's public node list, so the whole pipeline
        is testable offline. This file holds only what the real world publishes
        — relays, Tor exits, hosting — never who owns which wallet."""
        self.relays |= set(node_intel.get("relay", []))
        self.tor |= set(node_intel.get("tor_exit", []))
        self.hosting_asns |= {int(a) for a in node_intel.get("hosting_asns", [])}
        self._synthetic_hosting = set(node_intel.get("hosting", []))
        self.sources["synthetic"] = node_intel.get("source", "generated node_intel.json")

    # --- classification ---------------------------------------------------
    def classify(self, ip: str, asn: int | None = None) -> IpClassification:
        ip = str(ip)
        evidence: list[str] = []
        if ip.endswith(".onion"):
            # Reached over Tor: like an exit, it is where the transaction entered
            # the network and names nobody an ISP request could reach.
            evidence.append("a .onion address: the peer was reached over Tor")
            return IpClassification(ip, TOR_EXIT, evidence, asn)
        if ip in self.relays:
            evidence.append(f"listed as a reachable Bitcoin node in "
                            f"{self.sources.get(KNOWN_RELAY, 'the node snapshot')}")
            return IpClassification(ip, KNOWN_RELAY, evidence, asn)
        if ip in self.tor:
            evidence.append(f"listed as a Tor exit in "
                            f"{self.sources.get(TOR_EXIT, 'the Tor exit list')}")
            return IpClassification(ip, TOR_EXIT, evidence, asn)
        if asn is not None and int(asn) in self.hosting_asns:
            evidence.append(f"ASN {int(asn)} is a hosting/cloud/VPN network")
            return IpClassification(ip, HOSTING, evidence, asn)
        if ip in getattr(self, "_synthetic_hosting", set()):
            evidence.append("listed as a hosting-provider address in the node intel")
            return IpClassification(ip, HOSTING, evidence, asn)
        if asn is not None and is_high_risk_asn(asn):
            evidence.append(f"ASN {int(asn)} is on the high-risk list in config.yaml")
            return IpClassification(ip, HOSTING, evidence, asn)
        evidence.append("not listed as a public relay, Tor exit or hosting network")
        return IpClassification(ip, RESIDENTIAL, evidence, asn)

    def manifest(self) -> dict:
        path = self.dir / self.cfg["intel"]["manifest"]
        base = json.loads(path.read_text()) if path.exists() else {"files": {}}
        base["loaded"] = {"known_relays": len(self.relays), "tor_exits": len(self.tor),
                          "hosting_asns": len(self.hosting_asns)}
        return base

    @property
    def available(self) -> bool:
        return bool(self.relays or self.tor)


@lru_cache(maxsize=4)
def _default(intel_dir: str | None = None) -> IpIntel:
    return IpIntel(intel_dir)


def load_intel(intel_dir=None, node_intel=None, cfg: dict | None = None) -> IpIntel:
    """Build an IpIntel, optionally overlaid with a dataset's node_intel.json."""
    cfg = cfg or config.load()
    intel = IpIntel(intel_dir, cfg)
    path = Path(node_intel) if node_intel else None
    if path and path.is_dir():
        path = path / cfg["intel"]["synthetic_node_intel"]
    if path and path.exists():
        intel.add_synthetic(json.loads(path.read_text()))
    return intel


def classify_ip(ip: str, asn: int | None = None, intel: IpIntel | None = None) -> IpClassification:
    """Classify one IP. Uses the cached default intel unless one is passed."""
    return (intel or _default()).classify(ip, asn)
