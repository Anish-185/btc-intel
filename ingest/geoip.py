"""Offline GeoIP/ASN enrichment against local .mmdb files.

No network, ever: the databases are files on disk, paths from config.yaml.
A missing database is not fatal — the columns come back null so the rest of the
pipeline still runs; the correlation engine can see the nulls and abstain.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path

import maxminddb

import config

log = logging.getLogger(__name__)

COLUMNS = ["geo_country", "asn", "asn_org", "high_risk_asn"]
EMPTY = {"geo_country": None, "asn": None, "asn_org": None, "high_risk_asn": False}


@lru_cache(maxsize=1)
def high_risk_asns() -> frozenset[int]:
    return frozenset(config.get("geoip.high_risk_asns"))


def is_high_risk_asn(asn: int) -> bool:
    """VPN / hosting / Tor-adjacent ASN — location and identity evidence from an
    IP in one of these should be discounted, not trusted."""
    try:
        return int(asn) in high_risk_asns()
    except (TypeError, ValueError):
        return False


class GeoIp:
    """Country + ASN lookup. Readers may be injected (tests, alternate sources)."""

    def __init__(self, cfg: dict | None = None, country_reader=None, asn_reader=None):
        cfg = cfg or config.load()
        self.country = country_reader or _open(cfg["geoip"]["country_db"])
        self.asn = asn_reader or _open(cfg["geoip"]["asn_db"])
        self._cache: dict[str, dict] = {}

    @property
    def available(self) -> bool:
        return self.country is not None or self.asn is not None

    def lookup(self, ip: str) -> dict:
        if ip in self._cache:
            return self._cache[ip]
        out = dict(EMPTY)
        if ip:
            rec = _get(self.country, ip) or {}
            country = rec.get("country") or rec.get("registered_country") or {}
            out["geo_country"] = country.get("iso_code")
            asn_rec = _get(self.asn, ip) or {}
            asn = asn_rec.get("autonomous_system_number")
            out["asn"] = asn
            out["asn_org"] = asn_rec.get("autonomous_system_organization")
            out["high_risk_asn"] = is_high_risk_asn(asn) if asn is not None else False
        self._cache[ip] = out
        return out

    def close(self) -> None:
        for reader in (self.country, self.asn):
            if hasattr(reader, "close"):
                reader.close()


def _open(path):
    p = Path(path)
    if not p.exists():
        log.warning("GeoIP database missing: %s — enrichment columns will be null", p)
        return None
    return maxminddb.open_database(str(p))


def _get(reader, ip: str):
    if reader is None:
        return None
    try:
        return reader.get(ip)
    except (ValueError, TypeError):  # not an address this database understands
        return None


def enrich(df, geo: GeoIp | None = None, column: str = "src_ip", cfg: dict | None = None):
    """Add geo_country / asn / asn_org / high_risk_asn for each row's src_ip."""
    geo = geo or GeoIp(cfg)
    lookups = [geo.lookup(str(ip)) for ip in df[column]] if len(df) else []
    for col in COLUMNS:
        df[col] = [row[col] for row in lookups] if lookups else []
    return df
