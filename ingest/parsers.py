"""CSV / JSON / XML parsers. Each yields records keyed by our canonical names.

Nothing here knows NTRO's field names: they are read from config.yaml's schema
map, so a rename in the real data is a config edit.
"""

from __future__ import annotations

import csv
import json
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from pathlib import Path

import config

FIELDS = ["timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "txid",
          "input_addresses", "output_addresses", "input_amounts", "output_amounts",
          "fee", "script_type",
          # optional in a dump; used as the GeoIP fallback (see geoip.enrich)
          "asn", "geo_country"]

LIST_FIELDS = {"input_addresses", "output_addresses", "input_amounts", "output_amounts"}
NUMERIC_LISTS = {"input_amounts", "output_amounts"}


def _mapping(cfg: dict) -> dict[str, str]:
    """canonical name -> the key this dataset actually uses."""
    schema = cfg["schema"]
    return {f: schema.get("tx_id" if f == "txid" else f, f) for f in FIELDS}


def _split(value, sep: str, numeric: bool) -> list:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        items = list(value)
    else:
        items = [v for v in str(value).split(sep) if v != ""]
    return [_num(v) for v in items] if numeric else [str(v).strip() for v in items]


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return v  # kept as-is so validation reports it instead of the parser crashing


def _normalise(raw: dict, m: dict[str, str], sep: str) -> dict:
    out = {}
    for field, key in m.items():
        value = raw.get(key)
        out[field] = _split(value, sep, field in NUMERIC_LISTS) if field in LIST_FIELDS else value
    return out


def parse_csv(path: Path, cfg: dict | None = None) -> Iterator[tuple[int, dict]]:
    cfg = cfg or config.load()
    m, sep = _mapping(cfg), cfg["ingest"]["list_separator"]
    with Path(path).open(newline="", encoding="utf-8") as fh:
        for n, raw in enumerate(csv.DictReader(fh), start=2):  # row 1 is the header
            yield n, _normalise(raw, m, sep)


def parse_json(path: Path, cfg: dict | None = None) -> Iterator[tuple[int, dict]]:
    cfg = cfg or config.load()
    m, sep = _mapping(cfg), cfg["ingest"]["list_separator"]
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):  # tolerate {"records": [...]} wrappers
        data = next((v for v in data.values() if isinstance(v, list)), [])
    for n, raw in enumerate(data, start=1):
        yield n, _normalise(raw if isinstance(raw, dict) else {}, m, sep)


def parse_xml(path: Path, cfg: dict | None = None) -> Iterator[tuple[int, dict]]:
    cfg = cfg or config.load()
    m, sep = _mapping(cfg), cfg["ingest"]["list_separator"]
    for n, elem in enumerate(ET.parse(path).getroot(), start=1):
        raw: dict = {}
        for child in elem:
            items = [(i.text or "") for i in child]
            raw[child.tag] = items if items else (child.text or "")
        yield n, _normalise(raw, m, sep)


PARSERS = {"csv": parse_csv, "json": parse_json, "xml": parse_xml}


def parse(path, fmt: str | None = None, cfg: dict | None = None) -> Iterator[tuple[int, dict]]:
    path = Path(path)
    fmt = fmt or path.suffix.lstrip(".").lower()
    if fmt not in PARSERS:
        raise ValueError(f"no parser for {fmt!r}; have {sorted(PARSERS)}")
    return PARSERS[fmt](path, cfg)
