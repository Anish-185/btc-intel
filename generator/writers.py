"""Streaming CSV / JSON / XML writers for the same underlying records.

Column names come from config.yaml's schema map, so renaming a field for a
real NTRO dump is a config edit, not a code edit. Writers stream because a
200k-transaction run with multi-hop relay records is millions of rows.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from xml.sax.saxutils import escape, quoteattr

import config

FIELDS = ["timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "tx_id",
          "input_addresses", "output_addresses", "input_amounts", "output_amounts",
          "fee", "script_type", "geo_country", "asn"]

#: Written only by a `--wallet-profiles` run; without it the files are exactly
#: what they always were.
CONSTRUCTION_FIELDS = ["tx_version", "locktime", "input_sequences", "input_outpoints"]

LIST_FIELDS = {"input_addresses", "output_addresses", "input_amounts", "output_amounts"}
_LISTS = LIST_FIELDS | {"input_sequences", "input_outpoints"}

JSON_TAIL = "\n]\n"
XML_TAIL = "</records>\n"


def columns(cfg: dict | None = None, fields: list[str] = FIELDS) -> list[str]:
    schema = (cfg or config.load())["schema"]
    return [schema.get(f, f) for f in fields]


class _Writer:
    ext = ""
    tail = ""

    def __init__(self, path: Path, cfg: dict, append: bool = False,
                 fields: list[str] = FIELDS):
        self.path, self.cfg, self.fields = path, cfg, fields
        self.cols = columns(cfg, fields)
        self.n = 0
        if append:
            _truncate_tail(path, self.tail)
            self.fh = path.open("a", encoding="utf-8", newline="")
        else:
            self.fh = path.open("w", encoding="utf-8", newline="")
            self.header()

    def header(self) -> None: ...

    def close(self) -> None:
        self.fh.write(self.tail)
        self.fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class CsvWriter(_Writer):
    ext = "csv"

    def header(self):
        self.w = csv.writer(self.fh)
        self.w.writerow(self.cols)

    def write(self, row: dict):
        if not hasattr(self, "w"):
            self.w = csv.writer(self.fh)
        sep = self.cfg["ingest"]["list_separator"]
        self.w.writerow([sep.join(str(v) for v in row[f]) if f in _LISTS else row[f]
                         for f in self.fields])
        self.n += 1


class JsonWriter(_Writer):
    ext = "json"
    tail = JSON_TAIL

    def header(self):
        self.fh.write("[\n")

    def write(self, row: dict):
        named = {c: row[f] for c, f in zip(self.cols, self.fields)}
        self.fh.write(("," if self._existing() else "") + json.dumps(named))
        self.n += 1

    def _existing(self) -> bool:
        return self.n > 0 or self.path.stat().st_size > len("[\n")


class XmlWriter(_Writer):
    ext = "xml"
    tail = XML_TAIL

    def header(self):
        self.fh.write('<?xml version="1.0" encoding="UTF-8"?>\n<records>\n')

    def write(self, row: dict):
        parts = []
        for col, f in zip(self.cols, self.fields):
            if f in _LISTS:
                items = "".join(f"<item>{escape(str(v))}</item>" for v in row[f])
                parts.append(f"<{col}>{items}</{col}>")
            else:
                parts.append(f"<{col}>{escape(str(row[f]))}</{col}>")
        self.fh.write(f"  <record id={quoteattr(str(row['tx_id']))}>" + "".join(parts) + "</record>\n")
        self.n += 1


WRITERS = {"csv": CsvWriter, "json": JsonWriter, "xml": XmlWriter}


def open_writers(out_dir: Path, formats, cfg: dict | None = None, append: bool = False,
                 construction: bool = False):
    cfg = cfg or config.load()
    out_dir.mkdir(parents=True, exist_ok=True)
    fields = FIELDS + CONSTRUCTION_FIELDS if construction else FIELDS
    return [WRITERS[f](out_dir / f"transactions.{f}", cfg, append=append, fields=fields)
            for f in formats]


def _truncate_tail(path: Path, tail: str) -> None:
    """Reopen a finished file for appending by dropping its closing token."""
    if not tail or not path.exists():
        return
    with path.open("r+b") as fh:
        fh.seek(0, 2)
        size = fh.tell()
        window = min(size, len(tail) + 8)
        fh.seek(size - window)
        blob = fh.read().decode("utf-8")
        cut = blob.rfind(tail.strip())
        if cut < 0:
            raise ValueError(f"{path} does not end with {tail.strip()!r} — refusing to append")
        fh.truncate(size - window + cut)
