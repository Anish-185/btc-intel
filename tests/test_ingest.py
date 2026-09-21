"""Parsers agree across formats, bad rows are quarantined with a reason,
GeoIP enrichment adds the columns the correlation engine needs."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pandas as pd
import pytest

import config
from ingest.geoip import COLUMNS as GEO_COLUMNS
from ingest.geoip import GeoIp, enrich, is_high_risk_asn
from ingest.parsers import parse
from ingest.pipeline import resolve_input, run
from ingest.schema import RawTransaction, validate

FIXTURES = Path(__file__).parent / "fixtures"
FORMATS = ["csv", "json", "xml"]
CFG = config.load()


def parsed(fmt: str):
    return [(n, validate(rec)) for n, rec in parse(FIXTURES / f"sample.{fmt}", fmt)]


def good_models(fmt: str) -> list[RawTransaction]:
    return [m for _, (m, _) in parsed(fmt) if m is not None]


# --- cross-format agreement ----------------------------------------------
def test_all_three_formats_normalise_to_the_same_records():
    dumps = {f: [m.model_dump() for m in good_models(f)] for f in FORMATS}
    assert len(dumps["csv"]) == 3
    assert dumps["csv"] == dumps["json"] == dumps["xml"]


def test_types_survive_normalisation():
    m = good_models("xml")[0]
    assert m.input_amounts == [0.5, 0.25] and m.output_amounts == [0.74]
    assert m.input_addresses == ["bc1qaaa", "bc1qbbb"]
    assert str(m.src_ip) == "117.200.5.10" and m.src_port == 41001
    assert m.timestamp.year == 2026 and m.fee == pytest.approx(0.001)


def test_field_names_come_from_config_not_from_code(tmp_path):
    """Rename every column the way a real NTRO dump might; only config changes."""
    renames = {"timestamp": "ts", "src_ip": "source_address", "txid": "tx_hash",
               "input_addresses": "vin_addr", "input_amounts": "vin_value"}
    rows = list(csv.DictReader((FIXTURES / "sample.csv").open()))
    renamed = tmp_path / "renamed.csv"
    with renamed.open("w", newline="") as fh:
        cols = [renames.get(c, c) for c in rows[0]]
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow({renames.get(k, k): v for k, v in r.items()})

    cfg = json.loads(json.dumps(CFG))
    cfg["schema"].update({"timestamp": "ts", "src_ip": "source_address", "tx_id": "tx_hash",
                          "input_addresses": "vin_addr", "input_amounts": "vin_value"})
    models = [m for _, rec in parse(renamed, "csv", cfg) for m, _ in [validate(rec)] if m]
    assert [m.model_dump() for m in models] == [m.model_dump() for m in good_models("csv")]


# --- quarantine -----------------------------------------------------------
@pytest.mark.parametrize("fmt,expected", [("csv", "bad IP"),
                                          ("json", "mismatched input array lengths"),
                                          ("xml", "negative amount")])
def test_malformed_row_is_quarantined_with_the_right_reason(fmt, expected):
    bad = [(n, reason) for n, (m, reason) in parsed(fmt) if m is None]
    assert len(bad) == 1
    assert expected in bad[0][1]


def test_pipeline_quarantines_instead_of_crashing_or_dropping(tmp_path):
    for fmt in FORMATS:
        out = tmp_path / fmt / "transactions.parquet"
        q = tmp_path / fmt / "quarantine.parquet"
        summary = run(FIXTURES / f"sample.{fmt}", out, q, fmt)
        assert summary["rows"] == 3 and summary["quarantined"] == 1
        qdf = pd.read_parquet(q)
        assert list(qdf.columns) == ["source_file", "row", "reason", "raw"]
        assert qdf.loc[0, "source_file"] == f"sample.{fmt}"
        assert qdf.loc[0, "reason"]                      # never blank
        json.loads(qdf.loc[0, "raw"])                    # the offending record is kept
        assert len(pd.read_parquet(out)) == 3


def test_every_quarantine_reason_type_is_recognised():
    base = {"timestamp": "2026-01-01T00:00:00Z", "src_ip": "1.2.3.4", "dst_ip": "5.6.7.8",
            "src_port": 1, "dst_port": 8333, "txid": "x", "input_addresses": ["a"],
            "output_addresses": ["b"], "input_amounts": [1.0], "output_amounts": [0.9],
            "fee": 0.1, "script_type": "p2wpkh"}
    cases = {
        "bad IP": {"src_ip": "999.1.2.3"},
        "mismatched output array lengths": {"output_amounts": [0.9, 0.1]},
        "negative amount": {"input_amounts": [-1.0]},
        "bad timestamp": {"timestamp": "not-a-date"},
        "port out of range": {"src_port": 99999},
        "not a number": {"fee": None},
        "transaction has no inputs": {"input_addresses": [], "input_amounts": []},
    }
    for expected, patch in cases.items():
        model, reason = validate({**base, **patch})
        assert model is None and expected in reason, (expected, reason)
    missing = {k: v for k, v in base.items() if k != "fee"}
    model, reason = validate(missing)
    assert model is None and "missing field" in reason


def test_empty_and_all_bad_input_still_writes_both_files(tmp_path):
    src = tmp_path / "empty.json"
    src.write_text("[]")
    summary = run(src, tmp_path / "t.parquet", tmp_path / "q.parquet", "json")
    assert summary["rows"] == 0 and summary["quarantined"] == 0
    assert list(pd.read_parquet(tmp_path / "t.parquet").columns)[:3] == ["timestamp", "src_ip", "dst_ip"]


# --- geoip ----------------------------------------------------------------
class StubReader:
    """Stands in for a maxminddb Reader (the real .mmdb files are not in git)."""

    def __init__(self, data):
        self.data = data

    def get(self, ip):
        return self.data.get(ip)


COUNTRY = StubReader({"117.200.5.10": {"country": {"iso_code": "IN"}},
                      "49.36.8.30": {"registered_country": {"iso_code": "IN"}},
                      "73.14.11.50": {"country": {"iso_code": "US"}}})
ASN = StubReader({"117.200.5.10": {"autonomous_system_number": 9829,
                                   "autonomous_system_organization": "BSNL"},
                  "49.36.8.30": {"autonomous_system_number": 55836,
                                 "autonomous_system_organization": "RJIL"},
                  "73.14.11.50": {"autonomous_system_number": 14061,
                                  "autonomous_system_organization": "DigitalOcean"}})


def stub_geo():
    return GeoIp(country_reader=COUNTRY, asn_reader=ASN)


def test_enrichment_adds_country_and_asn_columns():
    df = pd.DataFrame({"src_ip": ["117.200.5.10", "49.36.8.30", "73.14.11.50"]})
    out = enrich(df, stub_geo())
    assert all(c in out.columns for c in GEO_COLUMNS)
    assert list(out["geo_country"]) == ["IN", "IN", "US"]
    assert list(out["asn"]) == [9829, 55836, 14061]
    assert list(out["asn_org"]) == ["BSNL", "RJIL", "DigitalOcean"]
    assert list(out["high_risk_asn"]) == [False, False, True]   # DigitalOcean is hosting


def test_pipeline_enriches_every_row(tmp_path):
    summary = run(FIXTURES / "sample.csv", tmp_path / "t.parquet", tmp_path / "q.parquet",
                  "csv", geo=stub_geo())
    df = pd.read_parquet(tmp_path / "t.parquet")
    assert summary["enriched"] == 3
    assert list(df["geo_country"]) == ["IN", "IN", "US"]
    assert df["high_risk_asn"].sum() == 1


def test_missing_mmdb_degrades_to_nulls_without_crashing(tmp_path):
    cfg = json.loads(json.dumps(CFG))
    cfg["geoip"]["country_db"] = str(tmp_path / "nope.mmdb")
    cfg["geoip"]["asn_db"] = str(tmp_path / "also-nope.mmdb")
    geo = GeoIp(cfg)
    assert not geo.available
    df = enrich(pd.DataFrame({"src_ip": ["117.200.5.10"]}), geo)
    assert df["geo_country"].isna().all() and df["asn"].isna().all()
    assert not df["high_risk_asn"].any()


def test_unknown_ip_and_junk_input_are_survivable():
    geo = stub_geo()
    assert geo.lookup("8.8.8.8") == {"geo_country": None, "asn": None,
                                     "asn_org": None, "high_risk_asn": False}
    assert geo.lookup("not-an-ip")["asn"] is None


def test_is_high_risk_asn_reads_the_configured_list():
    for asn in config.get("geoip.high_risk_asns"):
        assert is_high_risk_asn(asn)
    assert not is_high_risk_asn(9829)          # BSNL, residential
    assert not is_high_risk_asn(None) and not is_high_risk_asn("junk")


# --- input resolution -----------------------------------------------------
def test_ground_truth_is_never_ingested(tmp_path):
    """The hidden labels sit in the same directory — they must not be read as data."""
    (tmp_path / "transactions.json").write_bytes((FIXTURES / "sample.json").read_bytes())
    (tmp_path / "ground_truth.json").write_text(json.dumps({"wallets": {"bc1qaaa": "C000001"}}))
    assert resolve_input(tmp_path, "json")[0].name == "transactions.json"
    summary = run(tmp_path, tmp_path / "t.parquet", tmp_path / "q.parquet", "json", geo=stub_geo())
    assert summary["rows"] == 3
    assert "C000001" not in pd.read_parquet(tmp_path / "t.parquet").to_csv()


def test_directory_input_picks_one_format(tmp_path):
    for fmt in FORMATS:
        (tmp_path / f"sample.{fmt}").write_bytes((FIXTURES / f"sample.{fmt}").read_bytes())
    assert resolve_input(tmp_path, "json")[1] == "json"
    assert resolve_input(tmp_path)[0].suffix == f".{CFG['ingest']['format']}"
    with pytest.raises(FileNotFoundError):
        resolve_input(tmp_path / "nothing-here", "csv")


def test_directory_with_two_files_of_one_format_is_an_error(tmp_path):
    for name in ("a.csv", "b.csv"):
        (tmp_path / name).write_bytes((FIXTURES / "sample.csv").read_bytes())
    with pytest.raises(ValueError, match="several"):
        resolve_input(tmp_path, "csv")


def test_generated_data_round_trips_through_ingest(tmp_path):
    """The generator's own output must ingest cleanly — no quarantine."""
    from generator.main import build_parser, generate
    args = build_parser().parse_args(["--n-actors", "60", "--n-transactions", "300",
                                      "--output", str(tmp_path / "raw"), "--seed", "3",
                                      "--formats", "csv,json,xml"])
    gen = generate(args)
    seen = {}
    for fmt in FORMATS:
        s = run(tmp_path / "raw", tmp_path / f"{fmt}.parquet", tmp_path / f"{fmt}.q.parquet",
                fmt, geo=stub_geo())
        assert s["quarantined"] == 0
        assert s["rows"] == gen["rows"] and s["transactions"] == gen["transactions"]
        seen[fmt] = pd.read_parquet(tmp_path / f"{fmt}.parquet")
    pd.testing.assert_frame_equal(seen["csv"], seen["json"])
    pd.testing.assert_frame_equal(seen["csv"], seen["xml"])
