"""Schema validity, typology rates, determinism, gossip, injection."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET

import pytest

import config
from generator.inject import inject_pattern
from generator.main import build_parser, generate
from generator.typologies import ADDRESS_FORMS as FORMS
from generator.writers import FIELDS, LIST_FIELDS, columns

CFG = config.load()
SEP = CFG["ingest"]["list_separator"]


def run(tmp_path, **kw):
    argv = ["--n-actors", str(kw.pop("n_actors", 200)),
            "--n-transactions", str(kw.pop("n_transactions", 1500)),
            "--output", str(tmp_path), "--seed", str(kw.pop("seed", 42)),
            "--formats", kw.pop("formats", "csv,json,xml")]
    for flag, val in kw.items():
        argv += [f"--{flag.replace('_', '-')}"] + ([] if val is True else [str(val)])
    return generate(build_parser().parse_args(argv)), tmp_path


def read_csv(d):
    import csv
    with (d / "transactions.csv").open() as fh:
        return list(csv.DictReader(fh))


def read_gt(d):
    return json.loads((d / "ground_truth.json").read_text())


# --- schema ---------------------------------------------------------------
def test_all_three_formats_hold_the_same_records(tmp_path):
    summary, d = run(tmp_path)
    rows = read_csv(d)
    js = json.loads((d / "transactions.json").read_text())
    xml = ET.parse(d / "transactions.xml").getroot()
    assert len(rows) == len(js) == len(xml) == summary["rows"]
    assert [r[columns()[5]] for r in rows] == [j[columns()[5]] for j in js]


def test_csv_header_matches_config_schema(tmp_path):
    _, d = run(tmp_path, formats="csv")
    with (d / "transactions.csv").open() as fh:
        assert fh.readline().strip().split(",") == columns()


def test_row_fields_are_well_formed(tmp_path):
    _, d = run(tmp_path, formats="csv,json")
    cols = dict(zip(FIELDS, columns()))
    for r in read_csv(d)[:500]:
        assert r[cols["timestamp"]].endswith("Z")
        assert r[cols["src_ip"]].count(".") == 3 and r[cols["dst_ip"]].count(".") == 3
        assert 1 <= int(r[cols["src_port"]]) <= 65535
        assert int(r[cols["dst_port"]]) == CFG["gossip"]["p2p_port"]
        assert len(r[cols["tx_id"]]) == 64
        assert float(r[cols["fee"]]) > 0
        assert r[cols["script_type"]] in CFG["generator"]["script_types"]
        assert len(r[cols["geo_country"]]) == 2 and int(r[cols["asn"]]) > 0
        ins = r[cols["input_addresses"]].split(SEP)
        assert len(ins) == len(r[cols["input_amounts"]].split(SEP))
        assert all(any(a.startswith(p) for p, _ in FORMS.values()) for a in ins)
    for j in json.loads((d / "transactions.json").read_text())[:200]:
        for f in LIST_FIELDS:
            assert isinstance(j[cols[f]], list) and j[cols[f]]


def test_ground_truth_is_not_in_the_public_output(tmp_path):
    _, d = run(tmp_path, formats="csv")
    public = (d / "transactions.csv").read_text()
    gt = read_gt(d)
    assert "ground_truth" not in public
    # no cluster label, pattern name or origin-truth flag leaks into the dataset
    for leak in ["cluster_id", "pattern", "ransomware", "coinjoin", "layering", "true_origin"]:
        assert leak not in public
    assert set(gt) >= {"wallets", "clusters", "transactions", "ips"}


# --- typologies -----------------------------------------------------------
def test_all_typologies_appear_at_roughly_their_configured_rate(tmp_path):
    summary, d = run(tmp_path, n_transactions=4000)
    total = summary["transactions"]
    mix = CFG["generator"]["pattern_mix"]
    share = sum(mix.values())
    for name, weight in mix.items():
        got = summary["per_typology"][name] / total
        assert got == pytest.approx(weight / share, abs=0.03), f"{name}: {got:.3f}"
    assert summary["per_typology"]["normal"] / total > 0.5  # noise class is the majority


def test_each_typology_leaves_its_signature_in_ground_truth(tmp_path):
    _, d = run(tmp_path, n_transactions=4000)
    gt = read_gt(d)
    patterns = {c["pattern_type"] for c in gt["clusters"].values()}
    assert {"normal", "exchange", "ransomware_collector", "ransomware_victim",
            "cashout", "layering", "same_actor_cluster"} <= patterns
    tx_patterns = {t["pattern"] for t in gt["transactions"].values()}
    assert {"normal", "ransomware_victim_payment", "ransomware_peel", "layering_split",
            "layering_merge", "same_actor_cluster", "coinjoin"} <= tx_patterns


def test_coinjoin_inputs_come_from_unrelated_clusters(tmp_path):
    """The trap for common-input-ownership clustering must actually be set."""
    _, d = run(tmp_path, formats="csv", n_transactions=3000)
    gt = read_gt(d)
    cj = {tid for tid, t in gt["transactions"].items() if t["typology"] == "coinjoin"}
    cols = dict(zip(FIELDS, columns()))
    checked = 0
    for r in read_csv(d):
        if r[cols["tx_id"]] not in cj:
            continue
        amounts = {float(v) for v in r[cols["input_amounts"]].split(SEP)}
        owners = {gt["wallets"][a] for a in r[cols["input_addresses"]].split(SEP)}
        assert len(amounts) == 1                       # equal-value inputs
        assert len(owners) > 1                         # genuinely unrelated wallets
        checked += 1
    assert checked


def test_same_actor_cluster_shares_one_ip_and_nat_actors_do_not_share_a_cluster(tmp_path):
    _, d = run(tmp_path, formats="csv", n_transactions=3000)
    gt = read_gt(d)
    same = [c for c in gt["clusters"].values() if c["pattern_type"] == "same_actor_cluster"]
    assert same and all(len(c["wallets"]) >= 3 for c in same)
    # innocent NAT/VPN: several distinct clusters broadcasting from one IP
    by_ip: dict[str, set] = {}
    for cid, c in gt["clusters"].items():
        if c["shared_ip"]:
            by_ip.setdefault(c["true_broadcast_ip"], set()).add(cid)
    assert any(len(v) > 1 for v in by_ip.values()), "no innocent shared-IP noise generated"


# --- gossip ---------------------------------------------------------------
def test_multi_hop_relay_records_repeat_a_txid(tmp_path):
    _, d = run(tmp_path, formats="csv", relay_observation_rate=0.6)
    cols = dict(zip(FIELDS, columns()))
    counts: dict[str, int] = {}
    for r in read_csv(d):
        counts[r[cols["tx_id"]]] = counts.get(r[cols["tx_id"]], 0) + 1
    assert max(counts.values()) > 1
    assert sum(counts.values()) / len(counts) > 1.5


def test_single_row_mode_emits_one_row_per_txid_from_the_observed_origin(tmp_path):
    summary, d = run(tmp_path, formats="csv", single_row=True)
    gt = read_gt(d)
    cols = dict(zip(FIELDS, columns()))
    rows = read_csv(d)
    assert len(rows) == summary["transactions"] == len(gt["transactions"])
    assert len({r[cols["tx_id"]] for r in rows}) == len(rows)
    for r in rows:
        assert r[cols["src_ip"]] == gt["transactions"][r[cols["tx_id"]]]["observed_origin_ip"]


def test_observation_rate_controls_volume(tmp_path):
    low, _ = run(tmp_path / "lo", formats="csv", relay_observation_rate=0.1)
    high, _ = run(tmp_path / "hi", formats="csv", relay_observation_rate=0.9)
    assert high["rows"] > low["rows"] * 2


def test_masked_broadcasts_use_tor_or_hosting_ips(tmp_path):
    _, d = run(tmp_path, formats="csv", n_transactions=3000)
    gt = read_gt(d)
    tor, hosting = set(gt["ips"]["tor_exit"]), set(gt["ips"]["hosting"])
    kinds = {"tor": 0, "hosting": 0, "home": 0}
    for t in gt["transactions"].values():
        kinds[t["broadcast"]] += 1
        if t["broadcast"] == "tor":
            assert t["observed_origin_ip"] in tor
            assert t["observed_origin_ip"] != t["true_origin_ip"]
        elif t["broadcast"] == "hosting":
            assert t["observed_origin_ip"] in hosting
        else:
            assert t["observed_origin_ip"] == t["true_origin_ip"]
    assert all(v > 0 for v in kinds.values())
    assert gt["ips"]["relay"] and len(gt["ips"]["relay"]) == CFG["gossip"]["n_relays"]


# --- determinism ----------------------------------------------------------
def test_same_seed_gives_identical_output(tmp_path):
    a, da = run(tmp_path / "a", seed=7)
    b, db = run(tmp_path / "b", seed=7)
    assert a == {**b, "output": a["output"]}
    for name in ("transactions.csv", "transactions.json", "transactions.xml"):
        assert (da / name).read_bytes() == (db / name).read_bytes()
    ga, gb = read_gt(da), read_gt(db)
    for key in ("wallets", "clusters", "transactions", "ips"):
        assert ga[key] == gb[key]


def test_different_seed_gives_different_output(tmp_path):
    _, da = run(tmp_path / "a", seed=7, formats="csv")
    _, db = run(tmp_path / "b", seed=8, formats="csv")
    assert (da / "transactions.csv").read_bytes() != (db / "transactions.csv").read_bytes()


# --- injection ------------------------------------------------------------
@pytest.mark.parametrize("typology", ["ransomware_collector", "layering",
                                      "same_actor_cluster", "coinjoin", "normal"])
def test_inject_appends_one_instance_and_updates_ground_truth(tmp_path, typology):
    _, d = run(tmp_path, n_transactions=800)
    before_rows = len(read_csv(d))
    before = read_gt(d)
    res = inject_pattern(d, typology, {"n_counterparties": 10}, seed=99)

    after = read_gt(d)
    assert len(read_csv(d)) == before_rows + res["rows"]
    assert len(json.loads((d / "transactions.json").read_text())) == before_rows + res["rows"]
    assert len(ET.parse(d / "transactions.xml").getroot()) == before_rows + res["rows"]
    assert len(after["transactions"]) == len(before["transactions"]) + res["transactions"]
    assert set(after["clusters"]) > set(before["clusters"])          # fresh clusters only
    assert not set(res["clusters"]) & set(before["clusters"])
    assert all(after["transactions"][t]["injected"] for t in res["txids"])
    assert after["injections"][-1]["typology"] == typology
    # fresh wallets, and they are new
    assert not {w for c in res["clusters"] for w in after["clusters"][c]["wallets"]} & set(before["wallets"])


def test_inject_is_deterministic_and_respects_param_overrides(tmp_path):
    _, da = run(tmp_path / "a", n_transactions=800)
    _, db = run(tmp_path / "b", n_transactions=800)
    ra = inject_pattern(da, "ransomware_collector", {"victims": [6, 6], "peel_hops": [3, 3]}, seed=5)
    rb = inject_pattern(db, "ransomware_collector", {"victims": [6, 6], "peel_hops": [3, 3]}, seed=5)
    assert ra == rb
    assert ra["transactions"] == 6 + 3  # victims + peel hops, exactly as overridden



@pytest.mark.parametrize("profiled", [False, True])
def test_two_regenerations_write_byte_identical_injection_rows(tmp_path, profiled):
    """Dataset plus injection, rebuilt twice: every relay row, in every format,
    is the same bytes. Relay timing comes from the injection's own seeded stream."""
    extra = {"wallet_profiles": True} if profiled else {}
    files = []
    for name in ("a", "b"):
        _, d = run(tmp_path / name, n_transactions=600, **extra)
        before = {f: (d / f"transactions.{f}").stat().st_size for f in ("csv", "json", "xml")}
        inject_pattern(d, "ransomware_collector", {"n_counterparties": 10}, seed=321)
        files.append({f: (d / f"transactions.{f}").read_bytes() for f in before})
        assert all((d / f"transactions.{f}").stat().st_size > n for f, n in before.items())
    assert files[0] == files[1]
    injection = read_gt(tmp_path / "a")["injections"][-1]
    assert {"broadcast", "relay_observation_rate"} <= set(injection)

def test_inject_rejects_unknown_typology(tmp_path):
    _, d = run(tmp_path, formats="csv", n_transactions=400)
    with pytest.raises(KeyError):
        inject_pattern(d, "not_a_typology", seed=1)
