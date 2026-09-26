"""Wallet-construction fingerprints: the generator's profiles, every tell, the
classifier's unknown rules, clustering corroboration, and the API surfaces."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pandas as pd
import pytest

import config
from features import fingerprint as F
from generator import wallets
from graph.builder import Tx
from graph.clustering import cluster_wallets

CFG = config.load()

# --- 1. profiles off: byte-identical ------------------------------------------------
#: sha256[:16] of each output, computed from the committed code (HEAD, before
#: profiles existed) in a separate worktree and again after — identical. The
#: relay events are hashed on HEAD's fields: `services` joined them later, as a
#: null column, in the peer-profile phase.
PINS = {
    "corpus-base/0": "1cc0b886de984b88", "corpus-base/37": "bd1ca8fb8bc15285",
    "corpus-base/211": "e7065051e093e07b", "corpus-base/540": "b3bb4aa5db6b9b1b",
    "corpus-validity/0": "591281d4575b511f", "corpus-validity/37": "77d9c7753110bc35",
    "corpus-validity/211": "41896f4b27442bc0", "corpus-validity/540": "48c885ac90af07d7",
    "gen/ground_truth.json": "6875efe749a8c866", "gen/node_intel.json": "e3d7d8852d2c6bb2",
    "gen/synthetic_watchlist.json": "3d5f246afd2f8f11",
    "gen/transactions.csv": "e0b4018ff43e6d55", "gen/transactions.json": "e3a9661cd822a915",
    "gen/transactions.xml": "71b01c64ba85fd30",
    "gen-shifted/ground_truth.json": "d06b34ca849de3e4",
    "gen-shifted/node_intel.json": "e3d7d8852d2c6bb2",
    "gen-shifted/synthetic_watchlist.json": "28f1b6eb90e35e04",
    "gen-shifted/transactions.csv": "8d8bca4b7fce6dc6",
    "gen-shifted/transactions.json": "bf604f711a46789d",
    "gen-shifted/transactions.xml": "bc86a930ba40f3fd",
}
HEAD_EVENT_FIELDS = ["txid", "peer_ip", "peer_port", "peer_id", "user_agent", "wall_clock_ts",
                     "monotonic_or_derived_ts", "message_type", "direction", "capture_source",
                     "transport", "unreadable_flows"]


def _h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


@pytest.mark.parametrize("shifted", [False, True])
def test_generator_output_is_byte_identical_with_profiles_off(tmp_path, shifted):
    from generator.main import build_parser, generate
    argv = ["--n-actors", "60", "--n-transactions", "300", "--output", str(tmp_path),
            "--seed", "7", "--formats", "csv,json,xml"] + (["--shifted"] if shifted else [])
    generate(build_parser().parse_args(argv), CFG)
    for f in sorted(tmp_path.iterdir()):
        data = f.read_bytes()
        if f.name == "ground_truth.json":           # the one wall-clock field
            gt = json.loads(data)
            gt.pop("generated_at")
            data = json.dumps(gt, sort_keys=True).encode()
        assert _h(data) == PINS[f"gen{'-shifted' if shifted else ''}/{f.name}"], f.name


@pytest.mark.parametrize("manifest", ["base", "validity"])
def test_corpus_captures_are_byte_identical_with_profiles_off(manifest):
    from origination import corpus
    path = corpus.MANIFEST if manifest == "base" else corpus.VALIDITY_MANIFEST
    specs = corpus.expand(corpus.load_manifest(path))
    for i in (0, 37, 211, 540):
        assert "fingerprint" not in specs[i]
        events, truth, observers, _ = corpus.simulate(specs[i], CFG)
        ev = [{k: getattr(e, k) for k in HEAD_EVENT_FIELDS} for e in events]
        got = _h(json.dumps([ev, truth, observers], sort_keys=True, default=str).encode())
        assert got == PINS[f"corpus-{manifest}/{i}"], i


def test_the_cached_corpora_keep_their_identity():
    """The profile config enters a corpus digest only for a fingerprint manifest,
    so the base and validity corpora are not rebuilt because it was added."""
    from origination import corpus
    base = corpus.load_manifest(corpus.MANIFEST)
    changed = json.loads(json.dumps(CFG))
    changed["generator"]["wallet_profiles"]["start_height"] += 1
    assert corpus.digest(base, CFG) == corpus.digest(base, changed)
    fp = corpus.load_manifest(corpus.FINGERPRINT_MANIFEST)
    assert corpus.digest(fp, CFG) != corpus.digest(fp, changed)


# --- 1. profiles on ------------------------------------------------------------------
@pytest.fixture(scope="module")
def profiled_truth():
    from origination import corpus
    specs = corpus.expand(corpus.load_manifest(corpus.FINGERPRINT_MANIFEST))
    rows = []
    for spec in [s for s in specs if s["coinjoin"]][:8] + specs[1::97][:6]:
        _, truth, _, _ = corpus.simulate(spec, CFG)
        rows += [{"txid": t, **r} for t, r in truth.items()]
    return rows


def test_the_corpus_emits_every_profile_with_its_tells(profiled_truth):
    by = {}
    for r in profiled_truth:
        by.setdefault(r["wallet_profile"], []).append(r)
    assert set(by) == set(wallets.PROFILES)
    for r in by["legacy_naive"]:
        assert r["locktime"] == 0 and set(r["sequences"]) == {wallets.FINAL}
    for r in by["core_like"]:
        assert r["tx_version"] == 2
        assert r["locktime"] == 0 or r["locktime"] >= CFG["generator"]["wallet_profiles"][
            "start_height"] - 100
    for r in by["coordinator_coinjoin"]:
        assert r["shape"] == "coinjoin" and r["locktime"] == 0
    for r in by["batch_withdrawal"]:
        assert r["shape"] == "batch" and len(r["change_indices"]) == 1
    for r in profiled_truth:                        # values stay a transaction
        assert r["fee"] >= 0 and all(v > 0 for v in r["out_vals"])
        assert abs(sum(r["in_vals"]) - sum(r["out_vals"]) - r["fee"]) < 1e-7


def test_a_profiled_generator_run_records_the_profile_and_ingests(tmp_path):
    from generator.main import build_parser, generate
    from graph.builder import iter_transactions, load
    from ingest.pipeline import run as ingest_run
    generate(build_parser().parse_args([
        "--n-actors", "60", "--n-transactions", "300", "--output", str(tmp_path),
        "--seed", "7", "--formats", "csv,json,xml", "--wallet-profiles"]), CFG)
    gt = json.loads((tmp_path / "ground_truth.json").read_text())["transactions"]
    assert {t["wallet_profile"] for t in gt.values()} <= set(wallets.PROFILES)
    for fmt in ("csv", "json", "xml"):
        summary = ingest_run(tmp_path / f"transactions.{fmt}", tmp_path / f"{fmt}.parquet",
                             tmp_path / f"q{fmt}.parquet", fmt, record_custody=False)
        assert summary["quarantined"] == 0
    txs = list(iter_transactions(load(tmp_path / "csv.parquet")))
    assert all(tx.version in (1, 2) and tx.locktime is not None
               and len(tx.sequences) == len(tx.inputs) for tx in txs)


def test_an_ingest_without_construction_fields_has_exactly_the_old_columns(tmp_path):
    from generator.main import build_parser, generate
    from graph.builder import load
    from ingest.pipeline import run as ingest_run
    generate(build_parser().parse_args([
        "--n-actors", "30", "--n-transactions", "80", "--output", str(tmp_path),
        "--seed", "3", "--formats", "csv"]), CFG)
    ingest_run(tmp_path / "transactions.csv", tmp_path / "t.parquet", tmp_path / "q.parquet",
               "csv", record_custody=False)
    assert not {"tx_version", "locktime", "input_sequences", "input_outpoints"} & set(
        load(tmp_path / "t.parquet").columns)



@pytest.fixture(scope="module")
def typology_pair(tmp_path_factory):
    """One seed generated twice, profiles off and on, ingested."""
    from generator.main import build_parser, generate
    from ingest.pipeline import run as ingest_run
    out = {}
    for name, extra in (("plain", []), ("profiled", ["--wallet-profiles"])):
        d = tmp_path_factory.mktemp(name)
        generate(build_parser().parse_args([
            "--n-actors", "120", "--n-transactions", "900", "--output", str(d),
            "--seed", "6", "--formats", "csv", *extra]), CFG)
        ingest_run(d / "transactions.csv", d / "t.parquet", d / "q.parquet", "csv",
                   record_custody=False)
        out[name] = d
    return out


def test_peel_chain_detection_is_the_same_with_profiles_on(typology_pair):
    """Profiles on a peel chain move no amount and no chained address, so the
    detector walks the same hops to the same alerts. Ordinary payments do get
    fee and change tells, so a run of them that only happened to look
    peel-shaped may not survive; those chains are not the typology's."""
    from engines.rules.detectors import FeatureSet, detect_peel_chain
    from graph.builder import build_graph, load
    gt = json.loads((typology_pair["plain"] / "ground_truth.json").read_text())["transactions"]

    def peels(d):
        g = build_graph(load(d / "t.parquet"), CFG)
        return sorted((tuple(a.evidence), a.score, a.reason)
                      for a in detect_peel_chain(FeatureSet.from_graph(g, CFG), g, CFG)
                      if any(gt[t]["pattern"] != "normal" for t in a.evidence))

    plain, profiled = peels(typology_pair["plain"]), peels(typology_pair["profiled"])
    assert plain, "the dataset has no peel chain to compare"
    assert profiled == plain


def test_typology_transactions_record_which_tells_they_got(typology_pair):
    from generator.main import NEUTRAL_TELLS
    gt = json.loads((typology_pair["profiled"] / "ground_truth.json").read_text())["transactions"]
    plain = json.loads((typology_pair["plain"] / "ground_truth.json").read_text())["transactions"]
    rows = {r["txid"]: r for r in pd.read_parquet(typology_pair["plain"] / "t.parquet")
            .drop_duplicates("txid").to_dict("records")}
    got = {r["txid"]: r for r in pd.read_parquet(typology_pair["profiled"] / "t.parquet")
           .drop_duplicates("txid").to_dict("records")}
    typology = [t for t, m in gt.items() if m["pattern"] != "normal"]
    assert typology and set(gt) == set(plain)
    for txid in typology:
        tells = gt[txid]["wallet_tells"]
        assert set(NEUTRAL_TELLS) <= set(tells["applied"])
        assert {"fee", "change_type"} <= set(tells["skipped"])
        a, b = rows[txid], got[txid]
        assert a["fee"] == b["fee"]
        assert sorted(zip(a["output_addresses"], a["output_amounts"])) == sorted(
            zip(b["output_addresses"], b["output_amounts"]))
        assert sorted(a["input_amounts"]) == sorted(b["input_amounts"])
        if "script_type" not in tells["applied"]:
            assert sorted(a["input_addresses"]) == sorted(b["input_addresses"])
    assert any("script_type" in gt[t]["wallet_tells"]["applied"] for t in typology)
    normal = [m["wallet_tells"] for m in gt.values() if m["pattern"] == "normal"]
    assert normal and all("fee" in t["applied"] for t in normal)


def test_an_injection_into_a_profiled_dataset_is_profiled_and_ingests(typology_pair, tmp_path):
    import shutil

    from generator.inject import inject_pattern
    from ingest.pipeline import run as ingest_run
    d = tmp_path / "d"
    shutil.copytree(typology_pair["profiled"], d)
    res = inject_pattern(d, "ransomware_collector", {"n_counterparties": 10}, seed=99)
    gt = json.loads((d / "ground_truth.json").read_text())["transactions"]
    assert all("fee" in gt[t]["wallet_tells"]["skipped"] for t in res["txids"])
    summary = ingest_run(d / "transactions.csv", d / "t.parquet", d / "q.parquet", "csv",
                         record_custody=False)
    assert summary["quarantined"] == 0
    assert set(res["txids"]) <= set(pd.read_parquet(d / "t.parquet")["txid"])

# --- 2. every tell can fire and can fail ------------------------------------------------
P2WPKH = [f"bc1q{i:038x}" for i in range(1, 9)]
P2PKH = [f"1{i:033x}" for i in range(1, 9)]
P2TR = [f"bc1p{i:058x}" for i in range(1, 9)]


def view(**kw) -> F.View:
    base = {"in_addrs": P2WPKH[:1], "in_vals": [1.0], "out_addrs": [P2PKH[0], P2WPKH[1]],
            "out_vals": [0.3, 0.6999]}
    return F.View(**{**base, **kw})


TELL_CASES = [
    ("version", view(version=2), "v2", view(version=1), "v1"),
    ("version", view(version=3), "other", view(), None),
    ("locktime", view(locktime=850_000), "height", view(locktime=0), "zero"),
    ("locktime", view(locktime=1_790_000_000), "time", view(), None),
    ("sequence", view(sequences=[F.RBF_MAX]), "rbf", view(sequences=[F.FINAL]), "final"),
    ("sequence", view(sequences=[F.LOCKTIME_ONLY]), "locktime_only",
     view(in_addrs=P2WPKH[:2], in_vals=[1, 1], sequences=[F.FINAL, F.RBF_MAX]), "mixed"),
    ("ordering", view(out_vals=[0.3, 0.6999]), "bip69", view(out_vals=[0.6999, 0.3]), "not_bip69"),
    ("ordering", view(in_addrs=P2WPKH[:2], in_vals=[1, 1], out_vals=[0.5, 0.5],
                      outpoints=[f"{'00' * 32}:1", f"{'00' * 32}:0"]), "not_bip69",
     view(out_addrs=[P2PKH[0]], out_vals=[0.9]), None),
    ("change_position", view(out_addrs=[P2PKH[0], P2WPKH[0]]), "last",
     view(out_addrs=[P2WPKH[0], P2PKH[0]], out_vals=[0.6999, 0.3]), "first"),
    ("change_position", view(out_addrs=[P2PKH[0], P2PKH[1], P2WPKH[0]], out_vals=[.1, .2, .6]),
     "last", view(out_addrs=[P2WPKH[2], P2WPKH[3]]), None),        # both outputs match
    ("fee", view(fee=0.0001), "round_btc", view(fee=0.00001234), "fractional_rate"),
    ("fee", view(fee=11 * F.estimated_vsize(["p2wpkh"], ["p2pkh", "p2wpkh"]) / F.SATS),
     "integer_rate",
     view(fee=15 * F.estimated_vsize(["p2wpkh"], ["p2pkh", "p2wpkh"]) / F.SATS), "round_rate"),
    ("script_mix", view(in_addrs=P2PKH[:2], in_vals=[1, 1]), "p2pkh",
     view(in_addrs=[P2PKH[0], P2TR[0]], in_vals=[1, 1]), "mixed"),
    ("change_type", view(out_addrs=[P2PKH[0], P2WPKH[0]]), "reuse_input",
     view(out_addrs=[P2PKH[0], P2WPKH[1]]), "same_type"),
    ("change_type", view(out_addrs=P2PKH[:3] + [P2TR[0]], out_vals=[.2, .2, .2, .3]),
     "other_type", view(out_addrs=[P2PKH[0]], out_vals=[.9]), None),
    ("io_shape", view(), "1x2",
     view(in_addrs=P2WPKH[:5], in_vals=[1] * 5, out_addrs=P2PKH[:7], out_vals=[.1] * 7), "4+x6+"),
    ("batching", view(out_addrs=P2PKH[:4], out_vals=[.2, .2, .2, .3]), "equal_group",
     view(out_addrs=P2PKH[:5], out_vals=[.1, .2, .3, .4, .5]), "many_outputs"),
    ("batching", view(), "simple",
     view(out_addrs=P2PKH[:3], out_vals=[.2, .2, .2]), "equal_group"),
]


@pytest.mark.parametrize("tell, fires, expected, fails, otherwise", TELL_CASES,
                         ids=[f"{c[0]}-{c[2]}-{c[4]}" for c in TELL_CASES])
def test_each_tell_fires_and_fails(tell, fires, expected, fails, otherwise):
    assert F.tells(fires)[tell] == expected
    assert F.tells(fails)[tell] == otherwise


def test_every_tell_is_covered_both_ways():
    fired = {c[0] for c in TELL_CASES}
    assert fired == set(F.TELLS)


# --- 3. the classifier ------------------------------------------------------------------
@pytest.fixture(scope="module")
def model(profiled_truth):
    rows = [F.tells(F.View.of_record(r)) for r in profiled_truth]
    labels = [r["wallet_profile"] for r in profiled_truth]
    return F.FingerprintModel.fit(rows[::2], labels[::2]).calibrate(rows[1::2], labels[1::2])


def test_the_answer_is_ranked_calibrated_or_unknown(model, profiled_truth):
    answer = model.classify(F.tells(F.View.of_record(profiled_truth[0])), CFG)
    confidences = [r["confidence"] for r in answer["ranked"]]
    assert confidences == sorted(confidences, reverse=True)
    assert {r["label"] for r in answer["ranked"]} == set(F.LABELS)
    assert answer["label"] in {*F.LABELS, F.UNKNOWN}



def test_leave_one_profile_out_never_names_the_held_out_profile(profiled_truth):
    truth = pd.DataFrame(profiled_truth)
    truth["_tells"] = [F.tells(F.View.of_record(r)) for r in profiled_truth]
    truth["role"] = [("train", "calibration", "cross_test")[i % 3] for i in range(len(truth))]
    table = F.leave_one_profile_out(truth, CFG)
    per = table[table["held-out profile"] != "all (pooled)"]
    assert set(per["held-out profile"]) == set(F.LABELS)
    assert (per["most often named"] != per["held-out profile"]).all()
    assert (per["unknown"] + per["confidently mislabelled"] == per["transactions"]).all()
    pooled = table[table["held-out profile"] == "all (pooled)"].set_index("condition")
    assert pooled.loc["full", "transactions"] == (truth["role"] == "cross_test").sum()

def test_too_few_tells_is_unknown_whatever_the_score(model):
    sparse = dict.fromkeys(F.TELLS)
    sparse.update(io_shape="4+x6+", batching="equal_group", script_mix="p2wpkh")
    answer = model.classify(sparse, CFG)
    assert answer["label"] == F.UNKNOWN and "tells observable" in answer["unknown_reason"]


def test_a_weak_top_label_is_unknown(model):
    strict = {**CFG, "features": {**CFG["features"], "fingerprint": {
        **CFG["features"]["fingerprint"], "unknown_below": 1.01}}}
    t = F.tells(view(version=2, locktime=850_000, sequences=[F.RBF_MAX]))
    answer = model.classify(t, strict)
    assert answer["label"] == F.UNKNOWN and "under" in answer["unknown_reason"]


def test_no_fitted_model_means_unknown_and_says_why():
    answer = F.fingerprint(view(), None, CFG)
    assert answer["label"] == F.UNKNOWN and "fit" in answer["unknown_reason"]


def test_a_structural_answer_uses_its_own_calibration(model):
    t = F.tells(view(version=2, locktime=850_000, sequences=[F.RBF_MAX], fee=0.00001234))
    assert model.classify(t, CFG)["condition"] == F.FULL
    assert model.classify(F.structural(t), CFG)["condition"] == F.STRUCTURAL
    assert set(model.iso) == {F.FULL, F.STRUCTURAL}


def test_labels_name_software_families_and_patterns_never_parties():
    for label, text in F.LABELS.items():
        assert text.endswith("construction")
        for word in ("owner", "person", "user", "operator", "exchange", "company"):
            assert word not in text.lower(), (label, word)


def test_the_model_round_trips_through_json(model, tmp_path):
    again = F.FingerprintModel.load(model.save(tmp_path / "m.json"))
    t = F.tells(view(version=2, locktime=850_000, sequences=[F.RBF_MAX]))
    assert again.classify(t, CFG) == model.classify(t, CFG)


# --- 4. corroboration only ---------------------------------------------------------------
def _tx(txid, ins, outs):
    return Tx(txid, [(a, 1.0) for a in ins], [(a, 0.5) for a in outs])


def test_a_fingerprint_match_never_creates_a_merge():
    """Two wallets never spent together, both spent by identically fingerprinted
    transactions, stay two clusters — and the whole clustering is what it is
    without fingerprints."""
    txs = [_tx("t1", [P2WPKH[0]], [P2PKH[0]]), _tx("t2", [P2WPKH[1]], [P2PKH[1]])]
    same = {"t1": "core_like", "t2": "core_like"}
    with_fp = cluster_wallets(txs, CFG, fingerprints=same)
    assert not with_fp.same_cluster(P2WPKH[0], P2WPKH[1])
    assert with_fp.clusters == cluster_wallets(txs, CFG).clusters
    assert with_fp.confidence == {}


def test_a_fingerprint_mismatch_lowers_a_merge_but_keeps_it():
    txs = [_tx("t1", [P2WPKH[0]], [P2PKH[0]]), _tx("t2", [P2WPKH[1]], [P2PKH[1]]),
           _tx("t3", [P2WPKH[0], P2WPKH[1]], [P2PKH[2]])]
    plain = cluster_wallets(txs, CFG)
    mixed = cluster_wallets(txs, CFG, fingerprints={"t1": "core_like", "t2": "legacy_naive"})
    assert mixed.clusters == plain.clusters and mixed.same_cluster(P2WPKH[0], P2WPKH[1])
    cluster = mixed.cluster_of(P2WPKH[0])
    assert mixed.confidence[cluster] == CFG["graph"]["fingerprint"]["mismatch_factor"]
    assert mixed.conflicts[cluster][0]["txid"] == "t3"
    agreeing = cluster_wallets(txs, CFG, fingerprints={"t1": "core_like", "t2": "core_like",
                                                       "t3": "core_like"})
    assert agreeing.confidence[agreeing.cluster_of(P2WPKH[0])] == 1.0


def test_fingerprints_never_change_a_real_clustering(model):
    """On a generated dataset, any fingerprint assignment — the model's, or an
    adversarial one — leaves every union exactly as it was."""
    import tempfile

    import pandas as pd

    from generator.main import build_parser, generate
    from graph.builder import iter_transactions
    from ingest.pipeline import run as ingest_run
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        generate(build_parser().parse_args(["--n-actors", "80", "--n-transactions", "400",
                                            "--output", str(d), "--seed", "11",
                                            "--formats", "csv"]), CFG)
        ingest_run(d / "transactions.csv", d / "t.parquet", d / "q.parquet", "csv",
                   record_custody=False)
        txs = list(iter_transactions(pd.read_parquet(d / "t.parquet")))
    plain = cluster_wallets(txs, CFG).clusters
    labels = list(F.LABELS)
    adversarial = {tx.txid: labels[i % len(labels)] for i, tx in enumerate(txs)}
    for fps in (F.confident_labels(txs, CFG, model), adversarial):
        assert cluster_wallets(txs, CFG, fingerprints=fps).clusters == plain


# --- 5. evaluation ------------------------------------------------------------------------
def test_evaluation_tables_are_consistent(model, profiled_truth):
    import pandas as pd
    truth = pd.DataFrame(profiled_truth)
    truth["_tells"] = [F.tells(F.View.of_record(r)) for r in profiled_truth]
    truth["capture_id"] = "c"
    truth["role"] = ["within_test" if i % 2 else "cross_test" for i in range(len(truth))]
    out = F.evaluate({"model": model, "truth": truth, "corpus": "test"}, CFG)
    for row in out["agreement"].itertuples():
        assert (row._4 + row._5 + row._6 + row.neither) == row.transactions
    for label, matrix in out["confusion"].items():
        n = next(r.transactions for r in out["unknown"].itertuples() if r._2 == label)
        assert int(matrix.to_numpy().sum()) == n
    assert set(out["unknown"]["condition"]) == {"simulated"}


# --- 4. surfaces ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def client(tmp_path_factory, model):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    import api.app as app_module
    from fusion.pipeline import run as fusion_run
    from generator.main import build_parser, generate
    from ingest.pipeline import run as ingest_run
    d = tmp_path_factory.mktemp("fpapi")
    raw = d / "raw"
    generate(build_parser().parse_args(["--n-actors", "80", "--n-transactions", "400",
                                        "--output", str(raw), "--seed", "5",
                                        "--formats", "csv", "--wallet-profiles"]), CFG)
    ingest_run(raw, d / "t.parquet", d / "q.parquet", "csv")
    fusion_run(d / "t.parquet", raw / "ground_truth.json", d / "final.parquet",
               d / "final.json", CFG)
    model.save(d / "fp.json")
    patched = pytest.MonkeyPatch()
    patched.setattr(F, "load_model", lambda cfg=None: model)
    app_module.configure(d / "t.parquet", raw, d / "final.json", d / "feedback.parquet")
    yield TestClient(app_module.app), d
    app_module.configure()
    patched.undo()


def test_the_txid_page_serves_the_fingerprint(client):
    c, d = client
    import pandas as pd
    txid = pd.read_parquet(d / "t.parquet")["txid"].iloc[0]
    body = c.get(f"/transactions/{txid}/fingerprint").json()
    assert body["label"] in {*F.LABELS, F.UNKNOWN} and body["ranked"]
    assert "version" in body["observed_tells"]
    assert c.get("/transactions/nope/fingerprint").status_code == 404


def test_the_entity_page_serves_the_distribution_and_merge_confidence(client):
    c, d = client
    import pandas as pd

    import api.app as app_module
    wallet = pd.read_parquet(d / "t.parquet")["input_addresses"].iloc[0][0]
    entity = app_module._features()[1].entity_of(wallet)
    body = c.get(f"/entities/{entity}").json()
    fp = body["fingerprints"]
    assert fp["transactions"] >= 1
    assert sum(x["count"] for x in fp["labels"]) == fp["transactions"]
    assert 0 < fp["cluster_confidence"] <= 1.0 and "never create" in fp["note"]


def test_a_peer_profile_carries_its_originated_fingerprints(client):
    c, _ = client
    import api.app as app_module
    peer = app_module._profiles().leads.iloc[0]["ip"]
    body = c.get(f"/peers/{peer}/profile").json()["fingerprints"]
    assert body["propagation_origin"]["transactions"] >= 1
    assert body["originated"]["without_structure"] >= 0
