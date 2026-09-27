"""intel/: sealed bundles, import refusals, propagation, conflicts, and the demo
bundle's inability to pass as real intelligence."""

from __future__ import annotations

import ast
import inspect
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

import config
import custody
import intel
from fusion.stacker import SIGNALS
from graph.clustering import Clustering
from intel import bundle as B
from intel import importers
from intel import store as S
from intel.tags import Tag

FIXTURES = Path(__file__).parent / "fixtures"


def cfg_for(tmp_path, provenance="simulated") -> dict:
    cfg = json.loads(json.dumps(config.load()))      # config.load() is shared; copy it
    cfg["custody"]["ledger_path"] = str(tmp_path / "custody.jsonl")
    cfg["tags"]["store_dir"] = str(tmp_path / "store")
    cfg["ingest"]["provenance"] = provenance
    return cfg


def tag(subject, category="ransomware", applies_to="cluster", label=None, source="team list",
        confidence=0.9, reference="case file 12"):
    return Tag(subject=subject, label=label or f"{category} service", category=category,
               source=source, reference=reference, collected="2026-09-01",
               confidence=confidence, applies_to=applies_to)


def clustering() -> Clustering:
    """Cluster c1 = {a1, a2, a3} with an uncertain merge; c2 = {b1, b2}; lone z."""
    clusters = {"c1": {"a1", "a2", "a3"}, "c2": {"b1", "b2"}, "z": {"z"}}
    return Clustering(wallet_to_cluster={w: c for c, ws in clusters.items() for w in ws},
                      clusters=clusters, confidence={"c1": 0.5})


def actions(cfg) -> list[tuple[str, dict]]:
    return [(e["action"], e["detail"]) for e in custody.read(cfg)]


# --- the seal -------------------------------------------------------------------
def test_a_sealed_bundle_imports_and_the_import_is_recorded(tmp_path):
    cfg = cfg_for(tmp_path)
    B.write_bundle([tag("a1")], tmp_path / "b", "team", "a curated list")
    result = B.import_bundle(tmp_path / "b", cfg)
    assert result["tags"] == 1 and Path(result["stored_at"], "tags.jsonl").exists()
    (action, detail), = actions(cfg)
    assert action == "tags.bundle_imported" and detail["manifest_hash"] == result["manifest_hash"]
    assert S.load(cfg).header()["tags"] == 1


@pytest.mark.parametrize("tamper", ["unsealed", "edited", "added", "manifest"])
def test_an_unsealed_or_altered_bundle_is_refused_and_the_refusal_recorded(tmp_path, tamper):
    cfg = cfg_for(tmp_path)
    directory = tmp_path / "b"
    B.write_bundle([tag("a1")], directory, "team", "a curated list")
    if tamper == "unsealed":
        (directory / "manifest.json").unlink()
    elif tamper == "edited":
        lines = (directory / "tags.jsonl").read_text().replace('"ransomware"', '"exchange/VASP"')
        (directory / "tags.jsonl").write_text(lines)
    elif tamper == "added":
        (directory / "extra.jsonl").write_text("{}\n")
    else:
        m = json.loads((directory / "manifest.json").read_text())
        m["files"][0]["sha256"] = "0" * 64
        (directory / "manifest.json").write_text(json.dumps(m))
    with pytest.raises(B.BundleRefused):
        B.import_bundle(directory, cfg)
    (action, detail), = actions(cfg)
    assert action == "tags.bundle_refused" and detail["reason"]
    assert not (tmp_path / "store").exists()


def test_a_bundle_altered_inside_the_store_stops_counting(tmp_path):
    cfg = cfg_for(tmp_path)
    B.write_bundle([tag("a1")], tmp_path / "b", "team", "a curated list")
    stored = Path(B.import_bundle(tmp_path / "b", cfg)["stored_at"])
    (stored / "tags.jsonl").write_text((stored / "tags.jsonl").read_text().replace("0.9", "1.0"))
    store = S.load(cfg)
    assert store.by_address == {} and store.bundles[0]["ok"] is False


def test_a_second_bundle_under_the_same_name_is_refused(tmp_path):
    cfg = cfg_for(tmp_path)
    B.write_bundle([tag("a1")], tmp_path / "one", "team", "v1")
    B.write_bundle([tag("a2")], tmp_path / "two", "team", "v2")
    B.import_bundle(tmp_path / "one", cfg)
    with pytest.raises(B.BundleRefused, match="already imported"):
        B.import_bundle(tmp_path / "two", cfg)


def test_the_seal_is_p2p_manifest_not_a_second_crypto_path():
    source = inspect.getsource(B)
    assert "manifest.seal_capture" in source and "manifest.verify_capture" in source
    for module in (B, S, importers):
        text = inspect.getsource(module)
        assert "hashlib" not in text and "hmac" not in text


# --- propagation ----------------------------------------------------------------
def test_a_cluster_tag_reaches_every_member_at_the_merge_confidence():
    store = S.TagStore(risk={"ransomware": 1.0})
    store.add("team", [tag("a1", confidence=0.8)])
    entity = store.entity("c1", clustering())
    assert entity["tags"][0]["effective_confidence"] == pytest.approx(0.4)   # 0.8 x 0.5
    for member in ("a2", "a3"):
        shown = store.address(member, clustering())["tags"]
        assert shown and shown[0]["via"] == "a1" and shown[0]["effective_confidence"] == 0.4
    assert store.score(entity) == pytest.approx(0.4)


def test_an_address_tag_stays_on_its_address():
    store = S.TagStore(risk={"sanctioned": 1.0})
    store.add("ofac", [tag("a1", "sanctioned", applies_to="address")])
    entity = store.entity("c1", clustering())
    assert entity["tags"] == [] and len(entity["member_tags"]) == 1
    assert store.score(entity) == 0.0
    assert store.address("a2", clustering())["tags"] == []
    assert store.address("a1", clustering())["tags"][0]["basis"] == "address tag"
    store.add("ofac", [tag("z", "sanctioned", applies_to="address")])
    assert store.score(store.entity("z", clustering())) == 0.9      # a lone wallet is its address


def test_a_tag_never_crosses_into_another_cluster():
    """Actors join clusters c1 and c2 in the actor view; a tag on c1 says nothing
    about c2, and nothing in intel/ reads actors, fingerprints or flows."""
    store = S.TagStore(risk={"ransomware": 1.0})
    store.add("team", [tag("a1")])
    assert store.entity("c2", clustering())["tags"] == []
    for module in (B, S, importers):
        imported = {n.module if isinstance(n, ast.ImportFrom) else a.name
                    for n in ast.walk(ast.parse(inspect.getsource(module)))
                    if isinstance(n, (ast.Import, ast.ImportFrom))
                    for a in (n.names if isinstance(n, ast.Import) else [n])}
        for forbidden in ("fingerprint", "actors", "entity_graph", "taint"):
            assert not any(forbidden in (m or "") for m in imported - {"eval.actors"}), (
                module.__name__, forbidden)


def test_conflicting_tags_are_all_shown_and_flagged():
    store = S.TagStore(risk={"ransomware": 1.0, "exchange/VASP": 0.0})
    store.add("team", [tag("a1", "ransomware")])
    store.add("other team", [tag("a2", "exchange/VASP", label="an exchange")])
    entity = store.entity("c1", clustering())
    assert entity["conflict"] and len(entity["tags"]) == 2
    assert entity["categories"] == ["exchange/VASP", "ransomware"]
    assert store.score(entity) == pytest.approx(0.45)      # shown, not resolved away


def test_exchange_tags_are_shown_but_never_scored():
    store = S.TagStore(risk=config.load()["tags"]["risk"])
    store.add("team", [tag("b1", "exchange/VASP", confidence=1.0)])
    entity = store.entity("c2", clustering())
    assert entity["tags"] and store.score(entity) == 0.0


def test_tags_feed_the_stacker_as_a_signal():
    assert "tag_score" in SIGNALS
    assert "tag_score" in config.load()["fusion"]["stacker"]["signals"]

    class Features:
        clustering = clustering()

        def entity_of(self, wallet):
            return self.clustering.cluster_of(wallet) or wallet

    store = S.TagStore(risk={"ransomware": 1.0})
    store.add("team", [tag("a2", confidence=1.0)])
    frame = S.tag_scores(Features(), store=store)
    assert frame.to_dict("records") == [{"entity_id": "c1", "tag_score": 0.5}]


# --- the demo bundle ------------------------------------------------------------
@pytest.fixture(scope="module")
def demo_raw(tmp_path_factory):
    """A tiny generated dataset: a raw dir with ground truth."""
    from eval.datasets import build
    cfg = config.load()
    cfg["eval"]["n_actors"], cfg["eval"]["n_transactions"] = 200, 1200
    return build(cfg["eval"]["default_rate"], False, 7, cfg,
                 root=tmp_path_factory.mktemp("demo"), name_prefix="tags-demo").raw


def test_the_demo_bundle_is_simulated_everywhere(demo_raw, tmp_path):
    tags = importers.demo(demo_raw)
    assert tags and all(t.simulated and t.source == "simulated" for t in tags)
    assert {t.category for t in tags} >= {"exchange/VASP"}
    meta = B.write_bundle(tags, tmp_path / "demo", "demo", "SIMULATED")
    assert meta["simulated"] is True and meta["sources"] == ["simulated"]
    assert all(t.as_dict()["simulated"] for t in tags)   # the flag every view reads


def test_a_demo_tag_cannot_be_relabelled_real(demo_raw, tmp_path):
    cfg = cfg_for(tmp_path)
    tags = importers.demo(demo_raw)
    real = {**tags[0].as_dict(), "source": "OFAC SDN"}
    with pytest.raises(ValueError, match="ground truth"):
        Tag.from_dict(real)                              # at construction
    directory = tmp_path / "demo"
    B.write_bundle(tags, directory, "demo", "SIMULATED")
    text = (directory / "tags.jsonl").read_text()
    (directory / "tags.jsonl").write_text(text.replace('"source": "simulated"',
                                                       '"source": "OFAC SDN"', 1))
    with pytest.raises(B.BundleRefused, match="altered"):
        B.import_bundle(directory, cfg)                  # after sealing


def test_a_simulated_bundle_cannot_enter_a_real_case(demo_raw, tmp_path):
    B.write_bundle(importers.demo(demo_raw), tmp_path / "demo", "demo", "SIMULATED")
    with pytest.raises(B.BundleRefused, match="real case"):
        B.import_bundle(tmp_path / "demo", cfg_for(tmp_path, provenance="real"))


def test_a_bundle_cannot_mix_simulated_and_real_tags(demo_raw, tmp_path):
    tags = [*importers.demo(demo_raw)[:1], tag("a1")]
    B.write_bundle(tags, tmp_path / "mixed", "mixed", "mixed")
    with pytest.raises(B.BundleRefused, match="mixes"):
        B.import_bundle(tmp_path / "mixed", cfg_for(tmp_path))


# --- importers ------------------------------------------------------------------
def test_ofac_sdn_xbt_entries_become_sanctioned_tags_without_naming_individuals():
    tags = importers.ofac(FIXTURES / "sdn_fixture.xml")
    by_subject = {t.subject: t for t in tags}
    assert set(by_subject) == {"1ExampLeServiceXbtAddr11111111111", "bc1qexampleservice2xbt0000000000000000000",
                               "1ExampLePersonXbtAddr222222222222"}
    service = by_subject["1ExampLeServiceXbtAddr11111111111"]
    assert service.category == "sanctioned" and service.source == "OFAC SDN"
    assert "EXAMPLE EXCHANGE LTD" in service.label and service.collected == "2026-09-15"
    assert service.applies_to == "address" and "uid 9001" in service.reference
    person = by_subject["1ExampLePersonXbtAddr222222222222"]
    assert "DOE" not in person.label and "JANE" not in person.label
    assert person.label.startswith("OFAC SDN individual entry 9002")


def test_a_csv_row_that_is_not_a_valid_tag_fails_the_file_with_its_line(tmp_path):
    path = tmp_path / "list.csv"
    path.write_text("address,label,category,reference,collected,confidence\n"
                    "a1,Hydra,darknet market,report 7,2026-08-01,0.9\n"
                    "a2,Someone,person,report 8,2026-08-01,0.9\n")
    with pytest.raises(ValueError, match="line 3"):
        importers.from_csv(path, "team")
    path.write_text(path.read_text().splitlines()[0] + "\n"
                    "a1,Hydra,darknet market,report 7,2026-08-01,0.9\n")
    (t,) = importers.from_csv(path, "team")
    assert t.source == "team" and t.category == "darknet market"


def test_intel_is_a_declared_package():
    assert Path(intel.__file__).parent.name == "intel"


# --- the unfitted fallback without tags ------------------------------------------
def pre_p11_fallback(frame, cfg):
    """fusion.stacker's fallback as it was at 9f939f8: four signals, config weights."""
    w = cfg["risk_weights"]
    weights = {"rule_score": w.get("rules", 0.35), "anomaly_score": w.get("anomaly", 0.25),
               "gnn_score": w.get("gnn", 0.25), "taint_score": w.get("taint", 0.25)}
    values = frame[list(weights)].astype(float).fillna(0.0).to_numpy()
    return values @ np.array(list(weights.values())) / sum(weights.values())


def test_without_a_tag_store_the_fallback_scores_exactly_as_before_p11(tmp_path):
    from fusion.stacker import Stacker, default_weights
    rng = np.random.default_rng(3)
    frame = pd.DataFrame(rng.random((400, 4)), columns=["rule_score", "anomaly_score",
                                                        "gnn_score", "taint_score"])
    frame["tag_score"] = 0.0
    cfg = cfg_for(tmp_path)                           # an empty store directory
    for c in (cfg, {**cfg, "tags": {**cfg["tags"], "store_dir": None}}):
        weights = default_weights(c)
        assert "tag_score" not in weights
        scores = Stacker(fallback_weights=weights).score(frame)
        assert np.array_equal(scores, pre_p11_fallback(frame, c))
        threshold = c["fusion"]["alert_threshold"]
        assert (scores >= threshold).sum() == (pre_p11_fallback(frame, c) >= threshold).sum()
        # a subset scores exactly as it does inside the whole frame
        assert np.array_equal(Stacker(fallback_weights=weights).score(frame.iloc[:7]), scores[:7])


def test_with_a_tag_store_the_fallback_includes_the_tag_signal(tmp_path):
    from fusion.stacker import default_weights
    cfg = cfg_for(tmp_path)
    B.write_bundle([tag("a1")], tmp_path / "b", "team", "list")
    B.import_bundle(tmp_path / "b", cfg)
    assert default_weights(cfg)["tag_score"] == cfg["tags"]["fallback_weight"]
