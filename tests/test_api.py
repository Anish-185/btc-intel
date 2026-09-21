"""The propagation endpoint and the degraded-mode flag on /stats."""

from __future__ import annotations

import json

import pandas as pd
import pytest

import config

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient            # noqa: E402

import api.app as app_module                        # noqa: E402

CFG = config.load()


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    from fusion.pipeline import run as fusion_run
    from generator.main import build_parser, generate
    from ingest.pipeline import run as ingest_run

    d = tmp_path_factory.mktemp("api")
    raw = d / "raw"
    generate(build_parser().parse_args(["--n-actors", "120", "--n-transactions", "600",
                                        "--output", str(raw), "--seed", "23",
                                        "--formats", "csv"]))
    ingest_run(raw, d / "t.parquet", d / "q.parquet", "csv")
    fusion_run(d / "t.parquet", raw / "ground_truth.json", d / "final.parquet",
               d / "final.json", CFG)
    app_module.configure(d / "t.parquet", raw, d / "final.json")
    yield TestClient(app_module.app), d
    app_module.configure()


def a_multi_hop_txid(directory) -> str:
    df = pd.read_parquet(directory / "t.parquet")
    counts = df.groupby("txid").size()
    return str(counts[counts > 2].index[0])


def test_propagation_returns_cytoscape_elements(client):
    api, d = client
    txid = a_multi_hop_txid(d)
    body = api.get(f"/transactions/{txid}/propagation").json()
    assert body["txid"] == txid
    assert set(body) >= {"estimated_origin", "ip_class", "confidence", "runner_ups",
                         "elements", "layout", "caveat"}
    nodes, edges = body["elements"]["nodes"], body["elements"]["edges"]
    assert nodes and edges
    for node in nodes:                                  # Cytoscape shape
        assert set(node["data"]) >= {"id", "label", "role", "ip_class", "badge"}
    ids = {n["data"]["id"] for n in nodes}
    for edge in edges:
        assert edge["data"]["source"] in ids and edge["data"]["target"] in ids


def test_origin_and_runner_ups_are_marked_for_the_dashboard(client):
    api, d = client
    body = api.get(f"/transactions/{a_multi_hop_txid(d)}/propagation").json()
    roles = {n["data"]["id"]: n["data"]["role"] for n in body["elements"]["nodes"]}
    assert roles[body["estimated_origin"]] == "origin"
    assert list(roles.values()).count("origin") == 1
    for runner in body["runner_ups"]:
        assert roles[runner["ip"]] == "runner_up"


def test_tree_is_rooted_at_the_estimated_origin_for_dagre(client):
    api, d = client
    body = api.get(f"/transactions/{a_multi_hop_txid(d)}/propagation").json()
    assert body["layout"] == {"name": "dagre", "roots": [body["estimated_origin"]]}


def test_every_node_carries_an_ip_class_badge(client):
    api, d = client
    body = api.get(f"/transactions/{a_multi_hop_txid(d)}/propagation").json()
    allowed = {"relay", "tor", "hosting", "residential"}
    assert {n["data"]["badge"] for n in body["elements"]["nodes"]} <= allowed
    assert all(n["data"]["evidence"] for n in body["elements"]["nodes"])


def test_response_states_the_attribution_caveat(client):
    api, d = client
    body = api.get(f"/transactions/{a_multi_hop_txid(d)}/propagation").json()
    assert "not an attribution" in body["caveat"]
    assert 0.0 <= body["confidence"] <= 1.0


def test_unknown_transaction_is_a_404(client):
    api, _ = client
    assert api.get("/transactions/deadbeef/propagation").status_code == 404


def test_stats_reports_origin_estimation_status(client):
    api, _ = client
    body = api.get("/stats").json()
    origin = body["features"]["origin_estimation"]
    assert origin["status"] == "ok"
    assert origin["multi_hop_transactions"] > 0
    assert origin["estimator"] == CFG["engines"]["propagation"]["estimator"]
    assert body["alerts"] > 0


def test_stats_flags_degraded_mode_on_single_row_data(client, tmp_path):
    """The dashboard must be able to say origin estimation is not really running."""
    from generator.main import build_parser, generate
    from ingest.pipeline import run as ingest_run

    _, shared = client                    # restore this afterwards, not the defaults
    raw = tmp_path / "raw"
    generate(build_parser().parse_args(["--n-actors", "40", "--n-transactions", "150",
                                        "--output", str(raw), "--seed", "5",
                                        "--formats", "csv", "--single-row"]))
    ingest_run(raw, tmp_path / "t.parquet", tmp_path / "q.parquet", "csv")
    app_module.configure(tmp_path / "t.parquet", raw, tmp_path / "missing.json")
    try:
        body = TestClient(app_module.app).get("/stats").json()
        origin = body["features"]["origin_estimation"]
        assert origin["status"] == "degraded"
        assert "single relay record" in origin["reason"]
        assert origin["multi_hop_transactions"] == 0
    finally:
        app_module.configure(shared / "t.parquet", shared / "raw", shared / "final.json")


def test_alerts_endpoint_serves_the_fusion_output(client):
    api, _ = client
    body = api.get("/alerts?limit=5").json()
    assert len(body["alerts"]) <= 5
    assert body["alerts"] and body["alerts"][0]["reason"].startswith("Flagged due to")
    assert "warning" in body["stacker"]
