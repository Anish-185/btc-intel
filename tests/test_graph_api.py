"""The investigation graph endpoints, on graphs small enough to check by hand.

Every case here is a graph an investigator could draw on paper, so a failure
points at the traversal rather than at the fixture.
"""

from __future__ import annotations

import json

import pandas as pd
import pytest

import config

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

import api.app as app_module  # noqa: E402

CFG = config.load()


def tx(txid: str, inputs: list[tuple[str, float]], outputs: list[tuple[str, float]],
       ip: str = "10.0.0.1", ts: str = "2026-01-01T00:00:00Z") -> dict:
    return {
        "txid": txid,
        "input_addresses": [a for a, _ in inputs],
        "input_amounts": [v for _, v in inputs],
        "output_addresses": [a for a, _ in outputs],
        "output_amounts": [v for _, v in outputs],
        "fee": 0.0001,
        "script_type": "p2wpkh",
        "timestamp": pd.Timestamp(ts),
        "src_ip": ip,
        "asn": 9829,
        "geo_country": "IN",
    }


def serve(rows: list[dict], tmp_path, alerts: dict | None = None) -> TestClient:
    """Point the API at a hand-built set of transactions."""
    frame = pd.DataFrame(rows)
    path = tmp_path / "t.parquet"
    frame.to_parquet(path, index=False)
    alerts_path = tmp_path / "alerts.json"
    alerts_path.write_text(json.dumps(alerts or {"alerts": []}))
    app_module.configure(path, tmp_path, alerts_path, tmp_path / "feedback.parquet")
    return TestClient(app_module.app)


@pytest.fixture(autouse=True)
def reset():
    yield
    app_module.configure()


# --- a peeling chain: A -> B -> C -> D, with a dust branch off B -----------
CHAIN = [
    tx("t1", [("A", 1.0)], [("B", 0.9), ("A_change", 0.0999)]),
    tx("t2", [("B", 0.9)], [("C", 0.8), ("B_change", 0.0999)]),
    tx("t3", [("C", 0.8)], [("D", 0.7), ("C_change", 0.0999)]),
    tx("t4", [("B", 0.05)], [("DUST", 0.001), ("B_dust_change", 0.0489)]),
]


def ids(payload: dict, kind: str | None = None) -> set[str]:
    return {
        n["data"]["id"]
        for n in payload["nodes"]
        if kind is None or n["data"]["type"] == kind
    }


def test_trace_follows_the_money_forward_and_stops_at_max_hops(tmp_path):
    api = serve(CHAIN, tmp_path)

    one = api.get("/graph/trace", params={"from": "A", "max_hops": 1}).json()
    assert "B" in ids(one, "wallet")
    assert "C" not in ids(one, "wallet"), "one hop reached two hops away"

    three = api.get("/graph/trace", params={"from": "A", "max_hops": 3}).json()
    assert {"A", "B", "C", "D"} <= ids(three, "wallet")

    # The connector transactions are in the result — wallets are never joined
    # to each other directly.
    assert {"t1", "t2", "t3"} <= ids(three, "transaction")
    for edge in three["edges"]:
        source_type = next(n["data"]["type"] for n in three["nodes"] if n["data"]["id"] == edge["data"]["source"])
        target_type = next(n["data"]["type"] for n in three["nodes"] if n["data"]["id"] == edge["data"]["target"])
        assert {source_type, target_type} != {"wallet"}, "a wallet-to-wallet edge was invented"


def test_trace_depth_is_hops_from_the_root(tmp_path):
    api = serve(CHAIN, tmp_path)
    payload = api.get("/graph/trace", params={"from": "A", "max_hops": 3}).json()
    depth = {n["data"]["id"]: n["data"]["depth"] for n in payload["nodes"]}
    assert depth["A"] == 0
    assert depth["B"] == 1
    assert depth["C"] == 2
    assert depth["D"] == 3


def test_trace_prunes_below_min_amount_and_says_how_much(tmp_path):
    api = serve(CHAIN, tmp_path)
    full = api.get("/graph/trace", params={"from": "A", "max_hops": 3}).json()
    assert "DUST" in ids(full, "wallet")

    pruned = api.get(
        "/graph/trace", params={"from": "A", "max_hops": 3, "min_amount": 0.1}
    ).json()
    assert "DUST" not in ids(pruned, "wallet")
    assert {"B", "C", "D"} <= ids(pruned, "wallet")
    assert pruned["pruned_edges"] > 0


def test_trace_backward_walks_the_other_way(tmp_path):
    api = serve(CHAIN, tmp_path)
    back = api.get(
        "/graph/trace", params={"from": "D", "direction": "backward", "max_hops": 3}
    ).json()
    assert {"A", "B", "C", "D"} <= ids(back, "wallet")
    forward_from_d = api.get("/graph/trace", params={"from": "D", "max_hops": 3}).json()
    assert ids(forward_from_d, "wallet") == {"D"}, "money that never left D was traced out of it"


def test_trace_refuses_to_start_from_a_transaction(tmp_path):
    api = serve(CHAIN, tmp_path)
    assert api.get("/graph/trace", params={"from": "t1"}).status_code == 400


# --- shortest path --------------------------------------------------------
# Two routes from A to Z: a short one through t_fast, a long one through the
# chain. The short one must win, and direction must be respected.
PATHS = [
    tx("p1", [("A", 1.0)], [("M", 0.5), ("N", 0.49)]),
    tx("p2", [("M", 0.5)], [("Z", 0.49)]),
    tx("p3", [("N", 0.49)], [("O", 0.48)]),
    tx("p4", [("O", 0.48)], [("Z", 0.47)]),
]


def test_path_returns_the_shortest_directed_route(tmp_path):
    api = serve(PATHS, tmp_path)
    payload = api.get("/graph/path", params={"from": "A", "to": "Z"}).json()
    assert payload["path"] == ["A", "p1", "M", "p2", "Z"]
    assert payload["hops"] == 4
    assert [e["data"]["source"] for e in payload["edges"]] == ["A", "p1", "M", "p2"]


def test_path_respects_direction(tmp_path):
    api = serve(PATHS, tmp_path)
    response = api.get("/graph/path", params={"from": "Z", "to": "A"})
    assert response.status_code == 404
    assert "no directed money-flow path" in response.json()["detail"]
    assert "the other way" in response.json()["detail"]


def test_path_404s_on_an_unknown_node_and_on_a_self_path(tmp_path):
    api = serve(PATHS, tmp_path)
    assert api.get("/graph/path", params={"from": "A", "to": "nope"}).status_code == 404
    assert api.get("/graph/path", params={"from": "A", "to": "A"}).status_code == 400


# --- supernode pagination -------------------------------------------------
def supernode_rows(n: int = 60) -> list[dict]:
    """One exchange wallet paying `n` counterparties, each in its own
    transaction, with descending amounts so ranking is checkable."""
    rows = [tx("fund", [("SOURCE", 100.0)], [("HUB", 99.0)])]
    for i in range(n):
        rows.append(
            tx(f"s{i:03d}", [("HUB", 1.0)], [(f"W{i:03d}", round(1.0 - i * 0.01, 4))])
        )
    return rows


def test_neighbors_pages_through_a_supernode(tmp_path):
    api = serve(supernode_rows(60), tmp_path)

    first = api.get("/graph/nodes/HUB/neighbors", params={"direction": "out", "limit": 20}).json()
    assert first["total"] == 60
    assert first["returned"] == 20
    assert first["has_more"] is True
    assert first["remaining"] == 40

    second = api.get(
        "/graph/nodes/HUB/neighbors",
        params={"direction": "out", "limit": 20, "offset": 20},
    ).json()
    third = api.get(
        "/graph/nodes/HUB/neighbors",
        params={"direction": "out", "limit": 20, "offset": 40},
    ).json()
    assert third["has_more"] is False

    pages = [ids(p, "transaction") for p in (first, second, third)]
    assert sum(len(page) for page in pages) == 60
    assert set().union(*pages) == {f"s{i:03d}" for i in range(60)}
    assert not pages[0] & pages[1], "pages overlapped"


def test_neighbors_ranks_by_amount_so_the_first_page_is_the_useful_one(tmp_path):
    api = serve(supernode_rows(60), tmp_path)
    first = api.get("/graph/nodes/HUB/neighbors", params={"direction": "out", "limit": 5}).json()
    # s000 carries 1.0 BTC, s059 carries 0.41 — the biggest flows come first.
    assert ids(first, "transaction") == {"s000", "s001", "s002", "s003", "s004"}


def test_expanding_a_wallet_returns_the_wallets_on_the_far_side(tmp_path):
    api = serve(CHAIN, tmp_path)
    payload = api.get("/graph/nodes/A/neighbors", params={"direction": "out"}).json()
    assert "t1" in ids(payload, "transaction")
    assert "B" in ids(payload, "wallet"), "a lone connector node answers nothing"


def test_neighbors_direction_filters_the_expansion(tmp_path):
    api = serve(CHAIN, tmp_path)
    outgoing = api.get("/graph/nodes/B/neighbors", params={"direction": "out"}).json()
    incoming = api.get("/graph/nodes/B/neighbors", params={"direction": "in"}).json()
    assert "t2" in ids(outgoing, "transaction") and "t1" not in ids(outgoing, "transaction")
    assert "t1" in ids(incoming, "transaction") and "t2" not in ids(incoming, "transaction")


def test_unknown_node_is_a_404(tmp_path):
    api = serve(CHAIN, tmp_path)
    assert api.get("/graph/nodes/nope/neighbors").status_code == 404


# --- clusters and node shaping --------------------------------------------
def test_cluster_returns_its_member_wallets(tmp_path):
    # Common-input ownership merges the two inputs of t5 into one entity.
    rows = CHAIN + [tx("t5", [("A_change", 0.09), ("B_change", 0.09)], [("MERGED", 0.17)])]
    api = serve(rows, tmp_path)
    _, features = app_module._features()
    cluster_id = features.clustering.cluster_of("A_change")

    payload = api.get(f"/graph/clusters/{cluster_id}").json()
    assert payload["size"] >= 2
    assert {"A_change", "B_change"} <= ids(payload, "wallet")
    assert api.get("/graph/clusters/nope").status_code == 404


def test_wallet_nodes_carry_their_entity_risk(tmp_path):
    api = serve(CHAIN, tmp_path, alerts={"alerts": []})
    _, features = app_module._features()
    entity = features.clustering.cluster_of("B") or "B"

    api = serve(
        CHAIN,
        tmp_path,
        alerts={"alerts": [{"alert_id": entity, "entity_id": entity, "risk_score": 0.87}]},
    )
    payload = api.get("/graph/trace", params={"from": "A", "max_hops": 1}).json()
    node = next(n["data"] for n in payload["nodes"] if n["data"]["id"] == "B")
    assert node["risk"] == pytest.approx(0.87)
    assert node["alerted"] is True

    unflagged = next(n["data"] for n in payload["nodes"] if n["data"]["id"] == "A")
    assert unflagged["risk"] == 0.0
    assert unflagged["alerted"] is False


def test_ip_nodes_are_labelled_with_their_country(tmp_path):
    api = serve(CHAIN, tmp_path)
    payload = api.get("/graph/nodes/t1/neighbors", params={"direction": "in"}).json()
    ip_nodes = [n["data"] for n in payload["nodes"] if n["data"]["type"] == "ip"]
    assert ip_nodes and ip_nodes[0]["label"].endswith("IN")


# --- saved investigations -------------------------------------------------
def test_an_investigation_round_trips(tmp_path, monkeypatch):
    monkeypatch.setitem(CFG["fusion"], "investigations_dir", str(tmp_path / "inv"))
    monkeypatch.setattr(config, "load", lambda *a, **k: CFG)
    api = serve(CHAIN, tmp_path)

    state = {"nodes": ["A", "t1", "B"], "positions": {"A": {"x": 1, "y": 2}}, "layout": "fcose"}
    created = api.post("/investigations", json={"name": "Peel chain", "state": state}).json()
    assert created["name"] == "Peel chain"

    loaded = api.get(f"/investigations/{created['id']}").json()
    assert loaded["state"] == state
    assert loaded["id"] == created["id"]

    listing = api.get("/investigations").json()
    assert created["id"] in {row["id"] for row in listing["investigations"]}
    assert api.get("/investigations/nope").status_code == 404


def test_an_investigation_id_cannot_escape_its_directory(tmp_path, monkeypatch):
    monkeypatch.setitem(CFG["fusion"], "investigations_dir", str(tmp_path / "inv"))
    monkeypatch.setattr(config, "load", lambda *a, **k: CFG)
    api = serve(CHAIN, tmp_path)
    assert api.get("/investigations/..%2F..%2Fetc%2Fpasswd").status_code == 404


def test_a_saved_investigation_can_be_the_report_figure(tmp_path, monkeypatch):
    """A case report should show what the investigator was looking at."""
    monkeypatch.setitem(CFG["fusion"], "investigations_dir", str(tmp_path / "inv"))
    monkeypatch.setattr(config, "load", lambda *a, **k: CFG)
    api = serve(CHAIN, tmp_path)

    state = {
        "elements": [
            {"data": {"id": "A", "type": "wallet", "label": "A", "risk": 0.9}},
            {"data": {"id": "t1", "type": "transaction", "label": "t1"}},
            {"data": {"id": "B", "type": "wallet", "label": "B", "risk": 0.2}},
            {"data": {"id": "e1", "source": "A", "target": "t1", "amount": 1.0}},
            {"data": {"id": "e2", "source": "t1", "target": "B", "amount": 0.9}},
        ],
        "positions": {"A": {"x": 0, "y": 0}, "t1": {"x": 50, "y": 20}, "B": {"x": 100, "y": 0}},
    }
    saved = api.post("/investigations", json={"name": "Chain", "state": state}).json()

    _, features = app_module._features()
    entity = features.clustering.cluster_of("A") or "A"
    response = api.get(f"/entities/{entity}/report", params={"investigation": saved["id"]})
    assert response.status_code == 200
    assert response.content.startswith(b"%PDF-")
    assert b"/Count 1" in response.content

    # Without the parameter the report still draws its own neighbourhood.
    plain = api.get(f"/entities/{entity}/report")
    assert plain.status_code == 200 and plain.content.startswith(b"%PDF-")
