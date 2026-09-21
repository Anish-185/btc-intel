"""Smoke tests: the GNN pipeline runs end to end and emits probabilities.

Deliberately no accuracy assertions — the labels are synthetic and quality
tuning belongs in a later hyperparameter search (see engines/gnn/train.py).
The one accuracy-shaped test here is inverted: it guards against the *label
leaking* through transaction timing.
"""

from __future__ import annotations

import json

import pandas as pd
import pytest

torch = pytest.importorskip("torch")

import config
from engines.gnn.data import (EDGE_FEATURES, NODE_FEATURES, build_dataset, load_labels,
                              temporal_split, z_norm)
from engines.gnn.infer import SCORE_COLUMNS, load_model, score
from engines.gnn.infer import run as infer_run
from engines.gnn.model import GINe
from engines.gnn.train import run as train_run
from engines.gnn.train import save, train
from engines.rules.detectors import FeatureSet
from graph.builder import Tx, build_graph

CFG = config.load()
T0 = pd.Timestamp("2026-01-01T00:00:00Z")


def addr(name: str) -> str:
    return "bc1q" + name.ljust(34, "z")


def tx(txid, inputs, outputs, minutes=0.0) -> Tx:
    return Tx(txid, list(inputs), list(outputs), fee=0.001, script_type="p2wpkh",
              timestamp=T0 + pd.Timedelta(minutes=minutes), ips=["10.0.0.1"])


def tiny_graph(n_wallets: int = 50):
    """~50 wallets: a ring of ordinary payments plus a small peel chain."""
    txs = [tx(f"t{i}", [(addr(f"w{i}"), 1.0)],
              [(addr(f"w{(i + 1) % n_wallets}"), 0.6), (addr(f"c{i}"), 0.39)], minutes=i * 7)
           for i in range(n_wallets)]
    held, src = 9.0, addr("collector")
    for hop in range(4):
        change = addr(f"peelchange{hop}")
        txs.append(tx(f"peel{hop}", [(src, held)],
                      [(addr(f"cash{hop}"), round(held * 0.1, 8)),
                       (change, round(held * 0.9, 8))], minutes=400 + hop * 30))
        held, src = held * 0.9, change
    labels = {t.txid: int(t.txid.startswith("peel")) for t in txs}
    return build_graph(txs), labels


@pytest.fixture(scope="module")
def tiny():
    graph, labels = tiny_graph()
    return graph, labels, build_dataset(graph, labels=labels, cfg=CFG)


# --- dataset --------------------------------------------------------------
def test_dataset_tensor_shapes_line_up(tiny):
    _, _, data = tiny
    assert data.x.shape[1] == len(NODE_FEATURES)
    assert data.edge_attr.shape == (data.num_edges, len(EDGE_FEATURES))
    assert data.edge_index.shape == (2, data.num_edges)
    assert len(data.y) == len(data.edge_txid) == len(data.timestamps) == data.num_edges
    assert data.num_nodes == len(data.nodes)
    assert data.edge_index.max() < data.num_nodes


def test_a_utxo_transaction_becomes_one_edge_per_entity_pair():
    """Many-to-many is the adaptation Multi-GNN's account ledger never needs.

    The two inputs are one entity here — common-input-ownership merged them —
    so the expansion is over *entities*, not raw addresses.
    """
    t = tx("multi", [(addr("a"), 1.0), (addr("b"), 1.0)],
           [(addr("x"), 0.9), (addr("y"), 0.9), (addr("z"), 0.1)])
    features = FeatureSet.from_graph(build_graph([t]), CFG)
    assert features.entity_of(addr("a")) == features.entity_of(addr("b"))
    data = build_dataset(build_graph([t]), features, labels={"multi": 1}, cfg=CFG)
    assert data.num_edges == 1 * 3                  # 1 sender entity x 3 receivers
    assert set(data.edge_txid) == {"multi"}
    assert (data.y == 1).all()


def test_coinjoin_inputs_stay_separate_senders():
    """Clustering refuses to merge CoinJoin inputs, so each is its own sender."""
    cj = tx("cj", [(addr(f"in{i}"), 0.1) for i in range(4)],
            [(addr(f"out{i}"), 0.0999) for i in range(4)])
    data = build_dataset(build_graph([cj]), labels={"cj": 0}, cfg=CFG)
    assert data.num_edges == 4 * 4


def test_edge_expansion_is_capped():
    cfg = json.loads(json.dumps(CFG))
    cfg["engines"]["gnn"]["max_edges_per_tx"] = 4
    t = tx("wide", [(addr(f"i{i}"), 1.0) for i in range(5)],
           [(addr(f"o{i}"), 0.9) for i in range(5)])
    assert build_dataset(build_graph([t]), labels={"wide": 0}, cfg=cfg).num_edges == 4


def test_a_transaction_that_never_leaves_one_entity_keeps_a_self_loop():
    """Otherwise a pure-change transaction would vanish from scoring."""
    txs = [tx("fund", [(addr("outside"), 5.0)], [(addr("a"), 4.9)], minutes=0),
           tx("internal", [(addr("a"), 4.9)], [(addr("a"), 4.8)], minutes=10)]
    data = build_dataset(build_graph(txs), labels={"internal": 0, "fund": 0}, cfg=CFG)
    src, dst = data.edge_index.tolist()
    loops = [i for i, (s, d) in enumerate(zip(src, dst)) if s == d]
    assert "internal" in {data.edge_txid[i] for i in loops}


def test_labels_follow_the_configured_typologies():
    gt = {"transactions": {"a": {"typology": "ransomware_collector"},
                           "b": {"typology": "coinjoin"},
                           "c": {"typology": "layering"},
                           "d": {"typology": "normal"}}}
    labels = load_labels(gt, CFG)
    assert labels == {"a": 1, "b": 0, "c": 1, "d": 0}, "CoinJoin is mixing, not a crime"


def test_temporal_split_never_puts_the_future_in_training(tiny):
    _, _, data = tiny
    train_mask, val_mask, test_mask = temporal_split(data, CFG)
    assert int(train_mask.sum()) and int(val_mask.sum()) and int(test_mask.sum())
    assert not bool((train_mask & val_mask).any())
    assert data.timestamps[train_mask].max() <= data.timestamps[val_mask].min()
    assert data.timestamps[val_mask].max() <= data.timestamps[test_mask].min()


def test_z_norm_reuses_training_statistics():
    a = torch.tensor([[1.0, 2.0], [3.0, 4.0]])
    normed, stats = z_norm(a)
    assert normed.mean().abs() < 1e-6
    again, _ = z_norm(torch.tensor([[1.0, 2.0]]), stats)
    assert torch.allclose(again, normed[:1])


def test_constant_column_does_not_divide_by_zero():
    normed, _ = z_norm(torch.tensor([[5.0], [5.0]]))
    assert torch.isfinite(normed).all()


# --- training smoke -------------------------------------------------------
def test_two_epochs_train_without_error(tiny):
    _, _, data = tiny
    model, artefacts, history = train(data, CFG, epochs=2, verbose=False)
    assert len(history) == 2
    assert all(torch.isfinite(torch.tensor(h["loss"])) for h in history)
    assert artefacts["node_dim"] == len(NODE_FEATURES)
    assert "synthetic labels" in artefacts["warning"]


def test_training_refuses_unlabelled_data(tiny):
    graph, _, _ = tiny
    unlabelled = build_dataset(graph, cfg=CFG)          # no labels passed
    assert not bool(unlabelled.labelled.any())
    with pytest.raises(ValueError, match="no labelled edges"):
        train(unlabelled, CFG, epochs=1)


def test_model_forward_returns_one_logit_per_edge(tiny):
    _, _, data = tiny
    model = GINe(data.x.shape[1], data.edge_attr.shape[1], hidden=8, layers=2)
    assert model(data.x, data.edge_index, data.edge_attr).shape == (data.num_edges,)


# --- scores ---------------------------------------------------------------
def test_scores_are_probabilities_at_both_levels(tiny):
    graph, labels, data = tiny
    model, artefacts, _ = train(data, CFG, epochs=2, verbose=False)
    df = score(data, model, artefacts, CFG)
    assert list(df.columns) == SCORE_COLUMNS
    assert df["gnn_score"].between(0.0, 1.0).all()
    assert set(df["level"]) == {"transaction", "entity"}
    assert set(df[df.level == "transaction"]["id"]) == set(data.edge_txid)
    assert df["id"].duplicated().sum() == 0 or True     # ids are unique within a level
    for level in ("transaction", "entity"):
        assert not df[df.level == level]["id"].duplicated().any()


def test_saved_model_reloads_and_scores_identically(tiny, tmp_path):
    _, _, data = tiny
    model, artefacts, _ = train(data, CFG, epochs=2, verbose=False)
    before = score(data, model, artefacts, CFG)
    save(artefacts, tmp_path / "gnn.pt")
    reloaded, reloaded_artefacts = load_model(tmp_path / "gnn.pt", CFG)
    after = score(data, reloaded, reloaded_artefacts, CFG)
    pd.testing.assert_frame_equal(before, after)


def test_empty_graph_scores_nothing_instead_of_crashing(tiny):
    _, _, data = tiny
    model, artefacts, _ = train(data, CFG, epochs=1, verbose=False)
    empty = build_dataset([], FeatureSet.from_graph([], CFG), cfg=CFG)
    assert score(empty, model, artefacts, CFG).empty


def test_pyg_export_when_available(tiny):
    pytest.importorskip("torch_geometric")
    _, _, data = tiny
    pyg = data.to_pyg_data()
    assert pyg.num_nodes == data.num_nodes
    assert pyg.edge_index.shape == data.edge_index.shape


# --- end to end on generated data ----------------------------------------
@pytest.fixture(scope="module")
def generated(tmp_path_factory):
    from generator.main import build_parser, generate
    from ingest.pipeline import run as ingest_run
    from tests.test_ingest import stub_geo

    d = tmp_path_factory.mktemp("gnn")
    raw = d / "raw"
    generate(build_parser().parse_args(["--n-actors", "200", "--n-transactions", "1500",
                                        "--output", str(raw), "--seed", "13",
                                        "--formats", "csv"]))
    ingest_run(raw, d / "t.parquet", d / "q.parquet", "csv", geo=stub_geo())
    return d, raw


def test_train_then_infer_end_to_end(generated, tmp_path):
    d, raw = generated
    summary = train_run(d / "t.parquet", raw / "ground_truth.json", tmp_path / "gnn.pt",
                        epochs=2, cfg=CFG, verbose=False)
    assert summary["labelled"] > 0 and summary["illicit_edges"] > 0
    assert "unproven" in summary["warning"]

    scored = infer_run(d / "t.parquet", tmp_path / "scores.parquet", tmp_path / "gnn.pt", CFG)
    df = pd.read_parquet(tmp_path / "scores.parquet")
    assert df["gnn_score"].between(0.0, 1.0).all()
    assert scored["scored"]["transaction"] == 1500
    assert scored["scored"]["entity"] > 0


def test_timing_alone_does_not_give_away_the_label(generated):
    """Regression guard on the generator.

    Typology transactions used to be emitted back-to-back, so the gap since a
    wallet's previous transaction identified the pattern outright and every
    model trained on this data reported inflated accuracy. Instances are now
    spread over a window (generator.typology_spread_factor).
    """
    from sklearn.metrics import f1_score
    from sklearn.tree import DecisionTreeClassifier

    from graph.builder import from_parquet
    d, raw = generated
    data = build_dataset(from_parquet(d / "t.parquet", CFG),
                         labels=load_labels(raw / "ground_truth.json", CFG), cfg=CFG)
    train_mask, _, test_mask = temporal_split(data, CFG)
    X, y = data.edge_attr.numpy(), data.y.numpy()
    gap = EDGE_FEATURES.index("time_since_prev_tx_same_wallet")
    stump = DecisionTreeClassifier(max_depth=1, class_weight="balanced", random_state=0)
    stump.fit(X[train_mask.numpy()][:, [gap]], y[train_mask.numpy()])
    leaked = f1_score(y[test_mask.numpy()], stump.predict(X[test_mask.numpy()][:, [gap]]))
    assert leaked < 0.5, f"inter-transaction timing leaks the label (F1 {leaked:.2f})"
