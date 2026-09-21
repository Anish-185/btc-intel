"""Append one fresh instance of a typology to an existing dataset.

Used by red-team mode (Phase 8c): plant a known pattern into data the
detection stack has already been tuned on, then check whether it is found.
The gossip topology is rebuilt from the dataset's own seed, so injected
traffic traverses the same P2P network as the original run.
"""

from __future__ import annotations

import json
import random
from argparse import Namespace
from datetime import datetime
from pathlib import Path

import config

from .main import GROUND_TRUTH, ground_truth, iso, observed_origin, relay_rows
from .net import build_net
from .typologies import TYPOLOGIES, World
from .writers import WRITERS, open_writers


def _epoch(stamp: str) -> float:
    return datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()


def inject_pattern(dataset_dir, typology: str, params: dict | None = None,
                   seed: int = 0, cfg: dict | None = None) -> dict:
    """Append ONE new instance of `typology` (fresh wallets, fresh IPs).

    `params` overrides that typology's entry in config's `typology_params`,
    plus optional `n_counterparties` (fresh innocent wallets to transact with),
    `relay_observation_rate` and `single_row`.
    """
    if typology not in TYPOLOGIES:
        raise KeyError(f"unknown typology {typology!r}; have {sorted(TYPOLOGIES)}")
    params = dict(params or {})
    d = Path(dataset_dir)
    gt = json.loads((d / GROUND_TRUTH).read_text())

    cfg = json.loads(json.dumps(cfg or config.load()))  # local copy — overrides below
    overrides = {k: v for k, v in params.items()
                 if k not in ("n_counterparties", "relay_observation_rate", "single_row")}
    cfg["generator"]["typology_params"].setdefault(typology, {}).update(overrides)

    rng = random.Random(seed)
    net = build_net(random.Random(gt["seed"] + 1), cfg)  # same topology as the dataset
    offset = max((c["actor_id"] for c in gt["clusters"].values()), default=-1) + 1

    world = World(rng, cfg, id_offset=offset)
    world.t = max((_epoch(t["timestamp"]) for t in gt["transactions"].values()), default=world.t) + 60
    world.populate(params.get("n_counterparties", 25))  # fresh innocent counterparties

    txs = TYPOLOGIES[typology](world)

    formats = [f for f in WRITERS if (d / f"transactions.{f}").exists()]
    rate = params.get("relay_observation_rate", cfg["gossip"]["relay_observation_rate"])
    single = params.get("single_row", False)
    writers = open_writers(d, formats, cfg, append=True)
    rows = 0
    try:
        for tx in sorted(txs, key=lambda t: t.ts):
            actor = world.actor(tx.origin_actor)
            origin, kind = observed_origin(actor, net, rng, cfg)
            gt["transactions"][tx.txid] = {
                "pattern": tx.pattern, "typology": typology, "cluster_id": actor.cluster_id,
                "true_origin_ip": actor.home_ip.addr, "observed_origin_ip": origin.addr,
                "broadcast": kind, "timestamp": iso(tx.ts), "injected": True,
            }
            for row in relay_rows(tx, origin, net, rng, cfg, rate, single):
                for w in writers:
                    w.write(row)
                rows += 1
    finally:
        for w in writers:
            w.close()

    fresh = ground_truth(world, net, {}, Namespace(
        seed=seed, n_actors=len(world.actors), n_transactions=len(txs),
        relay_observation_rate=rate, single_row=single))
    gt["wallets"].update(fresh["wallets"])
    gt["clusters"].update(fresh["clusters"])
    gt["ips"]["true_broadcast"].update(fresh["ips"]["true_broadcast"])
    gt["ips"]["shared_nat"] = sorted(set(gt["ips"]["shared_nat"]) | set(fresh["ips"]["shared_nat"]))
    gt.setdefault("injections", []).append(
        {"typology": typology, "seed": seed, "params": params,
         "txids": [t.txid for t in txs], "clusters": sorted(fresh["clusters"])})
    (d / GROUND_TRUTH).write_text(json.dumps(gt, separators=(",", ":")))
    return {"typology": typology, "transactions": len(txs), "rows": rows,
            "clusters": sorted(fresh["clusters"]), "txids": [t.txid for t in txs]}
