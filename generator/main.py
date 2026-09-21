"""CLI: synthesise an NTRO-schema dataset plus a hidden ground truth.

    python -m generator.main --n-actors 5000 --n-transactions 200000 \
        --output data/raw/ --formats csv,json,xml --seed 42

ground_truth.json is NOT part of the public dataset — only eval/ reads it.
"""

from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timezone
from pathlib import Path

import config

from .net import GossipNet, Ip, build_net
from .typologies import TYPOLOGIES, Tx, World
from .writers import open_writers

GROUND_TRUTH = "ground_truth.json"


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def observed_origin(actor, net: GossipNet, rng: random.Random, cfg: dict) -> tuple[Ip, str]:
    """Where the broadcast *appears* to come from. Tor/hosting masks the truth."""
    b = cfg["generator"]["broadcast"]
    r = rng.random()
    if r < b["tor_rate"]:
        pool = [n for n in net.nodes if n.kind == "tor_exit"]
        if pool:
            return rng.choice(pool), "tor"
    elif r < b["tor_rate"] + b["hosting_rate"]:
        pool = [n for n in net.nodes if n.kind == "hosting"]
        if pool:
            return rng.choice(pool), "hosting"
    return actor.home_ip, "home"


def relay_rows(tx: Tx, origin: Ip, net: GossipNet, rng: random.Random, cfg: dict,
               observation_rate: float, single_row: bool):
    """One record per observed gossip hop, so a txid recurs across rows."""
    g = cfg["gossip"]
    hops = net.diffuse(origin, tx.ts, rng)
    if single_row:
        hops = hops[:1]                      # NTRO dumps without multi-hop records
    else:
        seen = [h for h in hops if rng.random() < observation_rate]
        hops = seen or [rng.choice(hops)]    # never let a tx vanish entirely
    lo, hi = g["ephemeral_ports"]
    in_addr = [a for a, _ in tx.inputs]
    in_amt = [v for _, v in tx.inputs]
    out_addr = [a for a, _ in tx.outputs]
    out_amt = [v for _, v in tx.outputs]
    for ts, src, dst in hops:
        yield {
            "timestamp": iso(ts), "src_ip": src.addr, "dst_ip": dst.addr,
            "src_port": rng.randint(lo, hi), "dst_port": g["p2p_port"],
            "tx_id": tx.txid, "input_addresses": in_addr, "output_addresses": out_addr,
            "input_amounts": in_amt, "output_amounts": out_amt, "fee": tx.fee,
            "script_type": tx.script_type, "geo_country": src.country, "asn": src.asn,
        }


def spread_instance(txs, name: str, rng: random.Random, cfg: dict) -> None:
    """Scatter one instance's transactions over a window, preserving order.

    Emitted back-to-back, a typology's transactions are separated by seconds
    while ordinary wallets re-spend hours apart — so the gap alone identifies
    the pattern and anything trained on it learns the simulator, not Bitcoin.
    """
    g = cfg["generator"]
    factor = g["typology_params"].get(name, {}).get("spread_factor", g["typology_spread_factor"])
    if len(txs) < 2 or not factor:
        return
    ordered = sorted(txs, key=lambda t: t.ts)
    t0 = ordered[0].ts
    window = len(txs) * g["seconds_between_txs"] * factor
    for tx, offset in zip(ordered, sorted(rng.uniform(0, window) for _ in txs)):
        tx.ts = t0 + offset   # order is preserved, so peel chains stay causal


def pick_typology(produced: dict[str, int], targets: dict[str, float]) -> str:
    """Whichever typology is furthest below its share of the transaction budget."""
    return min(targets, key=lambda k: produced[k] / targets[k] if targets[k] else float("inf"))


def ground_truth(world: World, net: GossipNet, tx_meta: dict, args) -> dict:
    by_kind: dict[str, list[str]] = {"residential": [], "hosting": [], "tor_exit": []}
    for n in net.nodes:
        by_kind[n.kind].append(n.addr)
    return {
        "seed": args.seed,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "params": {"n_actors": args.n_actors, "n_transactions": args.n_transactions,
                   "relay_observation_rate": args.relay_observation_rate,
                   "single_row": args.single_row},
        # cluster_id per wallet — the answer our clustering has to reconstruct
        "wallets": {addr: world.actor(aid).cluster_id for addr, aid in world.wallet_owner.items()},
        "clusters": {
            a.cluster_id: {
                "pattern_type": a.pattern,
                "actor_id": a.actor_id,
                "wallets": a.wallets,
                "true_broadcast_ip": a.home_ip.addr,
                "script_type": a.script_type,
                "asn": a.home_ip.asn,
                "shared_ip": a.shared_ip,  # innocent NAT/VPN co-tenancy
            }
            for a in world.actors if a.wallets
        },
        "transactions": tx_meta,
        "ips": {
            "relay": [net.nodes[i].addr for i in net.relays],
            "tor_exit": by_kind["tor_exit"],
            "hosting": by_kind["hosting"],
            "residential": by_kind["residential"],
            # multiple unrelated actors broadcast from these — co-occurrence here is noise
            "shared_nat": sorted({a.home_ip.addr for a in world.actors if a.shared_ip}),
            "true_broadcast": {a.cluster_id: a.home_ip.addr for a in world.actors if a.wallets},
        },
    }


def generate(args, cfg: dict | None = None) -> dict:
    cfg = cfg or config.load()
    rng = random.Random(args.seed)
    net = build_net(random.Random(args.seed + 1), cfg)  # topology stable across runs

    world = World(rng, cfg)
    world.t = datetime.fromisoformat(cfg["generator"]["start_time"].replace("Z", "+00:00")).timestamp()
    world.populate(args.n_actors)

    mix = cfg["generator"]["pattern_mix"]
    total = sum(mix.values())
    targets = {k: v / total * args.n_transactions for k, v in mix.items()}
    produced = {k: 0 for k in mix}
    tx_meta: dict[str, dict] = {}
    out_dir = Path(args.output)
    writers = open_writers(out_dir, args.formats, cfg)
    n_rows = 0
    try:
        while sum(produced.values()) < args.n_transactions:
            name = pick_typology(produced, targets)
            txs = TYPOLOGIES[name](world)
            spread_instance(txs, name, rng, cfg)
            produced[name] += len(txs)
            for tx in sorted(txs, key=lambda t: t.ts):
                actor = world.actor(tx.origin_actor)
                origin, kind = observed_origin(actor, net, rng, cfg)
                tx_meta[tx.txid] = {
                    "pattern": tx.pattern, "typology": name, "cluster_id": actor.cluster_id,
                    "true_origin_ip": actor.home_ip.addr, "observed_origin_ip": origin.addr,
                    "broadcast": kind, "timestamp": iso(tx.ts),
                }
                for row in relay_rows(tx, origin, net, rng, cfg,
                                      args.relay_observation_rate, args.single_row):
                    for wr in writers:
                        wr.write(row)
                    n_rows += 1
    finally:
        for wr in writers:
            wr.close()

    gt = ground_truth(world, net, tx_meta, args)
    (out_dir / GROUND_TRUTH).write_text(json.dumps(gt, separators=(",", ":")))
    return {"transactions": len(tx_meta), "rows": n_rows, "per_typology": produced,
            "actors": len(world.actors), "wallets": len(world.wallet_owner),
            "output": str(out_dir)}


def build_parser() -> argparse.ArgumentParser:
    g = config.get("gossip")
    p = argparse.ArgumentParser(prog="generator.main", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--n-actors", type=int, default=5000)
    p.add_argument("--n-transactions", type=int, default=200000)
    p.add_argument("--output", default=config.get("ingest.input_dir"))
    p.add_argument("--formats", default="csv,json,xml",
                   type=lambda s: [f.strip() for f in s.split(",") if f.strip()])
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--relay-observation-rate", type=float, default=g["relay_observation_rate"],
                   help="fraction of gossip hops that appear in the output")
    p.add_argument("--single-row", action="store_true",
                   help="one row per txid (origin broadcast only) — no multi-hop records")
    return p


def main(argv=None) -> None:
    args = build_parser().parse_args(argv)
    summary = generate(args)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
