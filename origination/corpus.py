"""A labelled training corpus of single-vantage captures, from the gossip sim.

    python -m origination.pipeline corpus

The supervised model is only as good as the captures it learns from, and the
repo had two, both hand-written fixtures with no degenerate and no out-of-scope
transaction in them. This module turns `generator.net`'s gossip simulator into
thousands of captures that look, row for row, like what an observer node
writes: `RelayEvent`s, featurised by `features.relay.compute_relay_features`
exactly as a real capture would be. Nothing here computes a feature.

WHAT VARIES, AND WHY EACH ONE
Every value comes from `origination/manifest.json`, and every capture is a pure
function of that file, its seed and `config.yaml`'s `gossip:` block:

  topology    four graph families (below) x node count x relay share. A
              topology *configuration* is one (family, n_nodes, relay_share)
              triple; several graphs are drawn from each. The cross-topology
              test set holds out whole configurations.
  observers   one to three, placed six ways (below). Placement is what decides
              whether the true origin can appear among the candidates at all.
  loss        the share of announcements the observer fails to record.
  senders     how many distinct addresses broadcast in one capture, and the
              share of them holding a direct connection to an observer.

Topology families:

  relay_hub    `generator.net.build_net` unchanged: links prefer public relays.
  uniform      the same, with `relay_bias` 0 — relays are ordinary nodes.
  small_world  a connected Watts-Strogatz ring (networkx), k = peer_degree.
  scale_free   Barabasi-Albert (networkx); the relays are the best-connected nodes.

Observer placements:

  random       peer_degree links to random nodes.
  hub          three times that many — a monitoring node with spare slots.
  edge         peer_degree links to the least-connected non-relay nodes.
  leaf         one link. Almost every transaction arrives from one peer, so
               almost every row is degenerate (candidate_count 1).
  relay_only   links to known relays only. Every candidate is a relay, so the
               rows are scope_out unless a sender connects directly.
  isolated     no links into the network at all. The observer hears only from
               senders connected to it directly; every other transaction is
               never observed, which is the candidate_count 0 case — it has no
               row in the matrix, and is counted in the summary instead.

The last three exist because the model has to meet those cases, and a corpus
that never contained them could not show that it abstains on them.

WHAT IS LABELLED
`truth` is the address that injected the transaction into the network: the
sender's own address, or — for the Tor/hosting share set in
`generator.broadcast` — the anonymising node it broadcast through. That is
`observed_origin_ip` in `generator.main`'s ground truth, the thing an observer
could in principle identify. A row is positive iff its peer is that address.

WHAT IS NOT SIMULATED — quoted beside every number this corpus produces
(`OMISSIONS`).
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import random
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import networkx as nx
import pandas as pd

import config
from features.relay import RELAY_COLUMNS, compute_relay_features, relay_frame
from generator.main import node_intel
from generator.net import GossipNet, Ip, IpAllocator, build_net
from ingest.geoip import GeoIp
from ingest.ip_intel import IpIntel
from p2p.capture_reader import RelayEvent

log = logging.getLogger(__name__)

MANIFEST = Path(__file__).with_name("manifest.json")

#: The one sentence that sits next to every simulated number.
OMISSIONS = (
    "The simulator omits: any Dandelion/Dandelion++ stem phase (every broadcast "
    "diffuses from its first hop immediately), Bitcoin Core's per-peer Poisson INV "
    "trickling (one exponential delay per hop stands in for it), clock skew between "
    "observers, inbound/outbound connection asymmetry, peer churn during a capture, "
    "re-announcement, wtxid relay, user agents and real GeoIP; senders keep one "
    "address and one peer set for a whole capture, and the share of senders "
    "connected directly to an observer is a sampled parameter, not a measurement.")

#: Observer addresses: TEST-NET-2, never allocated to a simulated node.
_OBSERVER_PREFIX = "198.51.100."
#: Observers carry a private-use ASN so enrichment cannot mistake them for a pool.
_OBSERVER_ASN = 64496

PLACEMENTS = ("random", "hub", "edge", "leaf", "relay_only", "isolated")


# --- the manifest ---------------------------------------------------------
def load_manifest(path: Path | str | None = None) -> dict:
    return json.loads(Path(path or MANIFEST).read_text())


def digest(manifest: dict, cfg: dict) -> str:
    """Identity of a corpus: the manifest plus every config block it reads.

    A cached corpus is served only when this matches, so changing a gossip
    delay in config.yaml cannot leave a stale corpus in place.
    """
    blocks = {"manifest": manifest, "gossip": cfg["gossip"],
              "broadcast": cfg["generator"]["broadcast"],
              "asn_pools": cfg["generator"]["asn_pools"],
              "propagation": cfg["engines"]["propagation"]}
    return hashlib.sha256(json.dumps(blocks, sort_keys=True).encode()).hexdigest()[:16]


def _seed(*parts) -> int:
    """A stable integer seed. Never `hash()`: it is salted per process."""
    return int(hashlib.sha256("/".join(map(str, parts)).encode()).hexdigest()[:12], 16)


def topology_id(family: str, n_nodes: int, relay_share: float) -> str:
    return f"{family}-n{n_nodes}-r{relay_share}"


def expand(manifest: dict) -> list[dict]:
    """The manifest -> one spec per capture, in a fixed order.

    Every random draw here is seeded from the manifest seed and the capture's
    position, so the list is identical on every machine and in every process.
    """
    t, c = manifest["topology"], manifest["capture"]
    held_out = set(manifest["cross_topology_test"])
    placements, weights = zip(*c["placement"].items())
    specs = []
    for family in t["families"]:
        for n_nodes in t["n_nodes"]:
            for share in t["relay_share"]:
                topo = topology_id(family, n_nodes, share)
                for g in range(t["graphs_per_topology"]):
                    graph_seed = _seed(manifest["seed"], topo, g)
                    for k in range(c["per_graph"]):
                        capture_seed = _seed(manifest["seed"], topo, g, k)
                        rng = random.Random(capture_seed)
                        specs.append({
                            "capture_id": f"{topo}-g{g}-c{k:02d}",
                            "topology_id": topo, "family": family,
                            "n_nodes": n_nodes, "relay_share": share,
                            "graph_seed": graph_seed, "capture_seed": capture_seed,
                            "topology_split": "cross_test" if topo in held_out else "train",
                            "placement": rng.choices(placements, weights)[0],
                            "observer_count": rng.randint(*c["observer_count"]),
                            "message_loss": rng.choice(c["message_loss"]),
                            "sender_adjacency": round(rng.uniform(*c["sender_adjacency"]), 3),
                            "n_transactions": rng.randint(*c["n_transactions"]),
                            "n_senders": rng.randint(*c["senders"]),
                            "tx_interval_s": c["tx_interval_s"],
                        })
    unknown = held_out - {s["topology_id"] for s in specs}
    if unknown:
        raise ValueError(f"cross_topology_test names configurations the manifest "
                         f"does not generate: {sorted(unknown)}")
    return specs


# --- one graph ------------------------------------------------------------
def build_graph(spec: dict, cfg: dict) -> GossipNet:
    """One topology instance. Node addresses, kinds and relays always come from
    `build_net`; the two networkx families replace only the peer lists."""
    gossip = copy.deepcopy(cfg["gossip"])
    n = spec["n_nodes"]
    gossip.update(n_nodes=n, n_relays=max(1, round(n * spec["relay_share"])),
                  # every forward is simulated: the cap exists for generator.main's
                  # 12-hop NTRO-style samples, not for an observer's view
                  max_hops_per_tx=n * gossip["peer_degree"] * 4)
    if spec["family"] == "uniform":
        gossip["relay_bias"] = 0.0
    net = build_net(random.Random(spec["graph_seed"]), {**cfg, "gossip": gossip})
    k = gossip["peer_degree"]
    if spec["family"] == "small_world":
        g = nx.connected_watts_strogatz_graph(n, k, 0.1, seed=spec["graph_seed"] % 2**32)
        net.peers = [sorted(g.neighbors(i)) for i in range(n)]
    elif spec["family"] == "scale_free":
        g = nx.barabasi_albert_graph(n, max(1, k // 2), seed=spec["graph_seed"] % 2**32)
        # Relabel so the best-connected graph nodes are the ones build_net
        # made relays (and listed in node_intel): a hub is a public relay.
        by_degree = sorted(g.nodes, key=lambda v: (-g.degree(v), v))
        others = [i for i in range(n) if i not in set(net.relays)]
        mapping = dict(zip(by_degree, sorted(net.relays) + others))
        g = nx.relabel_nodes(g, mapping)
        net.peers = [sorted(g.neighbors(i)) for i in range(n)]
    return net


def _observer_links(placement: str, net: GossipNet, rng: random.Random) -> list[int]:
    n, k = len(net.nodes), net.cfg["peer_degree"]
    if placement == "random":
        return rng.sample(range(n), min(k, n))
    if placement == "hub":
        return rng.sample(range(n), min(3 * k, n))
    if placement == "edge":
        relays = set(net.relays)
        quiet = sorted((i for i in range(n) if i not in relays),
                       key=lambda i: (len(net.peers[i]), i))
        return rng.sample(quiet[:max(k, len(quiet) // 4)], min(k, len(quiet)))
    if placement == "leaf":
        return [rng.randrange(n)]
    if placement == "relay_only":
        return rng.sample(net.relays, min(k, len(net.relays)))
    if placement == "isolated":
        return []
    raise ValueError(f"unknown placement {placement!r}")


def _with_observers(net: GossipNet, spec: dict, rng: random.Random) -> tuple[GossipNet, list[int]]:
    """The graph with the observer nodes wired in. Observers relay like any
    node — a Bitcoin node that stopped relaying would be conspicuous."""
    nodes, peers = list(net.nodes), [list(p) for p in net.peers]
    observers = []
    for i in range(spec["observer_count"]):
        index = len(nodes)
        nodes.append(Ip(f"{_OBSERVER_PREFIX}{i + 2}", _OBSERVER_ASN, "observer", "ZZ",
                        "residential"))
        links = _observer_links(spec["placement"], net, rng)
        peers.append(sorted(links))
        for j in links:
            peers[j].append(index)
        observers.append(index)
    return GossipNet(nodes, [sorted(set(p)) for p in peers], net.relays, net.cfg,
                     random.Random(spec["capture_seed"] + 1)), observers


# --- one capture ----------------------------------------------------------
def simulate(spec: dict, cfg: dict) -> tuple[list[RelayEvent], dict[str, str], list[str], GossipNet]:
    """(events the observers logged, txid -> true origin, observer ips, net)."""
    rng = random.Random(spec["capture_seed"])
    net, observers = _with_observers(build_graph(spec, cfg), spec, rng)
    observer_set = set(observers)
    index = {ip.addr: i for i, ip in enumerate(net.nodes)}
    mean = net.cfg["delay_mean_ms"] / 1000.0
    broadcast = cfg["generator"]["broadcast"]

    # Senders draw addresses from the same residential pools as relaying
    # nodes, so no enrichment column can tell a sender from a forwarder.
    allocator = IpAllocator(rng, cfg)
    masked = {"tor": [i for i, x in enumerate(net.nodes) if x.kind == "tor_exit"],
              "hosting": [i for i, x in enumerate(net.nodes)
                          if x.kind == "hosting" and i not in set(net.relays)]}
    senders = []
    for _ in range(spec["n_senders"]):
        home = allocator.allocate("residential")
        while home.addr in index:
            home = allocator.allocate("residential")
        entries = net.origin_peers(rng)
        if observers and rng.random() < spec["sender_adjacency"]:
            entries = sorted(set(entries) | {rng.choice(observers)})
        senders.append((home, entries))

    events: list[RelayEvent] = []
    truth: dict[str, str] = {}
    t = 1_790_000_000.0
    for _ in range(spec["n_transactions"]):
        t += rng.expovariate(1.0 / spec["tx_interval_s"])
        home, entries = rng.choice(senders)
        roll = rng.random()
        pool = ("tor" if roll < broadcast["tor_rate"] else
                "hosting" if roll < broadcast["tor_rate"] + broadcast["hosting_rate"] else None)
        origin = home
        if pool and masked[pool]:
            # Broadcast through an anonymising node: that node's own links are
            # where the transaction enters the network, and its address is
            # what an observer could at best identify.
            relay_node = rng.choice(masked[pool])
            origin, entries = net.nodes[relay_node], net.peers[relay_node]
        txid = "%064x" % rng.getrandbits(256)
        truth[txid] = origin.addr
        events.extend(_observed(net, observer_set, origin, entries, t, txid, spec,
                                mean, index, rng))
    return events, truth, [net.nodes[i].addr for i in observers], net


def _observed(net, observers, origin, entries, t0, txid, spec, mean, index, rng):
    """What the observers log for one transaction.

    `diffuse` records only the hop that first reaches each node. An observer
    hears more than that: every neighbour that holds the transaction announces
    it, unless the observer was the one that told it. So the diffusion gives
    each node's infection time, and each observer's log is rebuilt from its
    neighbours' — the infecting hop at its own timestamp, the rest one
    forwarding delay after the neighbour received it.
    """
    hops = net.diffuse(origin, t0, rng, entries=entries)
    infected: dict[str, float] = {}
    told_by: dict[str, str] = {}
    for ts, src, dst in hops:
        if dst.addr not in infected:
            infected[dst.addr] = ts
            told_by[dst.addr] = src.addr
    out = []
    for obs in sorted(observers):
        me = net.nodes[obs].addr
        heard: dict[str, float] = {}
        for ts, src, dst in hops:                   # direct: the origin, or the infecting hop
            if dst.addr == me:
                heard[src.addr] = min(heard.get(src.addr, ts), ts)
        for peer in net.peers[obs]:
            addr = net.nodes[peer].addr
            if addr in infected and told_by.get(addr) != me and addr not in heard:
                heard[addr] = infected[addr] + rng.expovariate(1.0 / mean)
        for addr in sorted(heard):
            if rng.random() < spec["message_loss"]:
                continue
            out.append(RelayEvent(
                txid=txid, peer_ip=addr, peer_port=8333, peer_id=index.get(addr),
                user_agent=None, wall_clock_ts=round(heard[addr], 6),
                monotonic_or_derived_ts=round(heard[addr] - 1_790_000_000.0, 6),
                message_type="inv", direction="inbound",
                capture_source=f"sim:{spec['capture_id']}"))
    return out


class _SimDb(dict):
    """An mmdb-shaped reader over the simulated world's own ASN assignment, so
    enrichment is a function of the manifest and not of which GeoLite files
    happen to be on this machine."""


def _geoip(net: GossipNet, cfg: dict) -> GeoIp:
    country = _SimDb({n.addr: {"country": {"iso_code": n.country}} for n in net.nodes})
    asn = _SimDb({n.addr: {"autonomous_system_number": n.asn,
                           "autonomous_system_organization": n.asn_name} for n in net.nodes})
    return GeoIp(cfg, country_reader=country, asn_reader=asn)


def _intel(net: GossipNet, cfg: dict) -> IpIntel:
    """The simulated world's public node list, and nothing else.

    The real Bitnodes snapshot is deliberately not overlaid: a simulated
    address can collide with a real one, and a random collision would label a
    simulated node a relay for no reason in the simulation.
    """
    quiet = logging.getLogger("ingest.ip_intel")
    level = quiet.level
    quiet.setLevel(logging.ERROR)                  # the empty intel dir is intended
    try:
        return IpIntel(Path(os.devnull) / "none", cfg, synthetic=node_intel(net, cfg))
    finally:
        quiet.setLevel(level)


def featurise(spec: dict, cfg: dict | None = None) -> dict:
    """One capture -> its matrix rows (labelled), relay records and truth."""
    cfg = cfg or config.load()
    events, truth, observers, net = simulate(spec, cfg)
    if events:
        features, _ = compute_relay_features(events, spec["capture_id"], observers, cfg,
                                             intel=_intel(net, cfg), geoip=_geoip(net, cfg))
    else:
        # An isolated observer nobody connected to heard nothing. Preflight
        # would reject the empty capture; it is kept, as candidate_count 0 in
        # the truth table, because that is exactly the case being counted.
        features = pd.DataFrame(columns=RELAY_COLUMNS)
    features["originated"] = [truth.get(t) == p for t, p in
                              zip(features["txid"], features["peer_ip"])]
    features["topology_id"] = spec["topology_id"]
    usable = [e for e in events if e.peer_ip not in set(observers)]
    relay = relay_frame(usable, sorted(observers)[0])
    relay["capture_id"] = spec["capture_id"]
    candidates = features.groupby("txid")["peer_ip"].apply(set).to_dict()
    truth_rows = pd.DataFrame(
        [{"capture_id": spec["capture_id"], "txid": txid, "origin_ip": ip,
          "candidate_count": len(candidates.get(txid, ())),
          "origin_is_candidate": ip in candidates.get(txid, ())}
         for txid, ip in truth.items()])
    return {"features": features, "relay": relay, "truth": truth_rows,
            "observers": ",".join(observers)}


def _featurise_job(args):
    spec, cfg = args
    return featurise(spec, cfg)


# --- the whole corpus -----------------------------------------------------
def build(cfg: dict | None = None, manifest: dict | None = None, root: Path | None = None,
          rebuild: bool = False, workers: int | None = None) -> Path:
    """Generate (or reuse) the corpus; returns its directory.

    Cached under `origination.corpus_dir/<digest>`: identical manifest and
    config, identical files, so a cached corpus is always the one the manifest
    describes. Worker processes change the wall time, never the output — each
    capture is seeded from its own spec and results are gathered in order.
    """
    cfg = cfg or config.load()
    manifest = manifest or load_manifest()
    out = Path(root or cfg["origination"]["corpus_dir"]) / digest(manifest, cfg)
    if (out / "summary.json").exists() and not rebuild:
        return out
    specs = expand(manifest)
    jobs = [(spec, cfg) for spec in specs]
    workers = workers or min(len(jobs), os.cpu_count() or 1)
    if workers > 1:
        with ProcessPoolExecutor(workers) as pool:
            results = list(pool.map(_featurise_job, jobs, chunksize=8))
    else:
        results = [_featurise_job(job) for job in jobs]

    out.mkdir(parents=True, exist_ok=True)
    features = pd.concat([r["features"] for r in results], ignore_index=True)
    # Object columns that are all-null in the simulation (user agents, real
    # connection age) would otherwise be typed differently from run to run.
    for column in ("user_agent", "peer_port", "est_first_timestamp_rank",
                   "est_rumor_centrality_rank", "est_timestamp_weighted_centrality_rank"):
        if column in features:
            features[column] = features[column].astype("object" if column == "user_agent"
                                                        else "float64")
    captures = pd.DataFrame(specs).assign(observers=[r["observers"] for r in results])
    truth = pd.concat([r["truth"] for r in results], ignore_index=True)
    features.to_parquet(out / "matrix.parquet", index=False)
    pd.concat([r["relay"] for r in results], ignore_index=True).to_parquet(
        out / "relay.parquet", index=False)
    truth.to_parquet(out / "truth.parquet", index=False)
    captures.to_parquet(out / "captures.parquet", index=False)
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2))
    (out / "summary.json").write_text(json.dumps(summarise(features, truth, captures),
                                                 indent=2))
    return out


def load(directory: Path) -> dict:
    return {name: pd.read_parquet(directory / f"{name}.parquet")
            for name in ("matrix", "relay", "truth", "captures")}


def summarise(features: pd.DataFrame, truth: pd.DataFrame, captures: pd.DataFrame) -> dict:
    """The realised distribution, which is what the report quotes.

    Transaction-level, because degenerate and scope_out are properties of a
    transaction's candidate set. `candidate_count 0` exists only here: a
    transaction nobody announced to the observer has no row in the matrix.
    """
    per_tx = features.groupby(["capture_id", "txid"]).agg(
        degenerate=("degenerate", "first"), scope_out=("scope_out", "first"))
    counts = truth["candidate_count"]
    bins = {"0": int((counts == 0).sum()), "1": int((counts == 1).sum()),
            "2-4": int(counts.between(2, 4).sum()), "5-9": int(counts.between(5, 9).sum()),
            "10+": int((counts >= 10).sum())}
    observed = truth[truth["candidate_count"] > 0]
    return {
        "captures": len(captures),
        "topology_configurations": int(captures["topology_id"].nunique()),
        "graphs": int(captures[["topology_id", "graph_seed"]].drop_duplicates().shape[0]),
        "transactions_broadcast": len(truth),
        "transactions_observed": len(observed),
        "rows": len(features),
        "positive_rows": int(features["originated"].sum()),
        "candidate_count_distribution": bins,
        "degenerate_transactions": int(per_tx["degenerate"].sum()),
        "scope_out_transactions": int(per_tx["scope_out"].sum()),
        "origin_among_candidates": int(observed["origin_is_candidate"].sum()),
        "origin_among_candidates_share": round(float(observed["origin_is_candidate"].mean()), 4)
        if len(observed) else None,
        "captures_by_placement": captures["placement"].value_counts().sort_index().to_dict(),
        "captures_by_family": captures["family"].value_counts().sort_index().to_dict(),
        "captures_by_topology_split": captures["topology_split"].value_counts()
        .sort_index().to_dict(),
    }
