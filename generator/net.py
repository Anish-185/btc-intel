"""Network layer: ASN-backed IP allocation and Bitcoin-style gossip diffusion.

The blockchain-only reference implementations in vendor/ have no equivalent of
this module (see docs/vendor_notes.md) — it is the half of the data SIH26146
actually turns on.
"""

from __future__ import annotations

import heapq
import random
from dataclasses import dataclass, field

import config


@dataclass(frozen=True)
class Ip:
    addr: str
    asn: int
    asn_name: str
    country: str
    kind: str  # residential | hosting | tor_exit | onion


class IpAllocator:
    """Hands out unique IPs from the example ASN ranges in config.yaml."""

    def __init__(self, rng: random.Random, cfg: dict | None = None):
        self.rng = rng
        self.pools = (cfg or config.load())["generator"]["asn_pools"]
        self._seen: set[str] = set()

    def allocate(self, kind: str = "residential") -> Ip:
        pool = self.rng.choice(self.pools[kind])
        for _ in range(100):
            addr = f"{pool['prefix']}.{self.rng.randint(0, 255)}.{self.rng.randint(1, 254)}"
            if addr not in self._seen:
                break
        self._seen.add(addr)
        return Ip(addr, pool["asn"], pool["name"], pool["country"], kind)

    def allocate_onion(self) -> Ip:
        """A Tor v3 hidden-service address: 56 base32 characters. It has no ASN
        and no country — that absence is the point of it."""
        alphabet = "abcdefghijklmnopqrstuvwxyz234567"
        addr = "".join(self.rng.choice(alphabet) for _ in range(56)) + ".onion"
        self._seen.add(addr)
        return Ip(addr, 0, "tor", "ZZ", "onion")


@dataclass
class GossipNet:
    """~500 simulated Bitcoin nodes; a few dozen high-degree public relays."""

    nodes: list[Ip]
    peers: list[list[int]]
    relays: list[int]
    cfg: dict
    rng: random.Random
    _by_addr: dict[str, Ip] = field(default_factory=dict)

    def __post_init__(self):
        self._by_addr = {n.addr: n for n in self.nodes}

    def ip(self, addr: str) -> Ip | None:
        return self._by_addr.get(addr)

    def entry_node(self) -> int:
        """The node a wallet hands its transaction to — relays are likelier."""
        if self.relays and self.rng.random() < self.cfg["relay_bias"]:
            return self.rng.choice(self.relays)
        return self.rng.randrange(len(self.nodes))

    def origin_peers(self, rng: random.Random) -> list[int]:
        """How many peers the sender announces to.

        A sender is a node, not a pendant leaf: Bitcoin Core opens 8 outbound
        connections by default and announces to all of them. Modelling the
        origin with a single link made it a degree-1 leaf of every propagation
        tree, which quietly decided the estimator comparison — a centrality
        estimator cannot find a source the topology has placed at the rim.
        """
        light = rng.random() < self.cfg["light_client_share"]
        lo, hi = self.cfg["light_client_peers" if light else "origin_peers"]
        count = rng.randint(lo, hi)
        peers, seen = [], set()
        while len(peers) < count:
            node = self.entry_node()
            if node not in seen:
                seen.add(node)
                peers.append(node)
            elif len(seen) >= len(self.nodes):
                break
        return peers

    def stem(self, origin: Ip, t0: float, rng: random.Random, entries: list[int],
             length: int) -> tuple[list[tuple[float, Ip, Ip]], int, float]:
        """Dandelion stem phase, in BIP-156's shape: the sender hands the
        transaction to ONE peer, and each stem node forwards it to one peer of
        its own, `length` hops in all; the last one fluffs (`diffuse` from it).

        Returns (stem hops, the fluff node, the time it holds the transaction).
        Simplifications, all named in docs/VALIDITY.md: the stem successor is a
        fresh uniform draw per hop rather than one of two per-epoch Dandelion
        destinations, stem hops use the ordinary per-hop delay, the length is
        drawn by the caller rather than by a per-hop coin at each node, and
        there is no embargo timer — a stem is never lost.
        """
        mean = self.cfg["delay_mean_ms"] / 1000.0
        node = rng.choice(entries)
        t = t0 + rng.expovariate(1.0 / mean)
        hops = [(t, origin, self.nodes[node])]
        path = {node}
        for _ in range(length - 1):
            options = [p for p in self.peers[node] if p not in path]
            if not options:
                break
            nxt = rng.choice(options)
            t += rng.expovariate(1.0 / mean)
            hops.append((t, self.nodes[node], self.nodes[nxt]))
            path.add(nxt)
            node = nxt
        return hops, node, t

    def diffuse(self, origin: Ip, t0: float, rng: random.Random,
                entries: list[int] | None = None) -> list[tuple[float, Ip, Ip]]:
        """Bitcoin-ish diffusion: exponential per-hop delay, breadth over peers.

        Returns hops as (timestamp, from_ip, to_ip). The origin announces to
        each of its own peers first, so it sits at the centre of its immediate
        neighbourhood rather than dangling off a single edge.

        `entries` pins the origin's peers. A sender keeps its connections from
        one transaction to the next, so a caller simulating several
        transactions from one sender passes the same list each time; left out,
        a fresh set is drawn per transaction, which is what `generator.main`
        has always done.
        """
        mean = self.cfg["delay_mean_ms"] / 1000.0
        budget = self.cfg["max_hops_per_tx"]
        entries = self.origin_peers(rng) if entries is None else entries
        hops = []
        seen: set[int] = set()
        queue = []
        for node in entries:
            t = t0 + rng.expovariate(1.0 / mean) * 0.25   # announcements are near-simultaneous
            hops.append((t, origin, self.nodes[node]))
            seen.add(node)
            queue.append((t, node))
        heapq.heapify(queue)
        while queue and len(hops) < budget:
            t, node = heapq.heappop(queue)
            for peer in self.peers[node]:
                if peer in seen:
                    continue
                t_peer = t + rng.expovariate(1.0 / mean)
                hops.append((t_peer, self.nodes[node], self.nodes[peer]))
                seen.add(peer)
                heapq.heappush(queue, (t_peer, peer))
                if len(hops) >= budget:
                    break
        hops.sort(key=lambda h: h[0])
        return hops


def build_net(rng: random.Random, cfg: dict | None = None) -> GossipNet:
    cfg = cfg or config.load()
    g = cfg["gossip"]
    alloc = IpAllocator(rng, cfg)
    n, n_relays = g["n_nodes"], g["n_relays"]

    kinds = ["residential"] * n
    for i in range(n):
        r = rng.random()
        if r < g["tor_node_share"]:
            kinds[i] = "tor_exit"
        elif r < g["tor_node_share"] + g["hosting_node_share"]:
            kinds[i] = "hosting"
    relays = rng.sample(range(n), n_relays)
    for i in relays:
        kinds[i] = g["relay_asn_pool"]  # public relays sit in hosting ASNs
    nodes = [alloc.allocate(k) for k in kinds]

    # Peer graph: every node picks `peer_degree` peers, biased towards relays,
    # which is what gives relays their high degree.
    peers: list[set[int]] = [set() for _ in range(n)]
    for i in range(n):
        while len(peers[i]) < g["peer_degree"]:
            j = rng.choice(relays) if rng.random() < g["relay_bias"] else rng.randrange(n)
            if j != i:
                peers[i].add(j)
                peers[j].add(i)
    return GossipNet(nodes, [sorted(p) for p in peers], relays, g, rng)
