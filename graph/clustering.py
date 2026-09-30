"""Wallet clustering: common-input-ownership + change-address heuristics.

Reimplemented in pure Python from BlockSci's *published* heuristic definitions
(`heuristics/change_address.cpp`, `tx_identification.cpp`) — read, not copied,
and nothing from vendor/ is imported. See docs/vendor_notes.md.

Two things carried over from BlockSci's design:
  * every sub-heuristic returns the set of outputs it *cannot rule out* as
    change, not a single pick — the vote happens afterwards;
  * a peeling chain is identified by its neighbours, not by its own shape alone.

One deliberate divergence: BlockSci's isCoinjoin assumes each participant
contributes a spend *and* a change output (most common value appears exactly
(n_out+1)//2 times), which misses equal-output rounds like Wasabi/Whirlpool
where every output is the same denomination. We test for a near-equal output
group instead, with the thresholds in config.yaml.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

import config

from .builder import Tx

# Address prefix -> script type. The only per-output type signal real dumps
# carry; the record-level script_type field describes the inputs being spent.
_PREFIXES = [("bc1p", "p2tr"), ("bc1q", "p2wpkh"), ("tb1q", "p2wpkh"),
             ("3", "p2sh"), ("2", "p2sh"), ("1", "p2pkh"), ("m", "p2pkh"), ("n", "p2pkh")]


def script_type_of(address: str) -> str:
    addr = str(address)
    for prefix, kind in _PREFIXES:
        if addr.startswith(prefix):
            # bech32 v0: 42 chars is a key hash, 62 a script hash
            if kind == "p2wpkh" and len(addr) > 50:
                return "p2wsh"
            return kind
    return ""


class DSU:
    """Union-find over wallet addresses."""

    def __init__(self):
        self.parent: dict[str, str] = {}
        self.rank: dict[str, int] = {}

    def add(self, x: str) -> str:
        self.parent.setdefault(x, x)
        self.rank.setdefault(x, 0)
        return x

    def find(self, x: str) -> str:
        self.add(x)
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:  # path compression
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a: str, b: str) -> str:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return ra
        if self.rank[ra] < self.rank[rb]:
            ra, rb = rb, ra
        self.parent[rb] = ra
        if self.rank[ra] == self.rank[rb]:
            self.rank[ra] += 1
        return ra

    def groups(self) -> dict[str, set[str]]:
        out: dict[str, set[str]] = {}
        for x in self.parent:
            out.setdefault(self.find(x), set()).add(x)
        return out


class TxIndex:
    """Who spends what — the cross-transaction context the heuristics need."""

    def __init__(self, txs: Iterable[Tx]):
        self.txs: dict[str, Tx] = {}
        self.spent_in: dict[str, str] = {}   # address -> txid that spends it
        self.created_in: dict[str, str] = {}  # address -> txid that first funded it
        for tx in txs:
            self.txs[tx.txid] = tx
            for addr in tx.input_addresses:
                self.spent_in.setdefault(addr, tx.txid)
            for addr in tx.output_addresses:
                self.created_in.setdefault(addr, tx.txid)

    def is_spent(self, address: str) -> bool:
        return address in self.spent_in

    def spending_tx(self, address: str) -> Tx | None:
        return self.txs.get(self.spent_in.get(address, ""))

    def funding_tx(self, address: str) -> Tx | None:
        return self.txs.get(self.created_in.get(address, ""))


# --- transaction identification -------------------------------------------
def looks_like_peeling(tx: Tx | None) -> bool:
    """BlockSci: a peeling chain link has exactly one input and two outputs."""
    return bool(tx) and len(tx.inputs) == 1 and len(tx.outputs) == 2


def is_peeling_chain(tx: Tx, idx: TxIndex) -> bool:
    """Peel-shaped, and a neighbour on either side is peel-shaped too."""
    if not looks_like_peeling(tx):
        return False
    if looks_like_peeling(idx.funding_tx(tx.input_addresses[0])):
        return True
    return any(looks_like_peeling(idx.spending_tx(a)) for a in tx.output_addresses)


def equal_value_group(values: list[float], tolerance: float) -> tuple[float, list[int]]:
    """Largest group of near-equal outputs: (value, indices)."""
    best: tuple[float, list[int]] = (0.0, [])
    for i, v in enumerate(values):
        same = [j for j, w in enumerate(values) if abs(w - v) <= tolerance * max(v, 1e-12)]
        if len(same) > len(best[1]):
            best = (v, same)
    return best


def is_coinjoin(tx: Tx, cfg: dict | None = None) -> bool:
    """Many inputs, many outputs, a big group sharing one value — skip
    common-input-ownership here or unrelated participants get merged."""
    c = (cfg or config.load())["graph"]["coinjoin"]
    n_in, n_out = len(tx.inputs), len(tx.outputs)
    if n_in < c["min_inputs"] or n_out < c["min_outputs"]:
        return False
    value, group = equal_value_group(tx.output_values, c["equal_value_tolerance"])
    if len(group) < c["min_equal_outputs"] or value <= c["dust_btc"]:
        return False
    return len(group) <= n_in  # no more participants than inputs


# --- heuristic 1: common input ownership ----------------------------------
def common_input_ownership(tx: Tx, cfg: dict | None = None) -> set[str]:
    """All inputs of one transaction are one entity — unless it is a CoinJoin."""
    if is_coinjoin(tx, cfg):
        return set()
    return set(tx.input_addresses)


# --- heuristic 2: change address, by majority vote ------------------------
# Each returns the OUTPUT INDICES it cannot rule out as change; an empty set
# means "no opinion" and casts no vote.

def h_address_reuse(tx: Tx, idx: TxIndex) -> set[int]:
    """An output paying back an input address is change (address reuse)."""
    inputs = set(tx.input_addresses)
    return {i for i, a in enumerate(tx.output_addresses) if a in inputs}


def h_address_type(tx: Tx, idx: TxIndex) -> set[int]:
    """If every input is one script type, change usually has that type too."""
    types = {script_type_of(a) or tx.script_type for a in tx.input_addresses}
    if len(types) != 1:
        return set()
    want = types.pop() or tx.script_type
    if not want:
        return set()
    matched = {i for i, a in enumerate(tx.output_addresses) if script_type_of(a) == want}
    return matched if len(matched) < len(tx.outputs) else set()  # all-match is no signal


def h_optimal_change(tx: Tx, idx: TxIndex) -> set[int]:
    """An output smaller than the smallest input: coin selection wouldn't have
    added that input if the change were bigger."""
    smallest_in = min(tx.input_values, default=0.0)
    matched = {i for i, v in enumerate(tx.output_values) if v < smallest_in}
    return matched if len(matched) < len(tx.outputs) else set()


def h_peeling_chain(tx: Tx, idx: TxIndex) -> set[int]:
    """In a peeling chain, change is the output that continues the chain.
    An unspent output cannot be ruled out (BlockSci does the same)."""
    if not is_peeling_chain(tx, idx):
        return set()
    out = set()
    for i, a in enumerate(tx.output_addresses):
        spender = idx.spending_tx(a)
        if spender is None or looks_like_peeling(spender):
            out.add(i)
    return out


HEURISTICS = {"address_reuse": h_address_reuse, "address_type": h_address_type,
              "optimal_change": h_optimal_change, "peeling_chain": h_peeling_chain}


def change_votes(tx: Tx, idx: TxIndex, cfg: dict | None = None) -> dict[int, int]:
    names = (cfg or config.load())["graph"]["change"]["heuristics"]
    votes: dict[int, int] = {}
    for name in names:
        for i in HEURISTICS[name](tx, idx):
            votes[i] = votes.get(i, 0) + 1
    return votes


def change_address_heuristic(tx: Tx, idx: TxIndex | None = None,
                             cfg: dict | None = None) -> str | None:
    """Best-guess change output, or None when the heuristics disagree or tie.

    Refusing to guess matters more than coverage: a wrong change link merges two
    entities permanently, and nothing downstream can undo it.
    """
    cfg = cfg or config.load()
    if len(tx.outputs) < 2 or is_coinjoin(tx, cfg):
        return None
    idx = idx if idx is not None else TxIndex([tx])
    votes = change_votes(tx, idx, cfg)
    if not votes:
        return None
    best = max(votes.values())
    winners = [i for i, v in votes.items() if v == best]
    if len(winners) != 1 or best < cfg["graph"]["change"]["min_votes"]:
        return None
    return tx.output_addresses[winners[0]]


# --- clustering -----------------------------------------------------------
@dataclass
class Clustering:
    wallet_to_cluster: dict[str, str] = field(default_factory=dict)
    clusters: dict[str, set[str]] = field(default_factory=dict)
    flags: dict[str, str] = field(default_factory=dict)      # cluster_id -> reason
    coinjoins: set[str] = field(default_factory=set)         # txids skipped
    change_outputs: dict[str, str] = field(default_factory=dict)  # txid -> address
    # Fingerprint corroboration (`corroborate`): every union, and the clusters
    # whose merges a fingerprint mismatch made less certain. Never a union.
    merges: list[dict] = field(default_factory=list)
    confidence: dict[str, float] = field(default_factory=dict)   # cluster_id -> min merge
    conflicts: dict[str, list[dict]] = field(default_factory=dict)

    def cluster_of(self, wallet: str) -> str | None:
        return self.wallet_to_cluster.get(wallet)

    def same_cluster(self, *wallets: str) -> bool:
        ids = {self.wallet_to_cluster.get(w) for w in wallets}
        return len(ids) == 1 and None not in ids

    @property
    def suspicious(self) -> list[str]:
        return sorted(self.flags)

    def summary(self) -> dict:
        sizes = sorted((len(v) for v in self.clusters.values()), reverse=True)
        return {"wallets": len(self.wallet_to_cluster), "clusters": len(self.clusters),
                "largest": sizes[0] if sizes else 0, "singletons": sum(s == 1 for s in sizes),
                "coinjoins_skipped": len(self.coinjoins),
                "change_links": len(self.change_outputs), "flagged": len(self.flags)}


def cluster_wallets(txs: Iterable[Tx], cfg: dict | None = None,
                    fingerprints: dict[str, str] | None = None) -> Clustering:
    """`fingerprints` (txid -> a confident fingerprint label) corroborates the
    merges; it never makes one. See `corroborate`."""
    cfg = cfg or config.load()
    g = cfg["graph"]
    txs = list(txs)
    idx = TxIndex(txs)
    dsu = DSU()
    result = Clustering()

    for tx in txs:
        for addr in tx.input_addresses + tx.output_addresses:
            dsu.add(addr)
        if is_coinjoin(tx, cfg):
            result.coinjoins.add(tx.txid)
            continue
        if g["common_input_ownership"]:
            inputs = sorted(common_input_ownership(tx, cfg))
            for addr in inputs[1:]:
                dsu.union(inputs[0], addr)
            if len(inputs) > 1:
                result.merges.append({"txid": tx.txid, "heuristic": "common_input_ownership",
                                      "wallets": inputs})
        if g["change_detection"]:
            change = change_address_heuristic(tx, idx, cfg)
            if change is not None and tx.input_addresses:
                result.change_outputs[tx.txid] = change
                dsu.union(tx.input_addresses[0], change)
                result.merges.append({"txid": tx.txid, "heuristic": "change_address",
                                      "wallets": [tx.input_addresses[0], change]})

    groups = dsu.groups()
    # A cluster is named after its smallest member, so ids are stable across runs
    result.clusters = {min(members): members for members in groups.values()}
    result.wallet_to_cluster = {w: cid for cid, members in result.clusters.items() for w in members}
    result.flags = cluster_collapse_guard(result.clusters, cfg)
    if fingerprints:
        corroborate(result, txs, fingerprints, cfg)
    return result


def corroborate(result: Clustering, txs: list[Tx], fingerprints: dict[str, str],
                cfg: dict | None = None) -> None:
    """Lower the confidence of a merge whose wallets were built by different software.

    Wallet software is usually consistent: the transactions spending one
    wallet's coins are built the same way. So for each union, the confident
    fingerprints of the transactions that spend the merged wallets are
    compared; two different families among them multiply that merge's
    confidence by `graph.fingerprint.mismatch_factor`. A cluster's confidence
    is its least confident merge.

    CORROBORATION ONLY. This reads `result.merges`, which the heuristics wrote,
    and changes no union: a mismatch can make a merge less certain, and a
    match can neither create a merge nor raise one above 1.0. `unknown`
    fingerprints are not in `fingerprints` and say nothing.
    """
    factor = (cfg or config.load())["graph"]["fingerprint"]["mismatch_factor"]
    spends: dict[str, set[str]] = {}
    for tx in txs:
        for addr in tx.input_addresses:
            spends.setdefault(addr, set()).add(tx.txid)
    for merge in result.merges:
        labels = {}
        for wallet in merge["wallets"]:
            for txid in spends.get(wallet, ()):
                if txid in fingerprints:
                    labels.setdefault(fingerprints[txid], []).append(txid)
        merge["fingerprints"] = {k: sorted(v) for k, v in sorted(labels.items())}
        merge["confidence"] = factor if len(labels) > 1 else 1.0
        cluster = result.wallet_to_cluster[merge["wallets"][0]]
        result.confidence[cluster] = min(result.confidence.get(cluster, 1.0),
                                         merge["confidence"])
        if len(labels) > 1:
            result.conflicts.setdefault(cluster, []).append(merge)


def cluster_collapse_guard(clusters: dict[str, set[str]], cfg: dict | None = None) -> dict[str, str]:
    """Flag oversized clusters instead of trusting them.

    One bad change guess on an exchange transaction can merge thousands of
    unrelated users; the answer is to mark it for review, not to drop it.
    """
    c = (cfg or config.load())["graph"]["collapse_guard"]
    limit, reason = c["max_cluster_wallets"], c["reason"]
    return {cid: reason for cid, members in clusters.items() if len(members) > limit}
