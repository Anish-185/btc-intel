"""Bitcoin-specific typologies.

Structure follows AMLSim's `add_aml_typology` (sample members -> add labelled
edges over a time window -> record the pattern as ground truth), reimplemented
for UTXO transactions: many-to-many inputs/outputs, change addresses, peeling
chains and CoinJoin equal-value structure, none of which AMLSim's account model
has. See docs/vendor_notes.md.

Every typology returns a list of Tx; the actors it creates carry the label.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

import config

from .net import Ip, IpAllocator


# Address shapes per script type: (prefix, body length). Real dumps carry this
# variety and the change-address heuristics depend on it.
ADDRESS_FORMS = {"p2pkh": ("1", 33), "p2sh": ("3", 33), "p2wpkh": ("bc1q", 38),
                 "p2wsh": ("bc1q", 58), "p2tr": ("bc1p", 58)}


@dataclass
class Actor:
    """One real-world entity. Its wallets are, by definition, one cluster."""

    actor_id: int
    pattern: str
    home_ip: Ip
    script_type: str = "p2wpkh"  # one wallet implementation per actor
    wallets: list[str] = field(default_factory=list)
    shared_ip: bool = False  # innocent NAT/VPN co-tenancy, not evidence

    @property
    def cluster_id(self) -> str:
        return f"C{self.actor_id:06d}"


@dataclass
class Tx:
    txid: str
    ts: float
    inputs: list[tuple[str, float]]
    outputs: list[tuple[str, float]]
    fee: float
    script_type: str
    origin_actor: int
    pattern: str


class World:
    """Actors, wallets and the clock. Typologies allocate everything through it."""

    def __init__(self, rng: random.Random, cfg: dict | None = None, id_offset: int = 0):
        self.cfg = cfg or config.load()
        self.id_offset = id_offset  # non-zero when appending to an existing dataset
        self.gen = self.cfg["generator"]
        self.rng = rng
        self.alloc = IpAllocator(rng, self.cfg)
        self.actors: list[Actor] = []
        self.wallet_owner: dict[str, int] = {}
        self.nat_ips: list[Ip] = []
        self.base_actors: list[int] = []
        self.exchanges: list[int] = []
        self.t = 0.0

    # --- allocation -------------------------------------------------------
    def new_actor(self, pattern: str, shared_ip: bool = False) -> Actor:
        ip = self.rng.choice(self.nat_ips) if (shared_ip and self.nat_ips) else self.alloc.allocate()
        a = Actor(len(self.actors) + self.id_offset, pattern, ip,
                  script_type=self.script_type(), shared_ip=shared_ip)
        self.actors.append(a)
        return a

    def actor(self, actor_id: int) -> Actor:
        return self.actors[actor_id - self.id_offset]

    def new_wallet(self, actor: Actor) -> str:
        prefix, length = ADDRESS_FORMS[actor.script_type]
        addr = prefix + f"{self.rng.getrandbits(4 * length):0{length}x}"
        actor.wallets.append(addr)
        self.wallet_owner[addr] = actor.actor_id
        return addr

    def wallet_of(self, actor: Actor) -> str:
        return self.rng.choice(actor.wallets) if actor.wallets else self.new_wallet(actor)

    def script_type(self) -> str:
        return self.rng.choices(self.gen["script_types"], self.gen["script_type_weights"])[0]

    def maybe_round(self, amount: float, rate: float | None = None) -> float:
        """Humans type round numbers; coin selection does not."""
        if self.rng.random() >= (self.gen["round_payment_rate"] if rate is None else rate):
            return amount
        unit = self.rng.choice([u for u in self.gen["round_units"] if u <= max(amount, 0.01)])
        return round(max(round(amount / unit) * unit, unit), 8)

    def fee(self) -> float:
        lo, hi = self.gen["fee_btc"]
        return round(self.rng.uniform(lo, hi), 8)

    def txid(self) -> str:
        return f"{self.rng.getrandbits(256):064x}"

    def tick(self) -> float:
        """Advance the clock by an exponential inter-transaction gap."""
        self.t += self.rng.expovariate(1.0 / self.gen["seconds_between_txs"])
        return self.t

    def tx(self, actor: Actor, inputs, outputs, pattern: str, ts: float | None = None) -> Tx:
        # script_type describes the inputs being spent, i.e. the spender's wallet
        return Tx(self.txid(), self.tick() if ts is None else ts, inputs, outputs,
                  self.fee(), actor.script_type, actor.actor_id, pattern)

    def populate(self, n_actors: int) -> None:
        """Build the standing population of ordinary wallets and exchanges."""
        g = self.gen
        self.nat_ips = [self.alloc.allocate() for _ in range(g["nat_pool_size"])]
        lo, hi = g["wallets_per_actor"]
        for _ in range(n_actors):
            shared = self.rng.random() < g["nat_share_rate"]
            a = self.new_actor("normal", shared_ip=shared)
            for _ in range(self.rng.randint(lo, hi)):
                self.new_wallet(a)
            self.base_actors.append(a.actor_id)
        for aid in self.rng.sample(self.base_actors, max(1, int(n_actors * g["exchange_share"]))):
            self.actor(aid).pattern = "exchange"
            self.exchanges.append(aid)
            for _ in range(20):  # exchanges hold many deposit addresses
                self.new_wallet(self.actor(aid))

    def pick_base(self) -> Actor:
        return self.actor(self.rng.choice(self.base_actors))


# --- typologies -----------------------------------------------------------
# Each returns the transactions of ONE instance. `normal` is one transaction.


def normal(w: World) -> list[Tx]:
    """Legitimate payment: 1-3 inputs, a recipient and usually a change output."""
    src = w.pick_base()
    # a third of ordinary payments go to an exchange deposit address
    dst = w.actor(w.rng.choice(w.exchanges)) if (w.exchanges and w.rng.random() < 0.33) else w.pick_base()
    if dst.actor_id == src.actor_id:
        return []
    n_in = w.rng.choices([1, 2, 3], [0.7, 0.2, 0.1])[0]
    inputs = [(w.wallet_of(src), round(w.rng.lognormvariate(-1.5, 1.3), 8)) for _ in range(n_in)]
    total = sum(v for _, v in inputs)
    pay = w.maybe_round(round(total * w.rng.uniform(0.15, 0.95), 8))
    pay = min(pay, round(total - w.fee(), 8))
    outputs = [(w.wallet_of(dst), pay)]
    change = round(total - pay - w.fee(), 8)
    if change > 1e-6:
        outputs.append((w.new_wallet(src), change))  # fresh change address
    w.rng.shuffle(outputs)
    return [w.tx(src, inputs, outputs, "normal")]


def ransomware_collector(w: World) -> list[Tx]:
    """Many victims pay one collector, which peels off small cash-outs."""
    p = w.gen["typology_params"]["ransomware_collector"]
    actor = w.new_actor("ransomware_collector")
    collector = w.new_wallet(actor)
    txs, pot = [], 0.0
    for _ in range(w.rng.randint(*p["victims"])):
        victim = w.new_actor("ransomware_victim")
        amount = w.maybe_round(round(w.rng.uniform(*p["ransom_btc"]), 8),
                               rate=p["round_ransom_rate"])
        pot += amount
        txs.append(w.tx(victim, [(w.new_wallet(victim), amount)], [(collector, amount)],
                        "ransomware_victim_payment"))
    # Peeling chain: each hop sends a small slice out and the rest to fresh change.
    held = pot
    for _ in range(w.rng.randint(*p["peel_hops"])):
        if held <= 1e-4:
            break
        peel = round(held * w.rng.uniform(*p["peel_fraction"]), 8)
        cashout = w.new_actor("cashout")
        change = w.new_wallet(actor)
        txs.append(w.tx(actor, [(collector, held)],
                        [(w.new_wallet(cashout), peel), (change, round(held - peel, 8))],
                        "ransomware_peel"))
        collector, held = change, held - peel
    return txs


def layering(w: World) -> list[Tx]:
    """Fan-out into intermediates, several hops, then fan back in."""
    p = w.gen["typology_params"]["layering"]
    fan, depth = w.rng.randint(*p["fan"]), w.rng.randint(*p["depth"])
    source = w.new_actor("layering")
    amount = round(w.rng.uniform(*p["amount_btc"]), 8)
    txs = []
    layer = [(w.new_wallet(source), amount)]
    for _ in range(depth):
        nxt = []
        for addr, amt in layer:
            splits = [w.rng.random() for _ in range(fan)]
            scale = amt * 0.98 / sum(splits)
            outs = []
            for s in splits:
                hop = w.new_actor("layering")
                a = w.new_wallet(hop)
                outs.append((a, round(s * scale, 8)))
            txs.append(w.tx(source, [(addr, amt)], outs, "layering_split"))
            nxt.extend(outs)
        # keep the width bounded; carry the largest branches forward
        layer = sorted(nxt, key=lambda o: -o[1])[:fan]
    sink = w.new_actor("layering")
    merged = round(sum(a for _, a in layer) * 0.98, 8)
    txs.append(w.tx(source, list(layer), [(w.new_wallet(sink), merged)], "layering_merge"))
    return txs


def same_actor_cluster(w: World) -> list[Tx]:
    """One actor, several wallets, all broadcast from one IP in a short window.

    The clustering + IP-correlation engines should merge these; the innocent
    NAT/VPN actors sharing an IP are the counter-example they must not merge.
    """
    p = w.gen["typology_params"]["same_actor_cluster"]
    actor = w.new_actor("same_actor_cluster")
    t0 = w.tick()
    txs = []
    for _ in range(w.rng.randint(*p["wallets"])):
        src = w.new_wallet(actor)
        amt = round(w.rng.uniform(*p["amount_btc"]), 8)
        dst = w.pick_base()
        ts = t0 + w.rng.uniform(0, p["window_seconds"])
        txs.append(w.tx(actor, [(src, amt)], [(w.wallet_of(dst), round(amt * 0.99, 8))],
                        "same_actor_cluster", ts=ts))
    return txs


def coinjoin(w: World) -> list[Tx]:
    """One transaction, equal-value inputs and outputs from unrelated wallets.

    Common-input-ownership must NOT fire here — that is the point of the test.
    """
    p = w.gen["typology_params"]["coinjoin"]
    denom = w.rng.choice(p["denomination_btc"])
    n = w.rng.randint(*p["participants"])
    participants = [w.pick_base() for _ in range(n)]
    inputs = [(w.wallet_of(a), denom) for a in participants]
    outputs = [(w.new_wallet(a), round(denom * 0.999, 8)) for a in participants]
    w.rng.shuffle(outputs)
    return [w.tx(participants[0], inputs, outputs, "coinjoin")]


TYPOLOGIES = {
    "normal": normal,
    "ransomware_collector": ransomware_collector,
    "layering": layering,
    "same_actor_cluster": same_actor_cluster,
    "coinjoin": coinjoin,
}
