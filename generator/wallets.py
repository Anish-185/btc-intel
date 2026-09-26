"""Wallet-construction profiles: how a transaction is built, not what it pays.

Each profile sets the tells `features/fingerprint.py` reads — tx version,
nLockTime, nSequence, BIP-69 ordering, change position, fee-rate rounding,
script types and change-address type — from the probability maps under
`generator.wallet_profiles` in config.yaml. The profiles are this simulation's
stand-ins for the families they are named after. docs/FINGERPRINTS.md says,
tell by tell, which parts are documented behaviour and which are assumptions.

OFF BY DEFAULT, AND OFF MEANS UNTOUCHED
Nothing here runs unless a caller asks for profiles, and every draw comes from
the `rng` the caller passes, which must be a stream of its own. So a corpus or
dataset generated with profiles off is byte-identical to one generated before
this module existed; tests/test_fingerprint.py pins it.
"""

from __future__ import annotations

import hashlib
import math
import random

from features.fingerprint import SATS, estimated_vsize, script_type_of

from .typologies import ADDRESS_FORMS

PROFILES = ("core_like", "electrum_like", "legacy_naive", "coordinator_coinjoin",
            "batch_withdrawal")
#: Transaction shapes that decide the profile rather than the sender's wallet.
SHAPE_PROFILE = {"coinjoin": "coordinator_coinjoin", "batch": "batch_withdrawal"}
DUST_SATS = 546
FINAL, LOCKTIME_ONLY, RBF = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD


def draw(rng: random.Random, weights: dict):
    keys = list(weights)
    return rng.choices(keys, [weights[k] for k in keys])[0]


def payment_profile(rng: random.Random, cfg: dict) -> str:
    """The wallet an ordinary sender uses, drawn once per sender."""
    return draw(rng, cfg["generator"]["wallet_profiles"]["payment_mix"])


def height_at(ts: float, t0: float, cfg: dict) -> int:
    """The chain tip at `ts`, ten minutes a block from `start_height` at `t0`."""
    return int(cfg["generator"]["wallet_profiles"]["start_height"] + max(ts - t0, 0) // 600)


def typed(address: str, script_type: str) -> str:
    """A stable address of the given script type standing in for `address`."""
    prefix, length = ADDRESS_FORMS[script_type]
    return prefix + hashlib.sha256(address.encode()).hexdigest()[:length]


# --- the construction itself --------------------------------------------------
def _fee_sats(policy: str, vsize: int, rng: random.Random) -> int:
    if policy == "absolute":                 # a round fee typed in BTC, not a rate
        return rng.choice([10_000, 20_000, 50_000])
    if policy == "round":                    # a round sat/vB
        return rng.choice([5, 10, 15, 20, 25, 50]) * vsize
    rate = rng.lognormvariate(math.log(12), 0.6)
    if policy == "integer":
        return max(1, round(rate)) * vsize
    return max(vsize, round(round(rate, 3) * vsize))   # fractional


def build(inputs: list[tuple[str, float]], outputs: list[tuple[str, float]],
          change: dict[int, int | None], profile: str, rng: random.Random,
          height: int, cfg: dict) -> dict:
    """Finish a transaction under `profile`.

    `change` maps each change output's index to the input index that funds it
    (a CoinJoin participant's own change), or None for the one change output
    of an ordinary spend. Change values are recomputed so that the fee follows
    the profile's fee policy; a change output that would fall below dust is
    dropped and its value left to the fee, as a wallet would.
    """
    p = cfg["generator"]["wallet_profiles"]["profiles"][profile]
    in_sats = [round(v * SATS) for _, v in inputs]
    outs = [[a, round(v * SATS), i in change, change.get(i)] for i, (a, v) in enumerate(outputs)]
    vsize = estimated_vsize([script_type_of(a) for a, _ in inputs],
                            [script_type_of(o[0]) for o in outs])
    fee = _fee_sats(draw(rng, p["fee"]), vsize, rng)
    owned = [o for o in outs if o[2] and o[3] is not None]
    single = [o for o in outs if o[2] and o[3] is None]
    if owned:                                  # CoinJoin: each participant pays a share
        paid = {i: sum(o[1] for o in outs if not o[2]) / max(len(inputs), 1)
                for i in range(len(inputs))}
        share = fee / len(inputs)
        for o in owned:
            o[1] = int(in_sats[o[3]] - paid[o[3]] - share)
    if single:
        rest = sum(in_sats) - sum(o[1] for o in outs if o is not single[0])
        single[0][1] = int(rest - fee)
    outs = [o for o in outs if not o[2] or o[1] >= DUST_SATS]

    outpoints = [f"{rng.getrandbits(256):064x}:{rng.randint(0, 3)}" for _ in inputs]
    ins = list(zip(inputs, outpoints))
    if rng.random() < p["bip69"]:
        from features.fingerprint import _outpoint_key
        ins.sort(key=lambda x: _outpoint_key(x[1]))
        outs.sort(key=lambda o: (o[1], o[0]))
    else:
        rng.shuffle(ins)
        position = draw(rng, p["change_position"])
        if position == "random":
            rng.shuffle(outs)
        else:
            paying = [o for o in outs if not o[2]]
            changes = [o for o in outs if o[2]]
            outs = changes + paying if position == "first" else paying + changes

    locktime = 0
    if rng.random() < p["anti_fee_sniping"]:
        # Anti-fee-sniping: the current height, occasionally up to 100 blocks
        # back (docs/FINGERPRINTS.md, locktime).
        locktime = height - (rng.randint(0, 100) if rng.random() < 0.1 else 0)
    sequence = RBF if rng.random() < p["rbf"] else (LOCKTIME_ONLY if locktime else FINAL)
    total_out = sum(o[1] for o in outs)
    return {
        "in_addrs": [a for (a, _), _ in ins], "in_vals": [v for (_, v), _ in ins],
        "out_addrs": [o[0] for o in outs], "out_vals": [round(o[1] / SATS, 8) for o in outs],
        "outpoints": [op for _, op in ins], "sequences": [sequence] * len(ins),
        "tx_version": int(draw(rng, p["version"])), "locktime": int(locktime),
        "fee": round((sum(in_sats) - total_out) / SATS, 8),
        "wallet_profile": profile,
        "change_indices": [i for i, o in enumerate(outs) if o[2]],
    }


def for_shape(shape: dict, profile: str, rng: random.Random, height: int, cfg: dict) -> dict:
    """A `generator.typologies.shape` record under `profile`, for the corpus.

    Its placeholder addresses become typed ones: inputs of the profile's input
    type; change of the inputs' type, or paid back to an input address when the
    profile reuses addresses; payees of the network-wide payee mix. A payment's
    last output is its change; a batch gains one change output; each CoinJoin
    participant gains its own with the profile's `participant_change` rate.
    """
    w = cfg["generator"]["wallet_profiles"]
    p = w["profiles"][profile]
    in_type = draw(rng, p["input_types"])
    inputs = [(typed(a, in_type), v) for a, v in zip(shape["in_addrs"], shape["in_vals"])]
    kind = shape["shape"]
    outputs, change = [], {}
    for i, (a, v) in enumerate(zip(shape["out_addrs"], shape["out_vals"])):
        if kind == "payment" and i == len(shape["out_addrs"]) - 1:
            reuse = draw(rng, p["change_type"]) == "reuse_input"
            outputs.append((inputs[0][0] if reuse else typed(a, in_type), v))
            change[i] = None
        elif kind == "coinjoin":
            outputs.append((typed(a, in_type), v))       # a coordinator round is one type
        else:
            outputs.append((typed(a, draw(rng, w["payee_types"])), v))
    if kind == "batch":
        change[len(outputs)] = None
        outputs.append((typed(f"{shape['in_addrs'][0]}-change", in_type), 0.0))
    if kind == "coinjoin":
        for i, (a, _) in enumerate(inputs):
            if rng.random() < p.get("participant_change", 0.0):
                change[len(outputs)] = i
                outputs.append((typed(f"{a}-change", in_type), 0.0))
    return build(inputs, outputs, change, profile, rng, height, cfg)
