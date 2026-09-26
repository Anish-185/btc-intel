"""How this transaction was built — a construction pattern — from on-chain
structure only. Not which software built it.

    python -m features.fingerprint fit       # fit + calibrate on the fingerprint corpus

A fingerprint names a *construction pattern*: "Core-like construction",
"coordinator CoinJoin shape", "batch-withdrawal shape". It never names the
software, a person or an organisation, and it is a probability, not a finding.
A construction unlike every trained pattern is answered `unknown` (the novelty
check, docs/FINGERPRINTS.md "Open-set revision"). Every tell, what it
indicates, which families exhibit it and where it is ambiguous is in
docs/FINGERPRINTS.md.

TELLS
Each tell reads one structural property and returns a category, or None when
this transaction cannot show it (a field the dataset does not carry, or a
structure too small to say anything). A missing tell is left out of the
evidence, never counted as a vote.

  version         tx version: v1 | v2 | other
  locktime        nLockTime: zero | height | time
  sequence        nSequence: rbf (≤ 0xFFFFFFFD) | locktime_only (0xFFFFFFFE) | final | mixed
  ordering        BIP-69 order: bip69 | not_bip69
  change_position first | middle | last, for an identifiable change output
  fee             round_btc | round_rate | integer_rate | fractional_rate
  script_mix      the inputs' script type, or mixed
  change_type     reuse_input | same_type | other_type
  io_shape        input-count bucket x output-count bucket
  batching        equal_group | many_outputs | simple

CLASSIFIER
Categorical naive Bayes over the tells, fitted on the corpus's training
captures. The per-label posterior is calibrated by one isotonic map, pooled
one-vs-rest, fitted on the calibration captures. The answer is `unknown` when
the top calibrated confidence is under `features.fingerprint.unknown_below`, or
fewer than `min_tells` tells were observable. Naive Bayes assumes the tells
are independent given the family; they are not (a v2 transaction usually also
sets a height locktime), so the raw posterior is overconfident, and the
isotonic map is what makes the number mean something.

Everything it is evaluated on is simulated (generator/wallets.py), so its
accuracy measures how well it recovers the simulator's own profiles, not how
well it would identify real software. The report says so beside every number.
"""

from __future__ import annotations

import argparse
import json
import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

import config

UNKNOWN = "unknown"
#: The labels, and how they are written for a reader: construction patterns,
#: never software identity (docs/FINGERPRINTS.md, "Open-set revision").
LABELS = {
    "core_like": "Core-like construction",
    "electrum_like": "Electrum-like construction",
    "legacy_naive": "legacy/naive construction",
    "coordinator_coinjoin": "coordinator CoinJoin shape",
    "batch_withdrawal": "batch-withdrawal shape",
}
#: Carried by every answer and shown wherever a label is.
STATEMENT = "The label describes how the transaction was built, not which software built it."
#: The novelty threshold is this quantile of the novelty score on the
#: validation (calibration) rows of the known profiles. Pre-registered.
NOVELTY_QUANTILE = 0.99
TELLS = ("version", "locktime", "sequence", "ordering", "change_position", "fee",
         "script_mix", "change_type", "io_shape", "batching")
#: Tells only a raw transaction shows. A relay log in the NTRO schema carries
#: none of them, and a fingerprint from the rest is a different, weaker
#: measurement — so it has its own calibration and its own report rows.
CONSTRUCTION_TELLS = ("version", "locktime", "sequence")
FULL, STRUCTURAL = "full", "structural"


def condition(t: dict) -> str:
    return FULL if any(t.get(k) is not None for k in CONSTRUCTION_TELLS) else STRUCTURAL


def structural(t: dict) -> dict:
    """The tells a dataset without construction fields would show."""
    return {k: (None if k in CONSTRUCTION_TELLS else v) for k, v in t.items()}

FINAL, LOCKTIME_ONLY, RBF_MAX = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD
LOCKTIME_THRESHOLD = 500_000_000      # below: a block height; at or above: a unix time
SATS = 100_000_000

# --- sizes ----------------------------------------------------------------
#: Weight units per input and per output for single-key spends, the standard
#: estimates (P2WSH as 2-of-3 multisig). Signatures vary by a byte or two, so
#: a vsize from these is an estimate; the fee-rate tell tolerates it on the
#: simulated data, where the generator uses the same table, and is weaker on
#: real data. docs/FINGERPRINTS.md.
INPUT_WU = {"p2pkh": 592, "p2sh": 364, "p2wpkh": 272, "p2wsh": 420, "p2tr": 230}
OUTPUT_WU = {"p2pkh": 136, "p2sh": 128, "p2wpkh": 124, "p2wsh": 172, "p2tr": 172}
OVERHEAD_WU, SEGWIT_FLAG_WU = 40, 2
SEGWIT = {"p2wpkh", "p2wsh", "p2tr", "p2sh"}      # p2sh counted as nested segwit


def script_type_of(address: str) -> str:
    from graph.clustering import script_type_of as of
    return of(address)


def estimated_vsize(in_types: list[str], out_types: list[str]) -> int:
    weight = OVERHEAD_WU
    weight += sum(INPUT_WU.get(t, INPUT_WU["p2wpkh"]) for t in in_types)
    weight += sum(OUTPUT_WU.get(t, OUTPUT_WU["p2wpkh"]) for t in out_types)
    if any(t in SEGWIT for t in in_types):
        weight += SEGWIT_FLAG_WU
    return math.ceil(weight / 4)


def _equal_group(values: list[float], tolerance: float = 1e-9) -> list[int]:
    from graph.clustering import equal_value_group
    return equal_value_group(values, tolerance)[1]


# --- one transaction, as the tells read it -------------------------------------
@dataclass
class View:
    """The structure the tells read. Optional fields are None when the dataset
    does not carry them."""

    in_addrs: list[str]
    in_vals: list[float]
    out_addrs: list[str]
    out_vals: list[float]
    fee: float | None = None                  # BTC
    script_type: str = ""                     # record-level input type, a fallback
    version: int | None = None
    locktime: int | None = None
    sequences: list[int] | None = None
    outpoints: list[str] | None = None

    @classmethod
    def of_tx(cls, tx) -> View:
        """From a `graph.builder.Tx`."""
        return cls([a for a, _ in tx.inputs], [v for _, v in tx.inputs],
                   [a for a, _ in tx.outputs], [v for _, v in tx.outputs],
                   tx.fee, tx.script_type, getattr(tx, "version", None),
                   getattr(tx, "locktime", None), getattr(tx, "sequences", None),
                   getattr(tx, "outpoints", None))

    @classmethod
    def of_record(cls, r: dict) -> View:
        """From a corpus truth row (`generator.typologies.shape` + wallets)."""
        def opt(key):
            v = r.get(key)
            return None if v is None or (isinstance(v, float) and math.isnan(v)) else v
        seqs, outs = opt("sequences"), opt("outpoints")
        return cls(list(r["in_addrs"]), [float(v) for v in r["in_vals"]],
                   list(r["out_addrs"]), [float(v) for v in r["out_vals"]],
                   opt("fee"), "", None if opt("tx_version") is None else int(r["tx_version"]),
                   None if opt("locktime") is None else int(r["locktime"]),
                   None if seqs is None else [int(s) for s in seqs],
                   None if outs is None else list(outs))

    @property
    def in_types(self) -> list[str]:
        return [script_type_of(a) or self.script_type for a in self.in_addrs]

    @property
    def out_types(self) -> list[str]:
        return [script_type_of(a) for a in self.out_addrs]


def change_index(v: View) -> tuple[int | None, str | None]:
    """(index, how it was identified) of the change output, or (None, None).

    Structural reasons first, so `change_type` can say something the
    identification did not already assume: an output paying back an input
    address; in a transaction with an equal-value group, the one output
    outside it; then the one output sharing the inputs' script type.
    """
    n = len(v.out_addrs)
    if n < 2:
        return None, None
    inputs = set(v.in_addrs)
    reused = [i for i, a in enumerate(v.out_addrs) if a in inputs]
    if len(reused) == 1:
        return reused[0], "reuse"
    group = _equal_group(v.out_vals)
    if len(group) >= 3 and n - len(group) == 1:
        return next(i for i in range(n) if i not in group), "structure"
    types = set(v.in_types)
    if len(types) == 1 and "" not in types:
        same = [i for i, t in enumerate(v.out_types) if t in types]
        if len(same) == 1:
            return same[0], "type"
    return None, None


def _bucket(n: int, edges: tuple) -> str:
    for label, hi in edges:
        if n <= hi:
            return label
    return edges[-1][0]


def _outpoint_key(op: str) -> tuple:
    txid, _, vout = str(op).partition(":")
    return bytes.fromhex(txid)[::-1] if len(txid) == 64 else txid, int(vout or 0)


def tells(v: View) -> dict[str, str | None]:
    """Every tell, as a category or None."""
    out: dict[str, str | None] = dict.fromkeys(TELLS)
    if v.version is not None:
        out["version"] = {1: "v1", 2: "v2"}.get(v.version, "other")
    if v.locktime is not None:
        out["locktime"] = ("zero" if v.locktime == 0 else
                           "height" if v.locktime < LOCKTIME_THRESHOLD else "time")
    if v.sequences:
        kinds = {("rbf" if s <= RBF_MAX else "locktime_only" if s == LOCKTIME_ONLY else "final")
                 for s in v.sequences}
        out["sequence"] = kinds.pop() if len(kinds) == 1 else "mixed"

    # BIP-69: inputs by outpoint (prev txid bytes, then vout), outputs by
    # amount, then scriptPubKey. The address stands in for the scriptPubKey,
    # which only matters on equal amounts. An order is evidence only when a
    # different order was possible.
    decidable, ordered = False, True
    if len(v.out_vals) >= 2 and len(set(v.out_vals)) >= 2:
        decidable = True
        keys = [(round(val * SATS), a) for val, a in zip(v.out_vals, v.out_addrs)]
        ordered &= keys == sorted(keys)
    if v.outpoints and len(v.outpoints) >= 2:
        decidable = True
        keys = [_outpoint_key(o) for o in v.outpoints]
        ordered &= keys == sorted(keys)
    if decidable:
        out["ordering"] = "bip69" if ordered else "not_bip69"

    change, how = change_index(v)
    if change is not None:
        n = len(v.out_addrs)
        out["change_position"] = "first" if change == 0 else "last" if change == n - 1 else "middle"
        in_types = set(v.in_types)
        out["change_type"] = ("reuse_input" if how == "reuse" else
                              "same_type" if v.out_types[change] in in_types else "other_type")

    if v.fee is not None and v.fee > 0:
        sats = round(v.fee * SATS)
        rate = sats / estimated_vsize(v.in_types, v.out_types)
        near = lambda x, step: abs(x / step - round(x / step)) * step <= 0.01
        out["fee"] = ("round_btc" if sats % 10_000 == 0 else
                      "round_rate" if rate >= 5 and near(rate, 5) else
                      "integer_rate" if near(rate, 1) else "fractional_rate")

    types = {t for t in v.in_types if t}
    if types:
        out["script_mix"] = types.pop() if len(types) == 1 else "mixed"
    out["io_shape"] = (_bucket(len(v.in_addrs), (("1", 1), ("2-3", 3), ("4+", 10 ** 9))) + "x"
                       + _bucket(len(v.out_addrs), (("1", 1), ("2", 2), ("3-5", 5),
                                                    ("6+", 10 ** 9))))
    out["batching"] = ("equal_group" if len(_equal_group(v.out_vals)) >= 3 else
                       "many_outputs" if len(v.out_addrs) >= 5 else "simple")
    return out


# --- the classifier --------------------------------------------------------------
@dataclass
class FingerprintModel:
    counts: dict = field(default_factory=dict)       # label -> tell -> value -> n
    totals: dict = field(default_factory=dict)       # label -> tell -> n observed
    vocab: dict = field(default_factory=dict)        # tell -> sorted values
    priors: dict = field(default_factory=dict)       # label -> share of training rows
    iso: dict = field(default_factory=dict)          # condition -> [x, y], posterior -> P(true)
    novelty: dict = field(default_factory=dict)      # condition -> threshold on novelty_score
    meta: dict = field(default_factory=dict)

    @classmethod
    def fit(cls, rows: list[dict], labels: list[str], alpha: float = 1.0) -> FingerprintModel:
        counts = defaultdict(lambda: defaultdict(Counter))
        vocab = defaultdict(set)
        for t, y in zip(rows, labels):
            for tell, value in t.items():
                if value is not None:
                    counts[y][tell][value] += 1
                    vocab[tell].add(value)
        n = Counter(labels)
        return cls(counts={y: {k: dict(c) for k, c in by.items()} for y, by in counts.items()},
                   totals={y: {k: sum(c.values()) for k, c in by.items()}
                           for y, by in counts.items()},
                   vocab={k: sorted(v) for k, v in vocab.items()},
                   priors={y: n[y] / len(labels) for y in sorted(n)},
                   meta={"rows": len(rows), "alpha": alpha, "per_label": dict(n)})

    def posterior(self, t: dict) -> dict[str, float]:
        alpha = self.meta.get("alpha", 1.0)
        logp = {}
        for y, prior in self.priors.items():
            s = math.log(prior)
            for tell, value in t.items():
                if value is None or tell not in self.vocab:
                    continue
                k = len(self.vocab[tell]) + (value not in self.vocab[tell])
                c = self.counts.get(y, {}).get(tell, {}).get(value, 0)
                s += math.log((c + alpha) / (self.totals.get(y, {}).get(tell, 0) + alpha * k))
            logp[y] = s
        top = max(logp.values())
        z = sum(math.exp(v - top) for v in logp.values())
        return {y: math.exp(v - top) / z for y, v in logp.items()}

    def novelty_score(self, t: dict, label: str) -> float:
        """The named family's worst-supported tell: the largest surprisal,
        -log p(value | label), over the observed tells. The counts are the
        training rows' own, smoothed as `posterior` smooths them."""
        alpha = self.meta.get("alpha", 1.0)
        worst = 0.0
        for tell, value in t.items():
            if value is None or tell not in self.vocab:
                continue
            k = len(self.vocab[tell]) + (value not in self.vocab[tell])
            c = self.counts.get(label, {}).get(tell, {}).get(value, 0)
            p = (c + alpha) / (self.totals.get(label, {}).get(tell, 0) + alpha * k)
            worst = max(worst, -math.log(p))
        return worst

    def _top(self, t: dict, cond: str) -> str:
        post = self.posterior(t)
        return min(post, key=lambda y: (-self.calibrated(post[y], cond), -post[y], y))

    def calibrate(self, rows: list[dict], labels: list[str]) -> FingerprintModel:
        """One isotonic map per condition: the calibration rows as they are
        (full), and the same rows with the construction tells masked
        (structural). Pooled one-vs-rest over the labels. Then, on the same
        rows, each condition's novelty threshold: the NOVELTY_QUANTILE of the
        novelty score under the family the model would name."""
        from sklearn.isotonic import IsotonicRegression
        for name, view in ((FULL, lambda t: t), (STRUCTURAL, structural)):
            xs, ys = [], []
            for t, y in zip(rows, labels):
                for label, p in self.posterior(view(t)).items():
                    xs.append(p)
                    ys.append(float(label == y))
            iso = IsotonicRegression(y_min=0.0, y_max=1.0, out_of_bounds="clip").fit(xs, ys)
            self.iso[name] = [[float(x) for x in iso.X_thresholds_],
                              [float(y) for y in iso.y_thresholds_]]
        for name, view in ((FULL, lambda t: t), (STRUCTURAL, structural)):
            scores = [self.novelty_score(view(t), self._top(view(t), name)) for t in rows]
            self.novelty[name] = float(np.quantile(scores, NOVELTY_QUANTILE)) if scores else None
        self.meta["calibration_rows"] = len(rows)
        return self

    def calibrated(self, p: float, cond: str = FULL) -> float:
        if cond not in self.iso:
            return p
        x, y = self.iso[cond]
        return float(np.interp(p, x, y))

    def classify(self, t: dict, cfg: dict | None = None) -> dict:
        """The ranked label set, and the answer: the top label, or unknown."""
        f = (cfg or config.load())["features"]["fingerprint"]
        observed = sorted(k for k, v in t.items() if v is not None)
        cond = condition(t)
        ranked = sorted(((y, self.calibrated(p, cond), p) for y, p in self.posterior(t).items()),
                        key=lambda r: (-r[1], -r[2], r[0]))
        top, conf, _ = ranked[0]
        score, limit = self.novelty_score(t, top), self.novelty.get(cond)
        novel = limit is not None and score > limit
        if len(observed) < f["min_tells"]:
            answer, why = UNKNOWN, (f"only {len(observed)} tells observable; at least "
                                    f"{f['min_tells']} are needed")
        elif novel:
            answer, why = UNKNOWN, (f"out of distribution: a tell this construction's "
                                    f"training transactions almost never show (novelty "
                                    f"{score:.2f} over {limit:.2f})")
        elif conf < f["unknown_below"]:
            answer, why = UNKNOWN, (f"top confidence {conf:.2f} is under "
                                    f"{f['unknown_below']}")
        else:
            answer, why = top, None
        return {"label": answer, "display": LABELS.get(answer, "unknown construction"),
                "confidence": round(conf, 4), "unknown_reason": why,
                "ranked": [{"label": y, "display": LABELS[y], "confidence": round(c, 4),
                            "posterior": round(p, 4)} for y, c, p in ranked],
                "tells": t, "observed_tells": observed, "condition": cond,
                "novelty": {"score": round(score, 4),
                            "threshold": None if limit is None else round(limit, 4),
                            "novel": novel},
                "statement": STATEMENT,
                "basis": (f"naive Bayes over the observable tells, isotonic-calibrated for "
                          f"the {cond} condition on simulated captures "
                          "(docs/FINGERPRINTS.md)")}

    # persistence: JSON, so the fitted numbers can be read in a review
    def save(self, path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.__dict__, indent=1, sort_keys=True))
        return path

    @classmethod
    def load(cls, path) -> FingerprintModel:
        return cls(**json.loads(Path(path).read_text()))


def load_model(cfg: dict | None = None) -> FingerprintModel | None:
    path = Path((cfg or config.load())["features"]["fingerprint"]["model_path"])
    return FingerprintModel.load(path) if path.exists() else None


def fingerprint(v: View, model: FingerprintModel | None, cfg: dict | None = None) -> dict:
    """One transaction's answer. Without a fitted model: unknown, and why."""
    t = tells(v)
    if model is None:
        return {"label": UNKNOWN, "display": "unknown construction", "confidence": None,
                "unknown_reason": "no fitted fingerprint model; run "
                                  "`python -m features.fingerprint fit`",
                "ranked": [], "tells": t, "statement": STATEMENT,
                "observed_tells": sorted(k for k, x in t.items() if x is not None)}
    return model.classify(t, cfg)


def confident_labels(txs, cfg: dict | None = None,
                     model: FingerprintModel | None = None) -> dict[str, str]:
    """txid -> label for every transaction not answered `unknown`: what
    `graph.clustering.corroborate` reads. Empty when corroboration is off or
    no model has been fitted, which leaves clustering exactly as it was."""
    cfg = cfg or config.load()
    if not cfg["graph"].get("fingerprint", {}).get("corroborate"):
        return {}
    model = model or load_model(cfg)
    if model is None:
        return {}
    out = {}
    for tx in txs:
        answer = model.classify(tells(View.of_tx(tx)), cfg)
        if answer["label"] != UNKNOWN:
            out[tx.txid] = answer["label"]
    return out


def answers_for(txs, cfg: dict | None = None,
                model: FingerprintModel | None = None) -> dict[str, dict]:
    """txid -> fingerprint answer for every transaction given."""
    cfg = cfg or config.load()
    model = model or load_model(cfg)
    return {tx.txid: fingerprint(View.of_tx(tx), model, cfg) for tx in txs}


def console_display(cfg: dict | None = None) -> bool:
    """Whether the console shows fingerprints by default. The API answers
    either way; see the display rule in docs/FINGERPRINTS.md."""
    return bool((cfg or config.load())["features"]["fingerprint"].get("console_display", False))


def distribution(answers: list[dict]) -> dict:
    """How a set of transactions' fingerprints split, unknown included."""
    counts = Counter(a["label"] for a in answers)
    n = sum(counts.values())
    return {"transactions": n, "statement": STATEMENT,
            "labels": [{"label": y, "display": LABELS.get(y, "unknown construction"),
                        "count": c, "share": round(c / n, 4)}
                       for y, c in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))]}


# --- fitting and evaluation on the fingerprint corpus ---------------------------------
def corpus_frame(cfg: dict, rebuild: bool = False, workers: int | None = None):
    """(truth rows with profiles, capture -> role, corpus name)."""
    import pandas as pd

    from origination import corpus
    from origination.evaluate import assign, check_split
    manifest = corpus.load_manifest(corpus.FINGERPRINT_MANIFEST)
    directory = corpus.build(cfg, manifest=manifest, rebuild=rebuild, workers=workers)
    truth = pd.read_parquet(directory / "truth.parquet")
    captures = pd.read_parquet(directory / "captures.parquet")
    roles = assign(captures, manifest)
    check_split(roles, captures)
    truth["role"] = truth["capture_id"].map(roles)
    return truth, directory.name


def fit(cfg: dict | None = None, rebuild: bool = False, workers: int | None = None) -> dict:
    cfg = cfg or config.load()
    truth, name = corpus_frame(cfg, rebuild, workers)
    rows = [tells(View.of_record(r)) for r in truth.to_dict("records")]
    truth["_tells"] = rows
    train, cal = truth[truth["role"] == "train"], truth[truth["role"] == "calibration"]
    model = FingerprintModel.fit(list(train["_tells"]), list(train["wallet_profile"]),
                                 cfg["features"]["fingerprint"]["laplace"])
    model.calibrate(list(cal["_tells"]), list(cal["wallet_profile"]))
    model.meta["corpus"] = name
    path = model.save(cfg["features"]["fingerprint"]["model_path"])
    return {"model": model, "path": path, "truth": truth, "corpus": name}


def evaluate(fitted: dict, cfg: dict | None = None) -> dict:
    """Per-class precision/recall, confusion matrices and unknown rates, per test set,
    plus the agreement between the CoinJoin fingerprint and the validity layer."""
    import pandas as pd

    from analysis import validity
    cfg = cfg or config.load()
    model, truth = fitted["model"], fitted["truth"]
    out = {"per_class": [], "confusion": {}, "unknown": [], "agreement": [],
           "disagreements": [], "corpus": fitted["corpus"]}
    for (role, set_name), cond in [(r, c) for r in (("within_test", "within-topology"),
                                                    ("cross_test", "cross-topology"))
                                   for c in (FULL, STRUCTURAL)]:
        label = f"{set_name}, {cond}"
        part = truth[truth["role"] == role]
        view = structural if cond == STRUCTURAL else (lambda t: t)
        answers = [model.classify(view(t), cfg) for t in part["_tells"]]
        pred = pd.Series([a["label"] for a in answers], index=part.index)
        y = part["wallet_profile"]
        out["unknown"].append({"condition": "simulated", "test set": label,
                               "transactions": len(part), "unknown": int((pred == UNKNOWN).sum()),
                               "unknown rate": round(float((pred == UNKNOWN).mean()), 4),
                               "accuracy if answered": round(float(
                                   (pred[pred != UNKNOWN] == y[pred != UNKNOWN]).mean()), 4)})
        for cls_ in LABELS:
            tp = int(((pred == cls_) & (y == cls_)).sum())
            named, actual = int((pred == cls_).sum()), int((y == cls_).sum())
            answered_actual = int(((y == cls_) & (pred != UNKNOWN)).sum())
            out["per_class"].append({
                "condition": "simulated", "test set": label, "class": cls_,
                "actual": actual, "named": named, "true positives": tp,
                "precision": round(tp / named, 3) if named else None,
                "recall": round(tp / actual, 3) if actual else None,
                "recall if answered": round(tp / answered_actual, 3) if answered_actual else None,
                "unknown": int(((y == cls_) & (pred == UNKNOWN)).sum())})
        out["confusion"][label] = pd.crosstab(
            y.rename("true profile"), pred.rename("fingerprint"),
            dropna=False).reindex(columns=[*LABELS, UNKNOWN], fill_value=0)

        # The CoinJoin fingerprint against the validity layer's COINJOIN detector.
        detected = [validity.coinjoin(validity.tx_of(t, r), cfg) is not None
                    for t, r in zip(part["txid"], part.to_dict("records"))]
        named = pred == "coordinator_coinjoin"
        det = pd.Series(detected, index=part.index)
        out["agreement"].append({
            "condition": "simulated", "test set": label, "transactions": len(part),
            "both CoinJoin": int((named & det).sum()),
            "fingerprint only": int((named & ~det).sum()),
            "detector only": int((~named & det).sum()),
            "neither": int((~named & ~det).sum()),
            "agreement rate": round(float((named == det).mean()), 4)})
        for kind, mask in (("detector only", ~named & det), ("fingerprint only", named & ~det)):
            for (truth_label, answer), n in Counter(zip(y[mask], pred[mask])).most_common():
                out["disagreements"].append({"condition": "simulated", "test set": label,
                                             "disagreement": kind, "true profile": truth_label,
                                             "fingerprint said": answer, "transactions": n})
    for key in ("per_class", "unknown", "agreement", "disagreements"):
        out[key] = pd.DataFrame(out[key])
    return out


#: A (tell, value) is defining for a pattern when at least this share of the
#: pattern's training rows that observe the tell show that value. Pre-registered.
DEFINING_SHARE = 0.8
OPEN_SET, CLOSED_SET = "open-set (novelty check)", "P8.1 (no novelty check)"


def defining_tells(rows: list[dict], labels: list[str]) -> dict[str, dict[str, str]]:
    """label -> {tell: value} for every tell whose value is DEFINING_SHARE-dominant
    among that label's rows (the training rows, never test rows)."""
    seen: dict[str, dict[str, Counter]] = defaultdict(lambda: defaultdict(Counter))
    for t, y in zip(rows, labels):
        for tell, value in t.items():
            if value is not None:
                seen[y][tell][value] += 1
    out = {}
    for y, by in seen.items():
        out[y] = {}
        for tell, c in by.items():
            value, n = c.most_common(1)[0]
            if n / sum(c.values()) >= DEFINING_SHARE:
                out[y][tell] = value
    return out


def outcome(t: dict, label: str, defining: dict[str, dict[str, str]]) -> str:
    """How a held-out transaction's answer is scored: `unknown`; `shared pattern`
    when it shows every defining tell of the named pattern that it observes (at
    least one); otherwise `harmful mislabel`. Reads only the tells and the
    training-row definitions, never the model's scores."""
    if label == UNKNOWN:
        return "unknown"
    rules = {k: v for k, v in defining.get(label, {}).items() if t.get(k) is not None}
    if rules and all(t[k] == v for k, v in rules.items()):
        return "shared pattern"
    return "harmful mislabel"


def leave_one_profile_out(truth, cfg: dict | None = None, test_role: str = "cross_test"):
    """The generalization test: constructions the model has never seen.

    For each profile, fit and calibrate (isotonic maps and novelty thresholds)
    on every other profile's train and calibration rows, then answer the
    held-out profile's `test_role` rows twice: with the novelty check, and
    without it (P8.1's rule). Each answer is scored by `outcome`, with the
    defining tells taken from the fold's own training rows.
    """
    import pandas as pd
    cfg = cfg or config.load()
    alpha = cfg["features"]["fingerprint"]["laplace"]
    rows = []
    for held in LABELS:
        rest = truth[truth["wallet_profile"] != held]
        train, cal = rest[rest["role"] == "train"], rest[rest["role"] == "calibration"]
        model = FingerprintModel.fit(list(train["_tells"]), list(train["wallet_profile"]), alpha)
        model.calibrate(list(cal["_tells"]), list(cal["wallet_profile"]))
        closed = FingerprintModel(**{**model.__dict__, "novelty": {}})
        defining = defining_tells(list(train["_tells"]), list(train["wallet_profile"]))
        test = truth[(truth["wallet_profile"] == held) & (truth["role"] == test_role)]
        for cond, view in ((FULL, lambda t: t), (STRUCTURAL, structural)):
            for name, m in ((CLOSED_SET, closed), (OPEN_SET, model)):
                said = Counter()
                named = Counter()
                for t in test["_tells"]:
                    v = view(t)
                    label = m.classify(v, cfg)["label"]
                    kind = outcome(v, label, defining)
                    said[kind] += 1
                    if kind == "harmful mislabel":
                        named[label] += 1
                rows.append({"held-out profile": held, "condition": cond, "model": name,
                             "transactions": len(test), "unknown": said["unknown"],
                             "shared pattern": said["shared pattern"],
                             "harmful mislabel": said["harmful mislabel"],
                             "most often harmfully named": (named.most_common(1)[0][0]
                                                            if named else "—")})
    frame = pd.DataFrame(rows)
    counts = ["transactions", "unknown", "shared pattern", "harmful mislabel"]
    pooled = (frame.groupby(["condition", "model"], sort=False)[counts].sum().reset_index()
              .assign(**{"held-out profile": "all (pooled)", "most often harmfully named": "—"}))
    frame = pd.concat([frame, pooled[frame.columns]], ignore_index=True)
    n = frame["transactions"].where(frame["transactions"] > 0)
    for col in ("unknown", "shared pattern", "harmful mislabel"):
        frame[f"{col} rate"] = (frame[col] / n).round(4)
    return frame[["held-out profile", "condition", "model", "transactions",
                  "unknown", "unknown rate", "shared pattern", "shared pattern rate",
                  "harmful mislabel", "harmful mislabel rate", "most often harmfully named"]]


def in_distribution_cost(fitted: dict, cfg: dict | None = None):
    """Accuracy when answered and the unknown rate on the known-profile test
    sets, with the novelty check and without it: what open-set costs."""
    import pandas as pd
    cfg = cfg or config.load()
    model, truth = fitted["model"], fitted["truth"]
    closed = FingerprintModel(**{**model.__dict__, "novelty": {}})
    rows = []
    for role, set_name in (("within_test", "within-topology"), ("cross_test", "cross-topology")):
        part = truth[truth["role"] == role]
        for cond, view in ((FULL, lambda t: t), (STRUCTURAL, structural)):
            for name, m in ((CLOSED_SET, closed), (OPEN_SET, model)):
                pred = [m.classify(view(t), cfg)["label"] for t in part["_tells"]]
                y = list(part["wallet_profile"])
                answered = [(a, b) for a, b in zip(pred, y) if a != UNKNOWN]
                rows.append({"test set": f"{set_name}, {cond}", "model": name,
                             "transactions": len(pred),
                             "unknown rate": round(1 - len(answered) / len(pred), 4),
                             "accuracy if answered": round(
                                 sum(a == b for a, b in answered) / len(answered), 4)
                             if answered else None})
    return pd.DataFrame(rows)

def transfer(model: FingerprintModel, cfg: dict | None = None, n_transactions: int = 3000,
             seed: int = 42) -> dict:
    """The model, fitted on corpus shapes, on a `generator.main --wallet-profiles`
    dataset: the same profiles, but the generator's typologies (peel chains,
    layering fan-outs, CoinJoin rounds) instead of the corpus's three shapes.
    A distribution shift inside the simulator; still simulated."""
    import tempfile

    import pandas as pd

    from generator.main import build_parser, generate
    from graph.builder import iter_transactions
    from ingest.pipeline import run as ingest_run
    cfg = cfg or config.load()
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        generate(build_parser().parse_args([
            "--n-actors", str(n_transactions // 10), "--n-transactions", str(n_transactions),
            "--output", str(d), "--seed", str(seed), "--formats", "csv",
            "--wallet-profiles"]), cfg)
        ingest_run(d / "transactions.csv", d / "t.parquet", d / "q.parquet", "csv", cfg=cfg,
                   record_custody=False)
        truth = json.loads((d / "ground_truth.json").read_text())["transactions"]
        txs = list(iter_transactions(pd.read_parquet(d / "t.parquet")))
    y = pd.Series([truth[tx.txid]["wallet_profile"] for tx in txs])
    typology = pd.Series([truth[tx.txid]["typology"] for tx in txs])
    pred = pd.Series([model.classify(tells(View.of_tx(tx)), cfg)["label"] for tx in txs])
    answered = pred != UNKNOWN
    rows = [{"condition": "simulated", "typology": t, "transactions": int(m.sum()),
             "unknown rate": round(float((~answered[m]).mean()), 3),
             "accuracy if answered": round(float((pred[m & answered] == y[m & answered]).mean()), 3)
             if (m & answered).any() else None}
            for t, m in ((t, typology == t) for t in sorted(typology.unique()))]
    return {"by_typology": pd.DataFrame(rows),
            "confusion": pd.crosstab(y.rename("true profile"), pred.rename("fingerprint"))
            .reindex(columns=[c for c in [*LABELS, UNKNOWN] if c in set(pred)], fill_value=0),
            "seed": seed, "transactions": len(txs)}


def main(argv=None) -> None:
    cfg = config.load()
    ap = argparse.ArgumentParser(prog="features.fingerprint", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["fit"])
    ap.add_argument("--rebuild", action="store_true")
    ap.add_argument("--workers", type=int, default=None)
    args = ap.parse_args(argv)
    fitted = fit(cfg, args.rebuild, args.workers)
    result = evaluate(fitted, cfg)
    print(result["unknown"].to_string(index=False))
    print(result["agreement"].to_string(index=False))
    print(json.dumps({"model": str(fitted["path"]), "corpus": fitted["corpus"]}, indent=2))


if __name__ == "__main__":
    main()
