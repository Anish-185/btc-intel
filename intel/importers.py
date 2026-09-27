"""Tags from three places: the OFAC SDN list, an operator's CSV, and (demo
only) generator ground truth. Each returns a list of Tag; intel.bundle seals it.
"""

from __future__ import annotations

import csv
import json
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import date
from pathlib import Path

from .tags import SIMULATED, Tag

# --- OFAC SDN -----------------------------------------------------------------
#: The idType OFAC uses for a Bitcoin address. Other digital currencies (ETH,
#: XMR, USDT...) have their own suffix and are not Bitcoin addresses.
OFAC_XBT = "Digital Currency Address - XBT"
OFAC_SOURCE = "OFAC SDN"
#: Look the uid up in OFAC's Sanctions List Search (sanctionssearch.ofac.treas.gov).
OFAC_REFERENCE = "OFAC SDN list, entry uid {uid}"


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child(element, name: str):
    return next((c for c in element if _local(c.tag) == name), None)


def _text(element, name: str) -> str:
    child = _child(element, name)
    return (child.text or "").strip() if child is not None else ""


def ofac(path) -> list[Tag]:
    """Bitcoin addresses from OFAC's SDN.XML.

    Written against the published format (sdnList / sdnEntry / idList / id,
    with idType "Digital Currency Address - XBT") and a hand-built fixture:
    this build has never seen a downloaded copy. Check the element names
    against a real SDN.XML before operational use (docs/TAGSTORE.md). Parsed
    namespace-blind, since OFAC has changed the namespace URI before.

    An entry that is an individual keeps only its SDN uid and programme in the
    label: tags describe services and categories, never private persons.
    """
    root = ET.parse(path).getroot()
    publish = next((e for e in root.iter() if _local(e.tag) == "Publish_Date"), None)
    collected = None
    if publish is not None and publish.text:
        month, day, year = (int(x) for x in publish.text.strip().split("/"))
        collected = date(year, month, day).isoformat()
    if collected is None:
        raise ValueError(f"{path}: no publshInformation/Publish_Date; is this SDN.XML?")
    out = []
    for entry in (e for e in root.iter() if _local(e.tag) == "sdnEntry"):
        ids = _child(entry, "idList")
        addresses = [_text(i, "idNumber") for i in (ids if ids is not None else [])
                     if _text(i, "idType") == OFAC_XBT and _text(i, "idNumber")]
        if not addresses:
            continue
        uid = _text(entry, "uid")
        programs = _child(entry, "programList")
        programs = ", ".join(p.text.strip() for p in (programs if programs is not None else [])
                             if p.text) or "no programme listed"
        if _text(entry, "sdnType") == "Individual":
            label = f"OFAC SDN individual entry {uid} ({programs})"
        else:
            label = f"{_text(entry, 'lastName') or 'entry ' + uid} (OFAC SDN, {programs})"
        for address in addresses:
            out.append(Tag(subject=address, label=label, category="sanctioned",
                           source=OFAC_SOURCE, reference=OFAC_REFERENCE.format(uid=uid),
                           collected=collected, confidence=1.0, applies_to="address"))
    return out


# --- an operator's CSV --------------------------------------------------------
CSV_COLUMNS = ("address", "label", "category", "reference", "collected", "confidence")


def from_csv(path, source: str | None = None) -> list[Tag]:
    """One tag per row. Columns: address, label, category, reference, collected,
    confidence, and optionally applies_to (address | cluster) and source. A
    `source` argument fills rows that do not name one. Any invalid row fails
    the whole file, naming its line: a curated list is fixed, not skimmed."""
    out = []
    with open(path, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing = set(CSV_COLUMNS) - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"{path}: missing columns {sorted(missing)}")
        for line, row in enumerate(reader, start=2):
            try:
                out.append(Tag(subject=row["address"].strip(), label=row["label"].strip(),
                               category=row["category"].strip(),
                               source=(row.get("source") or source or "").strip(),
                               reference=row["reference"].strip(),
                               collected=row["collected"].strip(),
                               confidence=float(row["confidence"]),
                               applies_to=(row.get("applies_to") or "address").strip()))
            except (ValueError, TypeError) as exc:
                raise ValueError(f"{path} line {line}: {exc}") from exc
    return out


# --- demo: generator ground truth ---------------------------------------------
def cashouts(meta: dict, outputs, gt: dict) -> set[str]:
    """The true cash-out wallets among one transaction's outputs: a ransomware
    peel's payment to a `cashout` wallet, or a layering merge's sink. One
    definition, shared by the demo bundle and eval.exit_eval."""
    if meta["pattern"] == "ransomware_peel":
        return {a for a in outputs if gt["clusters"].get(gt["wallets"].get(a, ""), {})
                .get("pattern_type") == "cashout"}
    if meta["pattern"] == "layering_merge":
        return set(outputs)
    return set()


def demo(raw_dir, with_cashouts: bool = True) -> list[Tag]:
    """A simulated bundle for the demo dataset: every illicit operation's origin
    cluster and every exchange, each tagged through its most-spent wallet (an
    exchange's hot wallet) with applies_to="cluster"; and every operation's
    true cash-out wallet, tagged exchange/VASP so an exit-point trace has a
    service to rank (the generator's cash-outs are fresh wallets, never one of
    its exchanges). `with_cashouts=False` leaves those out, for callers that
    tag cash-outs themselves.

    Every tag is source="simulated", which Tag checks against the reference.
    Tagging every operation is what makes any detection figure built on these
    tags an upper bound: real lists cover a fraction of real crime.
    """
    from eval.actors import OPERATION_TX_PATTERNS

    raw_dir = Path(raw_dir)
    gt = json.loads((raw_dir / "ground_truth.json").read_text())
    collected = gt["generated_at"][:10]
    reference = f"generator ground_truth.json, seed {gt['seed']}, cluster {{cid}}"

    spent, seen, outputs = Counter(), Counter(), {}
    with open(raw_dir / "transactions.csv", newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            spent.update(a for a in row["input_addresses"].split(";") if a)
            seen.update(a for a in row["output_addresses"].split(";") if a)
            outputs[row["txid"]] = [a for a in row["output_addresses"].split(";") if a]

    operations: dict[str, str] = {}
    for meta in gt["transactions"].values():
        if meta["pattern"] in OPERATION_TX_PATTERNS:
            operations.setdefault(meta["cluster_id"], meta["typology"])
    for cid, cluster in gt["clusters"].items():
        if cluster["pattern_type"] == "ransomware_collector":
            operations.setdefault(cid, "ransomware")

    def tag(cid: str, label: str, category: str) -> Tag | None:
        wallets = gt["clusters"][cid]["wallets"]
        best = max(sorted(wallets), key=lambda w: (spent[w], seen[w]))
        if not (spent[best] or seen[best]):
            return None                  # never transacted: nothing to attach to
        return Tag(subject=best, label=label, category=category, source=SIMULATED,
                   reference=reference.format(cid=cid), collected=collected,
                   confidence=1.0, applies_to="cluster")

    out = []
    for cid, typology in sorted(operations.items()):
        category = "ransomware" if "ransomware" in typology else "other"
        out.append(tag(cid, f"simulated {typology} operation {cid}", category))
    for cid, cluster in sorted(gt["clusters"].items()):
        if cluster["pattern_type"] == "exchange":
            out.append(tag(cid, f"simulated exchange {cid} hot wallet", "exchange/VASP"))
    if with_cashouts:
        found: dict[str, set[str]] = {}
        for txid, meta in gt["transactions"].items():
            if meta["pattern"] in OPERATION_TX_PATTERNS and txid in outputs:
                found.setdefault(meta["cluster_id"], set()).update(
                    cashouts(meta, outputs[txid], gt))
        out += [Tag(subject=w, label=f"simulated cash-out point of operation {cid}",
                    category="exchange/VASP", source=SIMULATED,
                    reference=f"generator ground_truth.json, seed {gt['seed']}, operation {cid}",
                    collected=collected, confidence=1.0, applies_to="cluster")
                for cid, wallets in sorted(found.items()) for w in sorted(wallets)]
    return [t for t in out if t is not None]
