"""The imported tags, and what they say about our addresses and entities.

Propagation rules (docs/TAGSTORE.md):

* a tag with applies_to="cluster" reaches every member address of the cluster
  its subject falls in, at the tag's confidence times the cluster's merge
  confidence (`Clustering.confidence`, lowered where merges are uncertain);
* a tag with applies_to="address" stays on its address. On a multi-wallet
  entity it is listed as a member's tag and does not score the entity;
* nothing else carries a tag: not fingerprints, not transaction flows, and not
  actor joins (an actor lists its members' tags, each under its member);
* two tags that disagree on one entity are both shown and flagged, never
  resolved.

Every bundle in the store is re-verified against its seal when loaded; one that
no longer verifies is left out and reported in `header()`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

import config

from .bundle import BundleRefused, check, store_dir
from .tags import Tag

log = logging.getLogger(__name__)


@dataclass
class TagStore:
    bundles: list[dict] = field(default_factory=list)
    by_address: dict[str, list[tuple[str, Tag]]] = field(default_factory=dict)
    risk: dict[str, float] = field(default_factory=dict)

    def add(self, bundle: str, tags: list[Tag]) -> None:
        for t in tags:
            self.by_address.setdefault(t.subject, []).append((bundle, t))

    def header(self) -> dict:
        loaded = [b for b in self.bundles if b["ok"]]
        return {"bundles": self.bundles, "tags": sum(b.get("tags", 0) for b in loaded),
                "simulated": any(b.get("simulated") for b in loaded),
                "statement": "Tags describe services and categories, never private "
                             "individuals. Each carries its source and collection date."}

    # --- what applies where -------------------------------------------------
    @staticmethod
    def _shown(bundle: str, tag: Tag, basis: str, confidence: float, via: str) -> dict:
        return {**tag.as_dict(), "bundle": bundle, "basis": basis, "via": via,
                "effective_confidence": round(confidence, 4)}

    def entity(self, entity_id: str, clustering) -> dict:
        """Tags on one entity (an address cluster or a lone wallet)."""
        members = sorted(clustering.clusters.get(entity_id, {entity_id}))
        merge = float(clustering.confidence.get(entity_id, 1.0)) if len(members) > 1 else 1.0
        applied, on_members = [], []
        for address in members:
            for bundle, t in self.by_address.get(address, ()):
                if t.applies_to == "cluster":
                    applied.append(self._shown(bundle, t, "cluster tag, through member "
                                               f"{address}", t.confidence * merge, address))
                elif len(members) == 1:
                    applied.append(self._shown(bundle, t, "address tag", t.confidence, address))
                else:
                    on_members.append(self._shown(
                        bundle, t, f"address tag on member {address}; not extended to the "
                        "cluster", t.confidence, address))
        shown = applied + on_members
        categories = sorted({t["category"] for t in shown})
        labels = sorted({t["label"] for t in applied})
        return {"entity_id": entity_id, "merge_confidence": round(merge, 4),
                "tags": applied, "member_tags": on_members,
                "conflict": len(categories) > 1 or len(labels) > 1,
                "categories": categories}

    def address(self, address: str, clustering) -> dict:
        """Tags on one address: its own, and cluster tags from its cluster."""
        entity_id = clustering.cluster_of(address) or address
        members = clustering.clusters.get(entity_id, {address})
        merge = float(clustering.confidence.get(entity_id, 1.0)) if len(members) > 1 else 1.0
        shown = [self._shown(b, t, "address tag" if t.applies_to == "address"
                             else "cluster tag", t.confidence, address)
                 for b, t in self.by_address.get(address, ())]
        for member in sorted(members - {address}):
            shown += [self._shown(b, t, f"cluster tag, through member {member}",
                                  t.confidence * merge, member)
                      for b, t in self.by_address.get(member, ()) if t.applies_to == "cluster"]
        categories = sorted({t["category"] for t in shown})
        return {"address": address, "entity_id": entity_id, "tags": shown,
                "conflict": len(categories) > 1, "categories": categories}

    def score(self, entity: dict) -> float:
        """The fusion signal: the strongest risk-weighted tag applied to the
        entity. Exchange/VASP tags weigh 0 (config tags.risk): they say where
        money went, not that the entity is suspect."""
        return max((self.risk.get(t["category"], 0.0) * t["effective_confidence"]
                    for t in entity["tags"]), default=0.0)


def load(cfg: dict | None = None, directory=None) -> TagStore:
    """Every bundle under the store directory, each re-verified."""
    cfg = cfg or config.load()
    store = TagStore(risk=dict(cfg["tags"]["risk"]))
    if directory is None and not cfg["tags"].get("store_dir"):
        return store                     # tags switched off (evaluation, tests)
    root = Path(directory or store_dir(cfg))
    for path in sorted(p for p in root.iterdir() if p.is_dir()) if root.exists() else []:
        try:
            verified, meta, tags = check(path, cfg)
        except BundleRefused as exc:
            log.warning("tag bundle %s left out: %s", path.name, exc)
            store.bundles.append({"name": path.name, "ok": False, "reason": str(exc)})
            continue
        store.add(meta["name"], tags)
        store.bundles.append({"name": meta["name"], "ok": True, "sources": meta["sources"],
                              "simulated": meta["simulated"], "tags": len(tags),
                              "created": meta["created"],
                              "manifest_hash": verified["manifest_hash"]})
    return store


def loaded(cfg: dict | None = None) -> bool:
    """Whether any verified bundle is in the store: the tag signal exists."""
    return any(b["ok"] for b in load(cfg).bundles)


def tag_scores(features, cfg: dict | None = None, store: TagStore | None = None) -> pd.DataFrame:
    """One `tag_score` per entity, for fusion.pipeline and fusion.incremental."""
    store = store or load(cfg)
    rows = []
    if store.by_address:
        clustering = features.clustering
        entities = {features.entity_of(a) for a in store.by_address}
        rows = [{"entity_id": e, "tag_score": store.score(store.entity(e, clustering))}
                for e in sorted(entities)]
    return pd.DataFrame(rows, columns=["entity_id", "tag_score"])

