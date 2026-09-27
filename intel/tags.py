"""One tag: what an address (or the cluster it defines) is, and who says so.

A tag describes a service or a category. It never names a private individual:
importers build labels from the service name or the list entry's reference, and
an entry that is a person keeps only its reference (intel.importers.ofac).

The subject is always an address. Our cluster ids are internal to one run of
graph/clustering and mean nothing on the machine that built the bundle, so a
cluster is tagged the way GraphSense does it: through an address in it, with
`applies_to="cluster"` asserting that the address's cluster is the service.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import date

CATEGORIES = ("exchange/VASP", "sanctioned", "ransomware", "darknet market", "mixer",
              "scam", "other")
APPLIES_TO = ("address", "cluster")

#: The one source a tag derived from generator ground truth may carry. It is
#: checked on every tag, and `simulated` is derived from it, never stored, so a
#: demo tag cannot be relabelled real without editing its source, which breaks
#: the bundle's seal (intel.bundle).
SIMULATED = "simulated"


@dataclass(frozen=True)
class Tag:
    subject: str            # an address
    label: str              # the service or list entry, never a person's name
    category: str           # one of CATEGORIES
    source: str             # who says so: "OFAC SDN", an operator's list, "simulated"
    reference: str          # URL or document reference for the claim
    collected: str          # ISO date the source was collected
    confidence: float       # the source's own confidence, 0-1
    applies_to: str = "address"   # "cluster": the subject's cluster is this service

    def __post_init__(self):
        problems = []
        if not self.subject or not str(self.subject).strip():
            problems.append("empty subject")
        if not self.label or not str(self.label).strip():
            problems.append("empty label")
        if self.category not in CATEGORIES:
            problems.append(f"category {self.category!r} not one of {CATEGORIES}")
        if self.applies_to not in APPLIES_TO:
            problems.append(f"applies_to {self.applies_to!r} not one of {APPLIES_TO}")
        if not self.source or not str(self.source).strip():
            problems.append("empty source")
        if not self.reference or not str(self.reference).strip():
            problems.append("no source reference")
        if not 0.0 <= float(self.confidence) <= 1.0:
            problems.append(f"confidence {self.confidence} outside [0, 1]")
        try:
            date.fromisoformat(str(self.collected)[:10])
        except ValueError:
            problems.append(f"collected {self.collected!r} is not an ISO date")
        if "ground_truth" in self.reference and self.source != SIMULATED:
            problems.append("derived from generator ground truth but not source='simulated'")
        if problems:
            raise ValueError(f"invalid tag for {self.subject!r}: {'; '.join(problems)}")

    @property
    def simulated(self) -> bool:
        return self.source == SIMULATED

    def as_dict(self) -> dict:
        return {**asdict(self), "simulated": self.simulated}

    @classmethod
    def from_dict(cls, d: dict) -> Tag:
        return cls(**{k: d[k] for k in ("subject", "label", "category", "source", "reference",
                                        "collected", "confidence", "applies_to") if k in d})
