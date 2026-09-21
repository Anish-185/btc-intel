"""The alert every rule emits.

The reason string is not decoration: it is what an investigator reads, and what
the explainability layer will quote. Every reason states the evidence that made
the rule fire, in plain English, with the actual numbers in it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pandas as pd

ALERT_COLUMNS = ["entity_id", "rule_name", "score", "reason", "evidence"]


@dataclass
class Alert:
    entity_id: str          # cluster id, or a txid for transaction-level rules
    rule_name: str
    score: float            # 0-1
    reason: str             # plain English, with the numbers that triggered it
    evidence: list[str] = field(default_factory=list)  # txids / wallet addresses

    def __post_init__(self):
        self.score = float(min(1.0, max(0.0, self.score)))
        if not self.reason:
            raise ValueError(f"{self.rule_name} produced an alert with no reason")

    def to_row(self) -> dict:
        return {"entity_id": self.entity_id, "rule_name": self.rule_name,
                "score": self.score, "reason": self.reason, "evidence": list(self.evidence)}


def alerts_to_frame(alerts) -> pd.DataFrame:
    df = pd.DataFrame([a.to_row() for a in alerts], columns=ALERT_COLUMNS)
    return df.sort_values(["score", "entity_id"], ascending=[False, True], ignore_index=True)


def ramp(value: float, floor: float, target: float, base: float = 0.0) -> float:
    """`base` at the rule's threshold, 1.0 once the evidence is overwhelming."""
    if value < floor:
        return 0.0
    grown = 1.0 if target <= floor else min(1.0, (value - floor) / (target - floor))
    return base + (1.0 - base) * grown
