"""IP ↔ cluster correlation. Produces probabilistic leads, never attribution.

Read engines/correlation/scorer.py's docstring before using any output of this
package in a report or hand-off.
"""

from .scorer import (Observation, asn_penalty, collect_observations, correlate,
                     infrastructure_penalty, raw_confidence, score_observations,
                     shared_ip_penalty)

__all__ = ["Observation", "correlate", "collect_observations", "score_observations",
           "raw_confidence", "asn_penalty", "infrastructure_penalty", "shared_ip_penalty"]
