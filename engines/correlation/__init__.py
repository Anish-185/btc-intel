"""IP ↔ cluster correlation. Produces probabilistic leads, never attribution.

Both directions: scorer.py goes from transactions to (cluster, IP) leads;
profile.py goes from a peer or ASN back to everything that evidence says about
it. docs/CORRELATION.md describes the pair.

Read engines/correlation/scorer.py's docstring before using any output of this
package in a report or hand-off.
"""

from .scorer import (Observation, asn_penalty, collect_observations, correlate,
                     infrastructure_penalty, raw_confidence, score_observations,
                     shared_ip_penalty)

from .profile import (asn_profile, build_sources, origination_answers, peer_profile,
                      transaction_origination)

__all__ = ["peer_profile", "asn_profile", "build_sources", "origination_answers",
           "transaction_origination", "Observation", "correlate", "collect_observations", "score_observations",
           "raw_confidence", "asn_penalty", "infrastructure_penalty", "shared_ip_penalty"]
