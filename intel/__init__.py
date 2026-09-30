"""An offline, sealed, provenance-tracked attribution store (docs/TAGSTORE.md).

Modelled on GraphSense TagPacks: a tag says what an address, or the cluster an
address defines, is (an exchange, a sanctioned service, a ransomware
collector), who said so, where and when. Tags arrive in sealed bundles built
on a connected machine and carried across the air gap; this package never
fetches anything.
"""
