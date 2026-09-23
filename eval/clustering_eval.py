"""Does the clustering recover the actors the generator actually created?

Everything downstream is scored per entity, and an entity is whatever
`graph/clustering.py` decided. If the clustering is wrong, a detection metric
can look fine while pointing at the wrong thing: one entity holding two
unrelated actors alerts once and scores as a catch.

The measure is the Adjusted Rand Index between our clusters and the generator's
true wallet→actor assignment. ARI rather than accuracy because cluster *labels*
are arbitrary — ours are named after a member address, the generator's are
`C000123` — so only the partition can be compared. It is adjusted for chance,
so 0 is what random grouping scores and 1 is exact agreement.

Reported beside it: how often the collapse guard fired. A single bad
change-address guess on an exchange transaction can merge thousands of
unrelated users into one entity, and the guard flags a cluster above
`graph.collapse_guard.max_cluster_wallets` for review rather than trusting it.
A high ARI with the guard firing constantly is not a good result.
"""

from __future__ import annotations

import pandas as pd
from sklearn.metrics import adjusted_rand_score

from graph.builder import build_graph, graph_transactions
from graph.clustering import cluster_wallets

from .datasets import Dataset


def evaluate(dataset: Dataset, cfg: dict) -> dict:
    """ARI against ground truth, plus what the collapse guard did."""
    frame = dataset.frame()
    transactions = list(graph_transactions(build_graph(frame, cfg)))
    result = cluster_wallets(transactions, cfg)
    truth = dataset.ground_truth()["wallets"]          # wallet -> true cluster id

    # Only wallets the generator labelled and the clustering actually saw. A
    # wallet that never transacted has no cluster in either partition, and
    # counting it as agreement would be free credit.
    shared = sorted(set(truth) & set(result.wallet_to_cluster))
    ours = [result.wallet_to_cluster[w] for w in shared]
    theirs = [truth[w] for w in shared]
    ari = adjusted_rand_score(theirs, ours) if shared else 0.0

    sizes = pd.Series({cid: len(m) for cid, m in result.clusters.items()})
    flagged = result.flags
    limit = cfg["graph"]["collapse_guard"]["max_cluster_wallets"]

    return {
        "dataset": dataset.describe(),
        "wallets_scored": len(shared),
        "our_clusters": len(result.clusters),
        "true_clusters": len(set(theirs)),
        "adjusted_rand_index": round(float(ari), 4),
        "largest_cluster": int(sizes.max()) if len(sizes) else 0,
        "mean_cluster_size": round(float(sizes.mean()), 2) if len(sizes) else 0.0,
        "singletons": int((sizes == 1).sum()),
        "collapse_guard_limit": limit,
        "collapse_guard_fired": len(flagged),
        "wallets_in_flagged_clusters": int(sum(len(result.clusters[c]) for c in flagged)),
    }


def comparison(datasets: dict[str, Dataset], cfg: dict) -> pd.DataFrame:
    """One row per dataset, so the shifted set sits beside the standard one."""
    rows = []
    for label, dataset in datasets.items():
        row = evaluate(dataset, cfg)
        rows.append({"set": label, **{k: v for k, v in row.items() if k != "dataset"}})
    return pd.DataFrame(rows)
