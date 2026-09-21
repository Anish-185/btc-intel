"""Simplified GINe edge classifier, adapted from Multi-GNN (see docs/vendor_notes.md).

Train and inference live in .train / .infer and are imported directly, so that
`python -m engines.gnn.train` does not re-import a half-initialised package.
"""

from .data import GraphTensors, build_dataset, load_labels, temporal_split, z_norm
from .model import EdgeGINConv, GINe

__all__ = ["GraphTensors", "build_dataset", "load_labels", "temporal_split", "z_norm",
           "GINe", "EdgeGINConv"]
