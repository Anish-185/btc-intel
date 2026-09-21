"""Combining every engine's signal into one ranked, explained alert list."""

from .explain import Explanation, build_reason, explain_entity, shap_contributions
from .stacker import SIGNALS, Stacker, ablation, default_weights, train
from .taint import Taint, compute_taint, load_watchlist, propagate, seeds_from_watchlist

__all__ = ["Taint", "propagate", "compute_taint", "seeds_from_watchlist", "load_watchlist", "Stacker", "SIGNALS",
           "train", "ablation", "default_weights", "Explanation", "explain_entity",
           "shap_contributions", "build_reason"]
