"""Origin inference measured against known truth, on real relay data.

Everywhere else in `eval/` the truth comes from our own simulator, so the
accuracy figures describe the simulator. This package is the one place where the
broadcaster is a real Bitcoin node whose address we know before the measurement
starts, and the observer is a real node writing a real capture — which is the
only setting in which "how often is the origin estimator right" is a statement
about Bitcoin rather than about `generator/`.

The protocol is pre-registered in docs/GROUND_TRUTH.md, committed with this
harness and before any signet number existed.

Three modules, and the split matters:

  broadcast   runs on the COLLECTION host. Drives a signet node through
              bitcoin-cli and writes the label file. Never imported by the
              report — `tests/test_ground_truth.py` asserts that.
  preflight   refuses to score a capture that cannot support a conclusion.
  score       the measurement, routed into `eval.report`'s section 9.
"""
