"""Supervised origination: did this peer originate this transaction, or forward it?

Per `(txid, peer_ip, capture_id)` binary classification over the
`features.relay` matrix, fusing the three `engines.propagation` estimators (which
are columns of that matrix) with timing and peer-history features.

  corpus     thousands of labelled single-vantage captures from `generator/`'s
             gossip simulation, deterministic from `manifest.json`
  model      additive gradient boosting, isotonic calibration, abstention by
             construction and by the pre-registered cost rule, exact SHAP via
             `fusion.explain`
  evaluate   capture- and topology-grouped splits, and the section-9 rows
  pipeline   the CLI: `python -m origination.pipeline corpus|evaluate|predict`

Results: docs/ORIGINATION_RESULTS.md, and row 5 of eval/results.md section 9.

EXTENSION POINT — SEMI-SUPERVISED, AND WHY IT IS NOT BUILT
The natural next step is to learn from unlabelled captures as well: self-
training or a consistency objective over mainnet traffic, where labels do not
exist but announcements are plentiful. It is not built because there is nothing
to feed it. The repo holds no pool of real unlabelled mainnet captures — only two
hand-written fixtures — and a semi-supervised model whose unlabelled pool is
more simulator output would learn nothing the supervised model has not already
seen; it would only look like it used real data. The place to add it is
`OriginationModel.fit`, taking a second, unlabelled matrix from
`features.relay.build` over real captures, once such captures exist and have
passed `p2p.manifest` verification.
"""
