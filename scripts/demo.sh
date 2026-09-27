#!/usr/bin/env bash
# The stage demo, offline and deterministic on the served demo dataset.
# Steps, flags and what each line shows: scripts/demo.py and docs/DEMO_SCRIPT.md.
#
#   scripts/demo.sh --preflight   # before going on stage
#   scripts/demo.sh               # the demo (add --pause to step by hand)
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
[ -x "$PY" ] || PY="python3"
exec "$PY" "$ROOT/scripts/demo.py" "$@"
