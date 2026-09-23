#!/usr/bin/env bash
# Install btc-intel on a machine with no network. Run from the repository root.
#
#   ./offline/install.sh                 # venv in .venv, from offline/wheelhouse
#   PYTHON=python3.12 ./offline/install.sh
#   ./offline/install.sh --venv /opt/btc-intel/venv
#
# Everything this needs was gathered by offline/build_wheelhouse.sh while the
# other machine still had internet. Nothing here reaches out: pip runs with
# --no-index, which makes a missing wheel an error rather than a download.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VENV="${VENV:-$ROOT/.venv}"
PYTHON="${PYTHON:-python3}"
WHEELHOUSE="$ROOT/offline/wheelhouse"

while [ $# -gt 0 ]; do
  case "$1" in
    --venv) VENV="$2"; shift 2 ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '\n\033[1;31m%s\033[0m\n' "$*" >&2; exit 1; }

# --- 1. is the bundle here at all? ----------------------------------------
say "checking the bundle"
[ -d "$WHEELHOUSE" ] || fail "no offline/wheelhouse/ — this copy of the repository was never
bundled. Run offline/build_wheelhouse.sh on a machine with internet, then copy
the whole directory across."

wheels=$(find "$WHEELHOUSE" -name '*.whl' | wc -l)
[ "$wheels" -gt 0 ] || fail "offline/wheelhouse/ is empty. Re-run offline/build_wheelhouse.sh."
echo "$wheels wheel(s) in offline/wheelhouse"

# --- 2. does this machine's Python match what the wheels were built for? ---
# A mismatch is the single most likely way this install fails, and pip's own
# error for it ("no matching distribution found") names neither cause nor fix.
have="$("$PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null)" \
  || fail "cannot run '$PYTHON'. Install Python 3.11 or newer, or set PYTHON=/path/to/python3."

if [ -f offline/bundle.json ]; then
  want="$("$PYTHON" -c 'import json;print(json.load(open("offline/bundle.json"))["python_version"])')"
  if [ "$want" != "$have" ]; then
    fail "the wheelhouse was built for Python $want; '$PYTHON' is $have.

Wheels are tagged with the interpreter version, so these will not install.
Either:
  * use the matching interpreter here —  PYTHON=python$want ./offline/install.sh
  * or rebuild the bundle for this one, on the machine that has internet:
        offline/build_wheelhouse.sh --python-version $have"
  fi
  echo "Python $have matches the bundle"
else
  echo "no offline/bundle.json — continuing, but nothing is checked against it" >&2
fi

# --- 3. the virtual environment -------------------------------------------
say "creating the virtual environment at $VENV"
if [ -d "$VENV" ]; then
  echo "already exists — reusing it"
else
  # --without-pip would be smaller, but then there is no pip to install with
  # and ensurepip is not always present on a stripped Ubuntu image.
  "$PYTHON" -m venv "$VENV" || fail "could not create a venv. On Ubuntu:  sudo apt install python3-venv
(that is the one thing this install needs from the distribution, and it is on
the base image of every Ubuntu release we have tried.)"
fi
VPY="$VENV/bin/python"

# --- 4. the dependencies ---------------------------------------------------
say "installing from offline/wheelhouse (no network)"
requirements=(-r offline/requirements.txt)
[ -f offline/requirements.txt ] || requirements=("$WHEELHOUSE"/*.whl)

# --no-index is the whole point: with it, a wheel that was never downloaded is
# a hard error here rather than a silent reach for pypi.org.
"$VPY" -m pip install --no-index --find-links "$WHEELHOUSE" --upgrade pip >/dev/null 2>&1 || true
"$VPY" -m pip install --no-index --find-links "$WHEELHOUSE" "${requirements[@]}" \
  || fail "install failed. The wheelhouse is missing something it needs — the line above
names it. Rebuild on the online machine with the same --python-version and
--platform as this box."

installed=$("$VPY" -m pip list --format=freeze 2>/dev/null | wc -l)
echo "$installed package(s) installed"

# --- 5. the trained weights ------------------------------------------------
say "installing model weights"
mkdir -p models
staged=0
for path in offline/models/*; do
  [ -e "$path" ] || continue
  cp -f "$path" models/ && staged=$((staged + 1))
done
if [ "$staged" = 0 ]; then
  cat >&2 <<'MSG'
no weights in offline/models/.

Not fatal: the fusion stacker falls back to the risk weights in config.yaml and
says so in its metrics, and the GNN engine contributes nothing rather than
failing. But the demo is less convincing, and the numbers will not match the
ones in the evaluation. Train them on the build machine and re-bundle.
MSG
else
  echo "$staged file(s) into models/"
fi

# --- 6. the intelligence snapshot ------------------------------------------
say "installing the IP intelligence snapshot"
mkdir -p data/intel
if compgen -G "offline/intel/*" >/dev/null; then
  cp -f offline/intel/* data/intel/
  if [ -f data/intel/manifest.json ]; then
    "$VPY" - <<'PY'
import json
from pathlib import Path
manifest = json.loads(Path("data/intel/manifest.json").read_text())
print(f"  snapshot taken {manifest.get('generated_at', '?')}")
for name, meta in manifest.get("files", {}).items():
    print(f"  {name:<26} {meta.get('status', '?')}  {meta.get('bytes', 0)} bytes")
PY
  fi
else
  cat >&2 <<'MSG'
no offline/intel/ in the bundle.

Relay and Tor-exit classification degrades to the starter lists in config.yaml.
Nothing fetches these at run time, so this is a quality loss, not a failure.
Re-run offline/fetch_intel.sh on the online machine and re-bundle.
MSG
fi

# --- 7. GeoIP, which cannot be automated -----------------------------------
say "checking for the GeoIP databases"
missing=()
for db in GeoLite2-Country.mmdb GeoLite2-ASN.mmdb; do
  [ -f "data/geoip/$db" ] || missing+=("$db")
done
if [ ${#missing[@]} -eq 0 ]; then
  ls -lh data/geoip/*.mmdb | awk '{print "  " $9 "  " $5}'
else
  printf '\n\033[1;33m%s\033[0m %s\n' "GeoIP databases missing:" "${missing[*]}" >&2
  cat >&2 <<MSG

These are the one thing the build script cannot fetch for you: MaxMind requires
a free account and a signed licence, so the download needs credentials nobody
should bake into a repository.

  What still works:  everything. Ingest, clustering, features, rules, the GNN,
                     origin estimation, alerts, the console, the PDF report.
  What is lost:      the country and ASN columns are null, so hosting/VPN ASN
                     classification falls back to the list in config.yaml and
                     geographic context is absent from the case report.

  How to fix it:     offline/GEOIP_SETUP.md — five minutes on a machine with
                     internet, then copy two files into data/geoip/.

This is a warning, not an error. The install has finished.
MSG
fi

# --- 8. does it actually run? ---------------------------------------------
say "smoke test"
"$VPY" - <<'PY'
import importlib.util
import sys

required = ["pandas", "numpy", "networkx", "sklearn", "pydantic", "yaml", "maxminddb",
            "pyarrow", "fastapi", "uvicorn", "joblib", "reportlab"]
optional = ["torch", "torch_geometric"]

missing = [name for name in required if importlib.util.find_spec(name) is None]
for name in required:
    if name not in missing:
        print(f"  {name}")
for name in optional:
    if importlib.util.find_spec(name) is None:
        print(f"  {name} — absent; the GNN engine scores nothing (bundled with --no-gnn?)")
    else:
        print(f"  {name}")
if missing:
    print(f"\nmissing: {', '.join(missing)}", file=sys.stderr)
    sys.exit(1)

import config
cfg = config.load()
assert cfg["offline"] is True, "config.yaml: offline must be true"
print("  config.yaml loads, offline: true")
PY

cat <<MSG

Installed. Next:

  1. Generate or copy in a dataset, then run the pipeline:
         $VENV/bin/python -m generator.main --output data/raw
         $VENV/bin/python -m ingest.pipeline --input data/raw/
         $VENV/bin/python -m fusion.pipeline

  2. Start the console (API and front end, one process):
         ./offline/run_offline.sh

  3. Work through offline/OFFLINE_CHECKLIST.md with the network cable out.
MSG
