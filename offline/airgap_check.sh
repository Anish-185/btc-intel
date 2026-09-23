#!/usr/bin/env bash
# Everything in OFFLINE_CHECKLIST.md that a script can check, with no network.
#
#   unshare -rn sh -c 'ip link set lo up; ./offline/airgap_check.sh'
#
# `unshare -rn` puts this in a kernel network namespace with nothing but
# loopback — a real air gap, without taking your own machine off the network
# and without root. On the demo box itself, with the cable out or the
# interface down, run it directly.
#
# It does not replace opening the console in a browser: no script can tell you
# whether the graph looks right.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
[ -x "$PY" ] || PY="python3"
PORT="${PORT:-8000}"
BASE="127.0.0.1:$PORT"

pass=0; fail=0
check() {
  if [ "$1" = 0 ]; then printf '  \033[32mPASS\033[0m  %s\n' "$2"; pass=$((pass + 1))
  else printf '  \033[31mFAIL\033[0m  %s\n' "$2"; fail=$((fail + 1)); fi
}
section() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
cleanup() { [ -n "${server:-}" ] && kill "$server" 2>/dev/null; }
trap cleanup EXIT

section "there is no network"
# If this passes on a connected machine the whole run means nothing, so it is
# the first thing checked rather than an assumption.
if curl -sS --max-time 5 -o /dev/null https://pypi.org 2>/dev/null; then
  check 1 "outbound HTTPS is impossible — IT IS NOT. This machine is online; the rest proves nothing"
else
  check 0 "outbound HTTPS is impossible"
fi

section "the pipeline, on sample data"
$PY -m generator.main --n-actors 60 --n-transactions 400 --seed 7 \
    --output data/raw --formats csv >/tmp/airgap-generator.log 2>&1
check $? "generator writes a dataset"
$PY -m ingest.pipeline --input data/raw/ >/tmp/airgap-ingest.log 2>&1
check $? "ingest parses, validates and enriches"
$PY -m fusion.pipeline >/tmp/airgap-fusion.log 2>&1
check $? "every engine runs and the alert list is written"
$PY -c "
import json
alerts = json.load(open('data/processed/final_alerts.json'))['alerts']
assert alerts, 'the alert list is empty'
print(f'        {len(alerts)} alerts')"
check $? "the alert list has content"

section "the server"
./offline/run_offline.sh >/tmp/airgap-server.log 2>&1 &
server=$!
for _ in $(seq 40); do curl -sf "$BASE/version" >/dev/null 2>&1 && break; sleep 1; done
curl -sf "$BASE/version" >/dev/null; check $? "the API answers /version"
curl -sf "$BASE/stats" >/dev/null;   check $? "/stats answers"
curl -sf "$BASE/alerts?limit=5" >/dev/null; check $? "/alerts answers"

section "the console"
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/")
[ "$code" = 307 ]; check $? "/ redirects to the console (got $code)"
curl -s "$BASE/app/" | grep -q '<div id="root">'; check $? "/app/ serves the console shell"
# The one that bites: /alerts is an API path AND a console route.
curl -s "$BASE/app/alerts" | grep -q '<div id="root">'
check $? "a deep link serves the app, not JSON"
asset=$(curl -s "$BASE/app/" | grep -o '/app/assets/index-[A-Za-z0-9_-]*\.js' | head -1)
curl -sf "$BASE$asset" >/dev/null; check $? "the script bundle loads ($asset)"
style=$(curl -s "$BASE/app/" | grep -o '/app/assets/index-[A-Za-z0-9_-]*\.css' | head -1)
curl -sf "$BASE$style" >/dev/null; check $? "the stylesheet loads"
curl -s "$BASE/app/" | grep -qiE 'fonts\.googleapis|cdn\.|unpkg|jsdelivr'
[ $? -ne 0 ]; check $? "the page shell references no CDN"

section "the case, the graph and the report"
entity=$(curl -s "$BASE/alerts?limit=1" | $PY -c 'import sys,json;print(json.load(sys.stdin)["alerts"][0]["entity_id"])')
curl -sf "$BASE/entities/$entity" >/dev/null; check $? "entity detail answers"
nodes=$(curl -sf "$BASE/graph/nodes/$entity/neighbors?direction=both&limit=20&offset=0" \
        | $PY -c 'import sys,json;print(len(json.load(sys.stdin)["nodes"]))' 2>/dev/null)
[ "${nodes:-0}" -gt 0 ]; check $? "the investigation graph returns ${nodes:-0} nodes"
curl -sf "$BASE/entities/$entity/report" -o /tmp/airgap-case.pdf; check $? "the report endpoint answers"
head -c 4 /tmp/airgap-case.pdf 2>/dev/null | grep -q '%PDF'
check $? "it is a real PDF ($(stat -c%s /tmp/airgap-case.pdf 2>/dev/null || echo 0) bytes)"
$PY -c "
import hashlib, json, sys
import custody
digest = hashlib.sha256(open('/tmp/airgap-case.pdf','rb').read()).hexdigest()
exports = [e for e in custody.read() if e['action'] == 'export.case_report']
assert exports, 'the export was not recorded in the custody ledger'
assert exports[-1]['detail']['report_sha256'] == digest, 'the ledger hash does not match the file'
" 2>/dev/null
check $? "the ledger's hash matches the PDF that was downloaded"

section "live monitoring and custody"
curl -sf -X POST "$BASE/monitor/start" >/dev/null; check $? "the monitor starts"
curl -sf -X POST "$BASE/monitor/simulate?transactions=20" >/dev/null; check $? "an arrival is dropped in"
handled=0
for _ in $(seq 30); do
  handled=$(curl -s "$BASE/monitor/status" | $PY -c 'import sys,json;print(json.load(sys.stdin)["files"])' 2>/dev/null || echo 0)
  [ "${handled:-0}" -ge 1 ] && break
  sleep 1
done
[ "${handled:-0}" -ge 1 ]; check $? "the arrival was handled (${handled:-0} file(s))"
curl -sf -X POST "$BASE/monitor/stop" >/dev/null; check $? "the monitor stops"
# The API serves compact JSON, so match on the value rather than on spacing.
curl -s "$BASE/custody/verify" | $PY -c 'import sys,json;sys.exit(0 if json.load(sys.stdin)["chain_intact"] else 1)'
check $? "the custody chain verifies"

section "the source scan and the suite"
$PY -m pytest tests/test_offline_guarantee.py -q >/tmp/airgap-guard.log 2>&1
check $? "no network calls anywhere in our source"
$PY -m pytest -q >/tmp/airgap-suite.log 2>&1
check $? "the test suite passes offline (tail /tmp/airgap-suite.log)"

printf '\n\033[1m== %d passed, %d failed ==\033[0m\n' "$pass" "$fail"
[ "$fail" = 0 ]
