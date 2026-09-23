#!/usr/bin/env bash
# Start btc-intel: one process serving the API and the console.
#
# FastAPI serves the built front end from web/dist itself (mounted at /app), so
# an offline machine needs no second web server, no npm and no node_modules —
# only the static files the build machine produced.
#
# It also refuses to start a second server. The failure that prevents: a
# uvicorn from an earlier session keeps port 8000, the new one exits with
# "address already in use" somewhere in a log nobody is reading, and the
# browser spends the next hour talking to a build from before the fix. A demo
# does not survive that twice.
#
#   offline/run_offline.sh              # start on 127.0.0.1:8000
#   PORT=8010 offline/run_offline.sh    # somewhere else
#   HOST=0.0.0.0 offline/run_offline.sh # reachable from another machine
#   offline/run_offline.sh --check      # check the port and exit
#
# Nothing here reaches the network: uvicorn binds to loopback and every stage
# reads only what is already on disk.
set -euo pipefail

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8000}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
[ -x "$PYTHON" ] || PYTHON="python3"

# Who has the port? ss and lsof both exist on most boxes; try both, and treat
# "no tool available" as "cannot verify" rather than as "free".
port_owner() {
  if command -v ss >/dev/null 2>&1; then
    ss -ltnpH "sport = :$PORT" 2>/dev/null | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2
  elif command -v lsof >/dev/null 2>&1; then
    lsof -tiTCP:"$PORT" -sTCP:LISTEN 2>/dev/null | head -1
  fi
}

owner="$(port_owner || true)"
if [ -n "${owner:-}" ]; then
  cmd="$(tr '\0' ' ' < "/proc/$owner/cmdline" 2>/dev/null || ps -p "$owner" -o args= 2>/dev/null || echo '?')"
  started="$(ps -p "$owner" -o lstart= 2>/dev/null | sed 's/^ *//' || echo '?')"
  cat >&2 <<MSG
port $PORT is already in use — not starting a second server.

  pid      $owner
  started  $started
  command  $cmd

That process is serving the console right now, and it may be an older build
than your working tree. Stop it and run this again:

  kill $owner && offline/run_offline.sh

Or start this one somewhere else:

  PORT=8010 offline/run_offline.sh
MSG
  exit 1
fi

if [ "${1:-}" = "--check" ]; then
  echo "port $PORT is free"
  exit 0
fi

commit="$(git -C "$ROOT" rev-parse --short=7 HEAD 2>/dev/null || echo unknown)"
if [ -z "${commit#unknown}" ] && [ -f "$ROOT/offline/bundle.json" ]; then
  # An installed bundle has no .git directory. The commit it was built from is
  # in bundle.json, and the console needs it to decide whether it matches.
  commit="$("$PYTHON" -c 'import json;print(json.load(open("'"$ROOT"'/offline/bundle.json"))["commit"])' 2>/dev/null || echo unknown)"
fi

cd "$ROOT"
if [ -f web/dist/index.html ]; then
  echo "btc-intel — $HOST:$PORT — commit $commit"
  echo
  echo "  console   http://$HOST:$PORT/app/     (/ redirects here)"
  echo "  api docs  http://$HOST:$PORT/docs"
  echo
  echo "the console compares this commit with its own; a mismatch raises a banner"
else
  cat >&2 <<MSG
btc-intel api — $HOST:$PORT — commit $commit

web/dist/index.html is missing, so this serves the API only and http://$HOST:$PORT/
will say so rather than showing a console.

  built bundle:   run offline/build_wheelhouse.sh on the machine with internet
  developing:     npm --prefix web run build, or npm --prefix web run dev

MSG
fi
BTC_INTEL_COMMIT="$commit" exec "$PYTHON" -m uvicorn api.app:app --host "$HOST" --port "$PORT"
