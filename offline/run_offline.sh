#!/usr/bin/env bash
# Start btc-intel's API, refusing to start a second one.
#
# The failure this prevents: a uvicorn from an earlier session keeps port 8000,
# the new one exits with "address already in use" somewhere in a log nobody is
# reading, and the browser spends the next hour talking to a build from before
# the fix. A demo does not survive that twice.
#
#   offline/run_offline.sh              # start on 127.0.0.1:8000
#   PORT=8010 offline/run_offline.sh    # somewhere else
#   offline/run_offline.sh --check      # check the port and exit
#
# Nothing here reaches the network: uvicorn binds to loopback and the pipeline
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
echo "btc-intel api — $HOST:$PORT — commit $commit"
echo "the console compares this commit with its own; a mismatch raises a banner"
cd "$ROOT"
BTC_INTEL_COMMIT="$commit" exec "$PYTHON" -m uvicorn api.app:app --host "$HOST" --port "$PORT"
