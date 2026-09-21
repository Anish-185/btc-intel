#!/usr/bin/env bash
# Fetch public IP intelligence into data/intel/. RUN ONCE WHILE ONLINE.
#
# Everything downstream of this is air-gapped: the pipeline only ever reads the
# files this script leaves behind, never the network. Re-run it to refresh.
#
# Sources (each is public and freely redistributable — check before adding more):
#
#   known_bitcoin_nodes.json  Bitnodes snapshot of reachable Bitcoin nodes.
#                             https://bitnodes.io/api/  — project github.com/ayeowch/bitnodes, MIT.
#                             Used to recognise public relays: a node in this
#                             list forwards thousands of other people's
#                             transactions, so seeing it is nearly no evidence.
#
#   tor_exit_nodes.txt        The Tor Project's own bulk exit list.
#                             https://check.torproject.org/torbulkexitlist
#                             Public domain / CC0. An exit IP is shared by
#                             thousands of unrelated users.
#
#   hosting_asns.txt          Curated hosting / cloud / VPN ASN list from
#                             github.com/brianhama/bad-asn-list (MIT), which
#                             aggregates datacentre and VPN providers. Merged
#                             with the starter list in config.yaml
#                             (geoip.high_risk_asns) at load time.
#
# manifest.json records each file's source URL, download date and SHA-256, so
# an analyst can say exactly which snapshot a finding was based on.

set -euo pipefail

DIR="${1:-data/intel}"
mkdir -p "$DIR"

BITNODES_URL="https://bitnodes.io/api/v1/snapshots/latest/"
TOR_URL="https://check.torproject.org/torbulkexitlist"
ASN_URL="https://raw.githubusercontent.com/brianhama/bad-asn-list/master/bad-asn-list.csv"

fetch() {
  local url="$1" out="$2"
  echo "fetching $url"
  if ! curl -fsSL --retry 3 --max-time 120 -o "$out.tmp" "$url"; then
    echo "  FAILED: $url — leaving any existing $out in place" >&2
    rm -f "$out.tmp"
    return 1
  fi
  mv "$out.tmp" "$out"
}

ok_bitnodes=1; ok_tor=1; ok_asn=1
fetch "$BITNODES_URL" "$DIR/known_bitcoin_nodes.json" || ok_bitnodes=0
fetch "$TOR_URL"      "$DIR/tor_exit_nodes.txt"       || ok_tor=0
fetch "$ASN_URL"      "$DIR/hosting_asns.txt"         || ok_asn=0

python3 - "$DIR" "$BITNODES_URL" "$TOR_URL" "$ASN_URL" <<'PY'
import hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path

directory = Path(sys.argv[1])
urls = {"known_bitcoin_nodes.json": sys.argv[2],
        "tor_exit_nodes.txt": sys.argv[3],
        "hosting_asns.txt": sys.argv[4]}

manifest = {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "files": {}}
for name, url in urls.items():
    path = directory / name
    if not path.exists():
        manifest["files"][name] = {"source_url": url, "status": "missing"}
        continue
    manifest["files"][name] = {
        "source_url": url,
        "downloaded_at": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
                                 .isoformat(timespec="seconds"),
        "bytes": path.stat().st_size,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "status": "ok",
    }
(directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(json.dumps(manifest, indent=2))
PY

if [ "$ok_bitnodes$ok_tor$ok_asn" != "111" ]; then
  echo "one or more sources failed; the pipeline still runs with whatever is present" >&2
fi
