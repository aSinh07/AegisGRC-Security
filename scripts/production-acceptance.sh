#!/usr/bin/env bash
set -euo pipefail
BASE="${AEGIS_ACCEPTANCE_URL:-http://127.0.0.1:8080}"
EXPECTED="${AEGIS_EXPECTED_COMMIT:-unknown}"
OUT="${AEGIS_ACCEPTANCE_OUT:-/tmp/aegis-production-acceptance.txt}"
tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT
code(){ curl -ksS -o "$tmp" -w '%{http_code}' "$1"; }
ready=$(code "$BASE/api/ready"); [ "$ready" = 200 ] || { echo "FAIL readiness HTTP $ready"; exit 1; }
grep -q '"ok":true' "$tmp" || { echo "FAIL readiness payload"; exit 1; }
health=$(code "$BASE/api/health"); [ "$health" = 401 ] || { echo "FAIL protected health HTTP $health"; exit 1; }
root=$(code "$BASE/"); [ "$root" = 200 ] || { echo "FAIL public landing HTTP $root"; exit 1; }
workspace=$(code "$BASE/index.html"); [ "$workspace" = 401 ] || { echo "FAIL anonymous workspace HTTP $workspace"; exit 1; }
for p in privacy terms security; do x=$(code "$BASE/$p"); [ "$x" = 200 ] || { echo "FAIL $p HTTP $x"; exit 1; }; done
asset=$(code "$BASE/dashboard.js"); [ "$asset" = 401 ] || { echo "FAIL protected dashboard asset HTTP $asset"; exit 1; }
{
 echo "AegisGRC production acceptance PASS"
 echo "commit=$EXPECTED"
 echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
 echo "base=$BASE"
 echo "readiness=200 health=401 root=200 workspace=401 dashboard_asset=401 privacy=200 terms=200 security=200"
} | tee "$OUT"
