#!/usr/bin/env bash
set -euo pipefail
URL="${AEGIS_LOAD_URL:-http://127.0.0.1:8080/api/ready}"
REQUESTS="${AEGIS_LOAD_REQUESTS:-500}"
CONCURRENCY="${AEGIS_LOAD_CONCURRENCY:-25}"
MAX_SECONDS="${AEGIS_LOAD_MAX_SECONDS:-20}"
command -v curl >/dev/null
start=$(date +%s)
tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT
seq "$REQUESTS" | xargs -P "$CONCURRENCY" -I{} sh -c 'curl -fsS --max-time 10 "$1" >/dev/null' _ "$URL" || { echo "FAIL: readiness request failed under concurrency"; exit 1; }
elapsed=$(( $(date +%s)-start ))
[ "$elapsed" -le "$MAX_SECONDS" ] || { echo "FAIL: $REQUESTS requests at concurrency $CONCURRENCY took ${elapsed}s (budget ${MAX_SECONDS}s)"; exit 1; }
printf 'PASS: %s readiness requests at concurrency %s completed in %ss.\n' "$REQUESTS" "$CONCURRENCY" "$elapsed"
