#!/usr/bin/env bash
set -euo pipefail
: "${DATABASE_URL:?DATABASE_URL is required}"
OUT="${AEGIS_BACKUP_DIR:-/tmp/aegis-backups}"
mkdir -p "$OUT"; chmod 700 "$OUT"
ts=$(date -u +%Y%m%dT%H%M%SZ)
file="$OUT/aegis-$ts.dump"
pg_dump --format=custom --no-owner --no-acl --dbname="$DATABASE_URL" --file="$file"
sha256sum "$file" | tee "$file.sha256"
echo "Backup created: $file"
echo "Production database was read only; no restore was performed against production."
