#!/usr/bin/env bash
set -euo pipefail
DUMP="${1:?usage: verify-restore-drill.sh backup.dump}"
command -v docker >/dev/null
sha256sum -c "$DUMP.sha256"
name="aegis-restore-drill-$$"
port="${AEGIS_RESTORE_DRILL_PORT:-55432}"
cleanup(){ docker rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker run -d --name "$name" -e POSTGRES_USER=aegis_restore -e POSTGRES_PASSWORD=restore_only -e POSTGRES_DB=aegis_restore -p "127.0.0.1:$port:5432" postgres:16-alpine >/dev/null
for _ in $(seq 1 30); do docker exec "$name" pg_isready -U aegis_restore -d aegis_restore >/dev/null 2>&1 && break; sleep 1; done
docker exec "$name" pg_isready -U aegis_restore -d aegis_restore >/dev/null
docker cp "$DUMP" "$name:/tmp/aegis.dump"
docker exec "$name" pg_restore --no-owner --no-acl -U aegis_restore -d aegis_restore /tmp/aegis.dump
tables=$(docker exec "$name" psql -U aegis_restore -d aegis_restore -Atc "select count(*) from pg_tables where schemaname='public'")
[ "$tables" -gt 0 ] || { echo "FAIL: restored database has no public tables"; exit 1; }
echo "PASS: isolated restore drill restored $tables public tables. Production database and volume were untouched."
