#!/usr/bin/env bash
set -euo pipefail

backup="${1:-}"
[ -n "$backup" ] && [ -s "$backup" ] || { echo "Usage: $0 <non-empty pg_dump custom-format file>"; exit 2; }

image="${POSTGRES_RESTORE_IMAGE:-postgres:16-alpine}"
name="aegis-restore-check-${RANDOM}-$$"
cleanup(){ docker rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker run -d --name "$name" -e POSTGRES_PASSWORD=restorecheck -e POSTGRES_USER=restorecheck -e POSTGRES_DB=restorecheck "$image" >/dev/null
for _ in $(seq 1 30); do
  docker exec "$name" pg_isready -U restorecheck -d restorecheck >/dev/null 2>&1 && break
  sleep 1
done
docker exec "$name" pg_isready -U restorecheck -d restorecheck >/dev/null

cat "$backup" | docker exec -i "$name" pg_restore --no-owner --no-privileges -U restorecheck -d restorecheck >/dev/null
count="$(docker exec "$name" psql -U restorecheck -d restorecheck -Atqc "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")"
[ "$count" -gt 0 ] || { echo "Restore produced no public tables"; exit 1; }
echo "Backup restore verification passed ($count public tables)."
