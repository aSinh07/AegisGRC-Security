#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
test -f .env.production || { echo ".env.production is required"; exit 1; }\n\nrequired=(POSTGRES_USER POSTGRES_PASSWORD POSTGRES_DB DATABASE_URL ASSESSMENT_SESSION_SECRET EVIDENCE_HMAC_KEY REPORT_SIGNING_KEY GRC_AUTOMATION_SECRET)\nfor key in "${required[@]}"; do\n  value="$(grep -E "^${key}=" .env.production | tail -1 | cut -d= -f2- || true)"\n  if [ -z "$value" ] || [[ "$value" == REPLACE_* ]] || [[ "$value" == replace-* ]]; then echo "Missing or placeholder production secret: $key"; exit 1; fi\ndone\n\nBACKUP_DIR="${BACKUP_DIR:-./backups}"\nmkdir -p "$BACKUP_DIR"\nif docker compose -f docker-compose.production.yml ps --status running postgres 2>/dev/null | grep -q postgres; then\n  stamp="$(date -u +%Y%m%dT%H%M%SZ)"\n  echo "Creating pre-deploy PostgreSQL backup..."\n  docker compose -f docker-compose.production.yml exec -T postgres pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc > "$BACKUP_DIR/aegis-$stamp.dump"\nfi

echo "Pulling release..."
git pull --ff-only origin main

echo "Building application image..."
docker compose -f docker-compose.production.yml build aegis

echo "Starting PostgreSQL without deleting its named volume..."
docker compose -f docker-compose.production.yml up -d postgres

echo "Starting/updating AegisGRC..."
docker compose -f docker-compose.production.yml up -d --no-deps aegis

echo "Waiting for readiness..."
for i in $(seq 1 30); do
  if body="$(curl -fsS http://127.0.0.1:8080/api/ready)" && echo "$body" | grep -q '"mode":"postgres"'; then
    echo "AegisGRC is ready with PostgreSQL persistence."
    docker compose -f docker-compose.production.yml ps
    exit 0
  fi
  sleep 2
done

echo "Readiness check failed; showing application logs."
docker compose -f docker-compose.production.yml logs --tail=100 aegis
exit 1
