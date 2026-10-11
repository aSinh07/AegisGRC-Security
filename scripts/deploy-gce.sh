#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
test -f .env.production || { echo ".env.production is required"; exit 1; }

PRODUCTION_DB_VOLUME="aegisgrc-security_aegis-db"
if ! docker volume inspect "$PRODUCTION_DB_VOLUME" >/dev/null 2>&1; then
  echo "Required production database volume $PRODUCTION_DB_VOLUME does not exist; refusing to initialize a replacement database."
  exit 1
fi

required=(POSTGRES_USER POSTGRES_PASSWORD POSTGRES_DB DATABASE_URL ASSESSMENT_SESSION_SECRET EVIDENCE_HMAC_KEY REPORT_SIGNING_KEY GRC_AUTOMATION_SECRET TOTP_ENCRYPTION_KEY)
for key in "${required[@]}"; do
  value="$(grep -E "^${key}=" .env.production | tail -1 | cut -d= -f2- || true)"
  normalized="$(printf '%s' "$value" | tr '[:lower:]' '[:upper:]')"
  if [ -z "$value" ] || [[ "$normalized" == REPLACE_* ]] || [[ "$normalized" == CHANGE_THIS* ]] || [[ "$normalized" == CHANGEME* ]]; then
    echo "Missing or placeholder production secret: $key"
    exit 1
  fi
done

node_env="$(grep -E '^NODE_ENV=' .env.production | tail -1 | cut -d= -f2- || true)"
cookie_secure="$(grep -E '^COOKIE_SECURE=' .env.production | tail -1 | cut -d= -f2- || true)"
[ "$node_env" = "production" ] || { echo "NODE_ENV must be production"; exit 1; }
[ "$cookie_secure" = "true" ] || { echo "COOKIE_SECURE must be true"; exit 1; }

totp_key="$(grep -E '^TOTP_ENCRYPTION_KEY=' .env.production | tail -1 | cut -d= -f2- || true)"
if ! printf '%s' "$totp_key" | base64 -d 2>/dev/null | awk 'BEGIN{ok=0} { } END{ }' >/dev/null; then
  echo "TOTP_ENCRYPTION_KEY must be valid base64"
  exit 1
fi
totp_bytes="$(printf '%s' "$totp_key" | base64 -d 2>/dev/null | wc -c | tr -d ' ')"
[ "$totp_bytes" = "32" ] || { echo "TOTP_ENCRYPTION_KEY must decode to exactly 32 bytes"; exit 1; }

BACKUP_DIR="${BACKUP_DIR:-./backups}"
mkdir -p "$BACKUP_DIR"
if docker compose -f docker-compose.production.yml ps --status running postgres 2>/dev/null | grep -q postgres; then
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  echo "Creating pre-deploy PostgreSQL backup..."
  backup_path="$BACKUP_DIR/aegis-$stamp.dump"
  docker compose -f docker-compose.production.yml exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' > "$backup_path"
  test -s "$backup_path" || { echo "PostgreSQL backup is empty; refusing deployment."; rm -f "$backup_path"; exit 1; }
  docker compose -f docker-compose.production.yml exec -T postgres sh -c 'pg_restore --version' >/dev/null
  docker run --rm -i postgres:16-alpine pg_restore -l < "$backup_path" >/dev/null || { echo "PostgreSQL backup validation failed; refusing deployment."; exit 1; }
  echo "Verified pre-deploy backup: $backup_path"
fi

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
