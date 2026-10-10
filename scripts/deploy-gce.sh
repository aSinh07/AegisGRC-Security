#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
test -f .env.production || { echo ".env.production is required"; exit 1; }

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
  if curl -fsS http://127.0.0.1:8080/api/ready >/dev/null; then
    echo "AegisGRC is ready."
    docker compose -f docker-compose.production.yml ps
    exit 0
  fi
  sleep 2
done

echo "Readiness check failed; showing application logs."
docker compose -f docker-compose.production.yml logs --tail=100 aegis
exit 1
