#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
COMPOSE=(docker compose -f docker-compose.production.yml)
VOLUME="aegisgrc-security_aegis-db"
PUBLIC_URL="${AEGIS_PUBLIC_URL:-https://aegisgrc-security.duckdns.org}"
fail(){ printf 'FAIL: %s\n' "$*" >&2; exit 1; }
ok(){ printf 'PASS: %s\n' "$*"; }
command -v docker >/dev/null || fail "Docker missing"
command -v curl >/dev/null || fail "curl missing"
docker volume inspect "$VOLUME" >/dev/null 2>&1 || fail "Existing production PostgreSQL volume missing"
ok "Existing PostgreSQL volume present"
"${COMPOSE[@]}" ps --status running postgres | grep -q postgres || fail "PostgreSQL container not running"
"${COMPOSE[@]}" exec -T postgres sh -c 'pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"' >/dev/null || fail "PostgreSQL not ready"
ok "PostgreSQL accepting connections"
"${COMPOSE[@]}" exec -T postgres sh -c 'psql -X -q -t -A -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT count(*) FROM information_schema.tables WHERE table_schema = '\''public'\''"' | grep -Eq '^[1-9][0-9]*$' || fail "PostgreSQL schema query failed"
ok "Production database schema readable"
body="$(curl --fail --silent --show-error --max-time 15 http://127.0.0.1:8080/api/ready)" || fail "Local readiness unavailable"
printf '%s' "$body" | grep -Eq '"ok"[[:space:]]*:[[:space:]]*true' || fail "Local readiness not OK"
printf '%s' "$body" | grep -Eq '"mode"[[:space:]]*:[[:space:]]*"postgres"' || fail "Local readiness not backed by PostgreSQL"
ok "Local readiness with PostgreSQL"
public="$(curl --fail --silent --show-error --max-time 20 "$PUBLIC_URL/api/ready")" || fail "Public HTTPS readiness unavailable"
printf '%s' "$public" | grep -Eq '"mode"[[:space:]]*:[[:space:]]*"postgres"' || fail "Public readiness not backed by PostgreSQL"
ok "Public HTTPS readiness with PostgreSQL"
status="$(curl --fail --silent --show-error --max-time 20 "$PUBLIC_URL/api/auth/status")" || fail "Auth status endpoint unavailable"
printf '%s' "$status" | grep -Eq '"configured"[[:space:]]*:[[:space:]]*true' || fail "Auth status not configured"
ok "Auth status endpoint responds"
protected="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 20 "$PUBLIC_URL/api/grc/organizations/00000000-0000-0000-0000-000000000000/scopes/00000000-0000-0000-0000-000000000000/enterprise-acceptance")" || fail "Protected API unreachable"
[ "$protected" = 401 ] || fail "Unauthenticated enterprise acceptance returned HTTP $protected (expected 401)"
ok "Unauthenticated enterprise acceptance denied"
report="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 20 "$PUBLIC_URL/api/grc/organizations/00000000-0000-0000-0000-000000000000/scopes/00000000-0000-0000-0000-000000000000/enterprise-report.json")" || fail "Report API unreachable"
[ "$report" = 401 ] || fail "Unauthenticated report returned HTTP $report (expected 401)"
ok "Unauthenticated enterprise report denied"
if [ "${AEGIS_RUN_LOAD_SMOKE:-0}" = "1" ]; then
  bash scripts/verify-load-smoke.sh
  ok "Bounded readiness load smoke"
fi
printf '\nPASS: non-destructive production smoke checks completed.\n'
printf 'NOTE: Authenticated TOTP, tenant isolation, evidence workflows and report exports require separate controlled test accounts.\n'
printf 'NOTE: Independent penetration testing requires evidence from an assessor independent of implementation.\n'
