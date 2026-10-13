import test from 'node:test';import assert from 'node:assert/strict';import {readFile} from 'node:fs/promises';
test('production deployment script contains real shell line breaks and application-only safeguards',async()=>{const s=await readFile(new URL('../scripts/deploy-gce.sh',import.meta.url),'utf8');assert.doesNotMatch(s,/\\n/);assert.match(s,/set -euo pipefail/);assert.match(s,/ps --status running postgres/);assert.match(s,/pg_isready/);assert.match(s,/SELECT 1/);assert.match(s,/up -d --no-deps aegis/);assert.match(s,/"mode":"postgres"/);assert.doesNotMatch(s,/up -d postgres|docker volume inspect|down\s+-v|down\s+--volumes|--remove-orphans/);});

test('production compose uses container env and canonical external database volume',async()=>{const s=await readFile(new URL('../docker-compose.production.yml',import.meta.url),'utf8');assert.match(s,/env_file: \.env\.production/);assert.match(s,/pg_isready/);assert.doesNotMatch(s,/\$\{POSTGRES_USER\}/);assert.doesNotMatch(s,/\$\{POSTGRES_DB\}/);assert.doesNotMatch(s,/POSTGRES_USER:\s*\$\{POSTGRES_USER\}/);assert.doesNotMatch(s,/POSTGRES_PASSWORD:\s*\$\{POSTGRES_PASSWORD\}/);assert.match(s,/name: aegisgrc-security_aegis-db/);assert.match(s,/external: true/);});

test('production deploy rejects placeholders and keeps backup explicitly optional',async()=>{const s=await readFile(new URL('../scripts/deploy-gce.sh',import.meta.url),'utf8');assert.match(s,/CHANGE_THIS/);assert.match(s,/CHANGEME/);assert.match(s,/AEGIS_PREDEPLOY_BACKUP:-0/);assert.match(s,/test -s "\$backup_path"/);assert.doesNotMatch(s,/PRODUCTION_DB_VOLUME/);});


test('production deploy requires encrypted MFA storage and secure cookie mode',async()=>{
 const s=await readFile(new URL('../scripts/deploy-gce.sh',import.meta.url),'utf8');
 assert.match(s,/TOTP_ENCRYPTION_KEY/);
 assert.match(s,/NODE_ENV must be production/);
 assert.match(s,/COOKIE_SECURE must be true/);
 assert.match(s,/decoding to exactly 32 bytes/);
 const env=await readFile(new URL('../.env.production.example',import.meta.url),'utf8');
 assert.match(env,/TOTP_ENCRYPTION_KEY=REPLACE_WITH_BASE64_ENCODED_32_BYTE_KEY/);
});


test('backup restore drill uses an isolated temporary PostgreSQL container',async()=>{
 const s=await readFile(new URL('../scripts/verify-backup-restore.sh',import.meta.url),'utf8');
 assert.match(s,/postgres:16-alpine/);
 assert.match(s,/pg_restore --no-owner --no-privileges/);
 assert.match(s,/information_schema\.tables/);
 assert.match(s,/trap cleanup EXIT/);
 assert.doesNotMatch(s,/aegisgrc-security_aegis-db/);
});
