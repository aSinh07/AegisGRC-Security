import test from 'node:test';import assert from 'node:assert/strict';import {readFile} from 'node:fs/promises';
test('production deployment script contains real shell line breaks and release safeguards',async()=>{const s=await readFile(new URL('../scripts/deploy-gce.sh',import.meta.url),'utf8');assert.doesNotMatch(s,/\\n/);assert.match(s,/set -euo pipefail/);assert.match(s,/pg_dump/);assert.match(s,/PRODUCTION_DB_VOLUME="aegisgrc-security_aegis-db"/);assert.match(s,/docker volume inspect/);assert.match(s,/refusing to initialize a replacement database/);assert.match(s,/exec -T postgres sh -c/);assert.doesNotMatch(s,/exec -T postgres pg_dump -U \"\\$POSTGRES_USER\"/);assert.match(s,/"mode":"postgres"/);assert.doesNotMatch(s,/down\s+-v|down\s+--volumes/);});

test('production compose uses container env and canonical external database volume',async()=>{const s=await readFile(new URL('../docker-compose.production.yml',import.meta.url),'utf8');assert.match(s,/env_file: \.env\.production/);assert.match(s,/pg_isready/);assert.doesNotMatch(s,/\$\{POSTGRES_USER\}/);assert.doesNotMatch(s,/\$\{POSTGRES_DB\}/);assert.doesNotMatch(s,/POSTGRES_USER:\s*\$\{POSTGRES_USER\}/);assert.doesNotMatch(s,/POSTGRES_PASSWORD:\s*\$\{POSTGRES_PASSWORD\}/);assert.match(s,/name: aegisgrc-security_aegis-db/);assert.match(s,/external: true/);});

test('production deploy rejects common placeholders and validates backups before release',async()=>{const s=await readFile(new URL('../scripts/deploy-gce.sh',import.meta.url),'utf8');assert.match(s,/CHANGE_THIS/);assert.match(s,/CHANGEME/);assert.match(s,/test -s "\$backup_path"/);assert.match(s,/pg_restore -l/);assert.match(s,/backup validation failed/);});


test('production deploy requires encrypted MFA storage and secure cookie mode',async()=>{
 const s=await readFile(new URL('../scripts/deploy-gce.sh',import.meta.url),'utf8');
 assert.match(s,/TOTP_ENCRYPTION_KEY/);
 assert.match(s,/NODE_ENV must be production/);
 assert.match(s,/COOKIE_SECURE must be true/);
 assert.match(s,/decode to exactly 32 bytes/);
 const env=await readFile(new URL('../.env.production.example',import.meta.url),'utf8');
 assert.match(env,/TOTP_ENCRYPTION_KEY=REPLACE_WITH_BASE64_ENCODED_32_BYTE_KEY/);
});
