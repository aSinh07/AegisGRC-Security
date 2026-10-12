import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';
const load=fs.readFileSync('scripts/verify-load-smoke.sh','utf8');
const restore=fs.readFileSync('scripts/verify-backup-restore.sh','utf8');
const deploy=fs.readFileSync('scripts/deploy-gce.sh','utf8');
test('load smoke is bounded non-destructive and readiness-only',()=>{assert.match(load,/api\/ready/);assert.match(load,/CONCURRENCY/);assert.match(load,/MAX_SECONDS/);assert.doesNotMatch(load,/POST|PUT|PATCH|DELETE/);});
test('restore drill uses isolated disposable PostgreSQL and never production volume',()=>{assert.match(restore,/docker run -d --name/);assert.match(restore,/pg_restore/);assert.match(restore,/trap cleanup EXIT/);assert.doesNotMatch(restore,/aegisgrc-security_aegis-db/);});
test('deployment remains backup-first and avoids destructive volume operations',()=>{assert.match(deploy,/pg_dump/);assert.doesNotMatch(deploy,/down -v|volume rm|volume prune|system prune/);});
