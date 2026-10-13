import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';
const load=fs.readFileSync('scripts/verify-load-smoke.sh','utf8');
const restore=fs.readFileSync('scripts/verify-backup-restore.sh','utf8');
const deploy=fs.readFileSync('scripts/deploy-gce.sh','utf8');
test('load smoke is bounded non-destructive and readiness-only',()=>{assert.match(load,/api\/ready/);assert.match(load,/CONCURRENCY/);assert.match(load,/MAX_SECONDS/);assert.doesNotMatch(load,/POST|PUT|PATCH|DELETE/);});
test('restore drill uses isolated disposable PostgreSQL and never production volume',()=>{assert.match(restore,/docker run -d --name/);assert.match(restore,/pg_restore/);assert.match(restore,/trap cleanup EXIT/);assert.match(restore,/to_regclass/);assert.match(restore,/orphan evidence rows/);for(const table of ['app_users','grc_organizations','assessments','evidence','findings','audit_events','documents'])assert.ok(restore.includes(table));assert.doesNotMatch(restore,/aegisgrc-security_aegis-db|docker volume|DROP\\s+DATABASE|DROP\\s+SCHEMA/i);});
test('deployment tooling avoids destructive database volume operations',()=>{assert.doesNotMatch(deploy,/down -v|volume rm|volume prune|system prune|DROP\\s+DATABASE|DROP\\s+SCHEMA/i);});
test('production acceptance is read-only and does not assume a named database volume',()=>{const acceptance=fs.readFileSync('scripts/verify-production-acceptance.sh','utf8');assert.ok(acceptance.includes('SELECT count(*) FROM information_schema.tables'));assert.doesNotMatch(acceptance,/docker volume|pg_dump|pg_restore|DROP\\s+DATABASE|DROP\\s+SCHEMA|TRUNCATE/i);});


test('GCE deploy is application-only and does not restart or recreate PostgreSQL',()=>{
 const deploy=fs.readFileSync('scripts/deploy-gce.sh','utf8');
 assert.match(deploy,/ps --status running postgres/);
 assert.match(deploy,/pg_isready/);
 assert.match(deploy,/SELECT 1/);
 assert.match(deploy,/up -d --no-deps aegis/);
 assert.doesNotMatch(deploy,/up -d postgres/);
 assert.doesNotMatch(deploy,/docker volume (rm|create)|down -v|--remove-orphans/);
});

test('predeploy backup is optional rather than a deployment requirement',()=>{
 const deploy=fs.readFileSync('scripts/deploy-gce.sh','utf8');
 assert.match(deploy,/AEGIS_PREDEPLOY_BACKUP:-0/);
 assert.doesNotMatch(deploy,/PRODUCTION_DB_VOLUME/);
});


test('GCE deploy pins the already checked-out release and never pulls a moving main branch',()=>{
 const deploy=fs.readFileSync('scripts/deploy-gce.sh','utf8');
 assert.match(deploy,/AEGIS_RELEASE_SHA/);
 assert.match(deploy,/git rev-parse HEAD/);
 assert.doesNotMatch(deploy,/git pull/);
 assert.match(deploy,/Release mismatch/);
});


test('dependency installs are lockfile-backed across CI and production image',()=>{
 assert.ok(fs.existsSync('package-lock.json'));
 const dockerfile=fs.readFileSync('Dockerfile','utf8');
 const workflows=[
  fs.readFileSync('.github/workflows/verify.yml','utf8'),
  fs.readFileSync('.github/workflows/ci.yml','utf8'),
  fs.readFileSync('.github/workflows/build.yml','utf8')
 ];
 assert.match(dockerfile,/RUN npm ci\b/);
 assert.doesNotMatch(dockerfile,/RUN npm install\b/);
 for(const workflow of workflows){
  assert.match(workflow,/npm ci\b/);
  assert.doesNotMatch(workflow,/npm install\b/);
 }
});
