import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

test('assessment tenancy migration is additive and non-destructive',async()=>{
 const sql=await readFile(new URL('../db/schema.sql',import.meta.url),'utf8');
 assert.match(sql,/ALTER TABLE assessments ADD COLUMN IF NOT EXISTS organization_id/);
 assert.match(sql,/ALTER TABLE assessments ADD COLUMN IF NOT EXISTS created_by/);
 assert.doesNotMatch(sql,/DROP\s+(TABLE|COLUMN)/i);
});
test('evidence integrity metadata is additive without rewriting legacy rows',async()=>{
 const sql=await readFile(new URL('../db/schema.sql',import.meta.url),'utf8');
 assert.match(sql,/ALTER TABLE evidence ADD COLUMN IF NOT EXISTS byte_length bigint/);
 assert.match(sql,/ALTER TABLE evidence ADD COLUMN IF NOT EXISTS integrity_verified_at timestamptz/);
 assert.doesNotMatch(sql,/UPDATE evidence/i);
});

test('evidence migration is restart-safe and does not recreate or drop named constraint',async()=>{
 const sql=await readFile(new URL('../db/schema.sql',import.meta.url),'utf8');
 assert.doesNotMatch(sql,/ALTER TABLE evidence ADD CONSTRAINT evidence_sha256_format_chk/i);
 assert.doesNotMatch(sql,/DROP CONSTRAINT evidence_sha256_format_chk/i);
});

test('unassigned assessment cannot be claimed without creator ownership',async()=>{
 const src=await readFile(new URL('../src/grc-organizations.ts',import.meta.url),'utf8');
 assert.match(src,/row\.created_by!==userId/);
 assert.match(src,/administrator-led migration/);
});

test('legacy assessment reads use tenant-scoped database accessors',async()=>{
 const store=await readFile(new URL('../src/store.ts',import.meta.url),'utf8');
 assert.match(store,/assessmentForUser/);assert.match(store,/assessmentsForUser/);
 assert.match(store,/WHERE a\.id=\$1 AND m\.user_id=\$2/);
 assert.match(store,/findingsForAssessment/);assert.match(store,/evidenceForAssessment/);assert.match(store,/auditsForAssessment/);
 const server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 assert.match(server,/db\.assessmentsForUser\(u\.userId\)/);
 assert.match(server,/db\.assessmentForUser\(u\.userId,req\.params\.id\)/);
 assert.match(server,/db\.auditsForAssessment\(req\.params\.id\)/);
 assert.match(server,/db\.evidenceForAssessment\(req\.params\.id\)/);
});

test('legacy document AI review and export routes enforce user tenant access',async()=>{
 const server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 for(const route of [
  "/api/assessments/:id/documents/:docId/security-assess",
  "/api/assessments/:id/documents/:docId/analyze",
  "/api/assessments/:id/documents/:docId",
  "/api/assessments/:id/copilot",
  "/api/assessments/:id/ai-remediation",
  "/api/assessments/:id/report.pdf",
  "/api/assessments/:id/report/download",
  "/api/assessments/:id/grc-reviews",
  "/api/assessments/:id/framework-assessment/:framework",
  "/api/assessments/:id/framework-report/:framework/:format",
  "/api/assessments/:id/export/:kind/:format"
 ])assert.equal(server.includes(route),true,route);
 assert.match(server,/assessmentForUser\(u\.userId,req\.params\.id\)/);
 assert.match(server,/requireAssessmentAccess\(u\.userId,req\.params\.id\)/);
});

test('server has no legacy global assessment finding evidence or audit reads',async()=>{
 const server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 for(const call of ['db.assessments()','db.findings()','db.evidence()','db.audits()'])assert.equal(server.includes(call),false,call);
 assert.match(server,/db\.assessmentForUser\(u\.userId,assessmentId\)/);
 assert.match(server,/db\.findingsForAssessment\(assessmentId\)/);
 assert.match(server,/db\.evidenceForAssessment\(assessmentId\)/);
});


test('finding import requires mutation role in the assessment organization',async()=>{
 const {readFile}=await import('node:fs/promises');
 const server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 const start=server.indexOf("app.post('/api/grc/assessments/:assessmentId/finding-import'");
 const end=server.indexOf("app.post('/api/grc/assessments/:assessmentId/findings/:findingId/review'",start);
 const route=server.slice(start,end);
 assert.match(route,/const access=await requireAssessmentAccess\(u\.userId,req\.params\.assessmentId\)/);
 assert.match(route,/requireOrgPermission\(u\.userId,access\.organization_id,'findingReview'\)/);
});


test('finding import evidence findings and audit persist atomically',async()=>{
 const {readFile}=await import('node:fs/promises');
 const store=await readFile(new URL('../src/store.ts',import.meta.url),'utf8');
 const server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 const start=store.indexOf('saveFindingImport:async');
 const end=store.indexOf('saveEvidence:async',start);
 const tx=store.slice(start,end);
 assert.match(tx,/client\.query\('BEGIN'\)/);
 assert.match(tx,/INSERT INTO evidence/);
 assert.match(tx,/INSERT INTO findings/);
 assert.match(tx,/INSERT INTO audit_events/);
 assert.match(tx,/client\.query\('COMMIT'\)/);
 assert.match(tx,/client\.query\('ROLLBACK'\)/);
 const route=server.slice(server.indexOf("app.post('/api/grc/assessments/:assessmentId/finding-import'"),server.indexOf("app.post('/api/grc/assessments/:assessmentId/findings/:findingId/review'"));
 assert.match(route,/db\.saveFindingImport\(ev,parsed\.findings,audit\)/);
 assert.doesNotMatch(route,/db\.saveEvidence\(ev\)/);
});


test('protected report exports require current user step-up before tenant data is rendered',async()=>{
 const server=await readFile(new URL('../src/server.ts',import.meta.url),'utf8');
 for(const marker of ["app.get('/api/assessments/:id/framework-report/:framework/:format'","app.get('/api/assessments/:id/export/:kind/:format'"]){
  const start=server.indexOf(marker);assert.notEqual(start,-1,marker);
  const route=server.slice(start,start+4200);
  const step=route.indexOf('reportAuthorized(req)');
  const tenant=route.indexOf('assessmentForUser(u.userId,req.params.id)');
  assert.ok(step>=0,'step-up missing');assert.ok(tenant>step,'tenant lookup must follow step-up verification');
  for(const code of ['USER_SESSION_MISSING','PASSWORD_INVALID','TOTP_INVALID','STEP_UP_RATE_LIMITED'])assert.ok(route.includes(code),code+' structured export failure missing');
 }
});

test('browser report download preserves same-origin session and gives actionable MFA failures',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 const start=html.indexOf('async function confirmExport()');assert.notEqual(start,-1);
 const fn=html.slice(start,start+4200);
 assert.match(fn,/credentials:'same-origin'/);
 assert.match(fn,/x-report-password/);assert.match(fn,/x-report-totp/);
 assert.match(fn,/login session has expired/i);assert.match(fn,/account password is incorrect/i);assert.match(fn,/Authenticator code invalid or expired/i);
 assert.match(fn,/if\(!b\.size\)/);
});
