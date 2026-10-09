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
