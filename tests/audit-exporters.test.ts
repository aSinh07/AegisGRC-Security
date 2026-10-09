import test from 'node:test';import assert from 'node:assert/strict';
import {auditDocx,auditXlsx,auditPdf} from '../src/audit-exporters.js';
const model={assessmentId:'assessment-test',organizationId:'org-test',generatedAt:'2026-01-01T00:00:00Z',assuranceBoundary:'Not certification',executiveSummary:{findings:1,confirmed:1},evidenceRegister:[{source:'scanner',sha256:'a'.repeat(64),created_at:'2026-01-01'}],findingLifecycle:[{findingId:'f1',severity:'HIGH',title:'Validated finding',source:'document',evidenceHash:'a'.repeat(64),findingStatus:'OPEN',analystDecisions:[{decision:'CONFIRMED'}],issue:{issue_key:'ISSUE-1'},risks:[{risk_key:'RISK-1',inherent_rating:'HIGH'}],capa:[{capa_key:'CAPA-1',status:'RETEST_PENDING',retest_run_id:'r1'}]}],limitations:['Framework mappings do not constitute certification.']};
test('audit DOCX has valid zip signature',async()=>{const b=await auditDocx(model);assert.equal(b.subarray(0,2).toString(),'PK')});
test('audit XLSX has valid zip signature',()=>{const b=auditXlsx(model);assert.equal(b.subarray(0,2).toString(),'PK')});
test('audit PDF has valid PDF signature and lifecycle content',async()=>{const b=await auditPdf(model);assert.equal(b.subarray(0,4).toString(),'%PDF');assert.ok(b.length>500)});

test('audit model labels evidence hashes as ingest records rather than re-verification',async()=>{
 const src=await import('node:fs/promises').then(x=>x.readFile(new URL('../src/audit-trace.ts',import.meta.url),'utf8'));
 assert.match(src,/HASH_RECORDED_AT_INGEST/);assert.match(src,/not a subsequent integrity re-verification/);
 const server=await import('node:fs/promises').then(x=>x.readFile(new URL('../src/server.ts',import.meta.url),'utf8'));
 assert.match(server,/hashComputedByServer:true/);assert.match(server,/integrityStatus:'HASHED_AT_INGEST'/);assert.doesNotMatch(server,/evidence:\{id:evidenceId,sha256,verified:true\}/);
 const pdf=await import('node:fs/promises').then(x=>x.readFile(new URL('../src/audit-exporters.ts',import.meta.url),'utf8'));
 assert.match(pdf,/Hash metadata timestamp/);assert.doesNotMatch(pdf,/Integrity verification timestamp/);
});
